---
name: bloodhound
description: Analyze BloodHound CE JSON files or plan AD attack paths. Use when BloodHound output is available, discussing ACL edges, Kerberoastable users, GMSA, LAPS, ADCS paths, delegation, domain trusts, or any BloodHound-derived attack path.
user-invocable: false
allowed-tools: Read
---

# BloodHound Analysis

## Core rule
BloodHound shows POSSIBLE paths — not guaranteed. Always cross-reference with "User Notes" in context.
If a path is marked as rabbit hole → skip it entirely, never revisit.

## Collect
```bash
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip      # includes ADCS nodes
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip -k   # Kerberos-only env
# On Windows: SharpHound.exe -c all --zipfilename bh.zip
```

## First steps after loading
1. Mark all owned principals (users, computers, hashes you have)
2. "Shortest Paths from Owned Principals"
3. Check "Outbound Object Control" per owned principal
4. "Find all Kerberoastable Accounts"
5. "Find AS-REP Roastable Users"
6. "Find Computers with Unconstrained Delegation"
7. "Find Computers with Constrained Delegation"
8. Check ADCS nodes (if collected with rusthound-ce)
9. "Find Principals with DCSync Rights"
10. "Find all Domain Admins"

## ACL edge → best abuse
| Edge | Primary abuse |
|------|--------------|
| GenericAll (user) | Shadow cred → targeted kerberoast → password change |
| GenericAll (group) | AddMember → inherit group rights |
| GenericAll (computer) | RBCD or shadow cred |
| GenericAll (GPO) | GPO abuse → immediate code exec on linked OUs |
| GenericWrite (user) | Shadow cred or targeted kerberoast (add SPN) |
| GenericWrite (computer) | RBCD via msDS-AllowedToActOnBehalfOfOtherIdentity |
| AddKeyCredentialLink | Shadow credentials → PKINIT → NT hash (UnPAC-the-Hash) |
| WriteSPN | Targeted kerberoast |
| ForceChangePassword | Reset password — check if account is disabled first |
| WriteOwner | Take ownership → grant GenericAll → exploit above |
| AddSelf / AddMember | Join group → inherit all group permissions |
| AllExtendedRights | Includes ForceChangePassword + ReadLAPSPassword; treat as GenericAll |
| ReadGMSAPassword | Retrieve GMSA NT hash → PTH |
| WriteDACL | Grant DCSync or GenericAll on target |
| WriteAccountRestrictions | Write msDS-AllowedToActOnBehalfOfOtherIdentity → RBCD directly |
| AllowedToDelegate | S4U2Self+S4U2Proxy → impersonate any user to target service |
| AllowedToAct | RBCD — attacker machine account can impersonate any user |
| DCSync | Dump all hashes (secretsdump -just-dc) |
| ReadLAPSPassword | Read ms-Mcs-AdmPwd → local admin cred for target computer |
| SyncLAPSPassword | Sync LAPS passwords domain-wide without full DCSync |
| Contains (OU) | GPO linked to OU → affects all objects inside |
| GPLink | GPO controls objects in linked OU |
| ADCSESC1–ADCSESC13 | Certificate template exploitation paths (see adcs skill) |

## Kerberos delegation edges
| Edge | What it means |
|------|--------------|
| AllowedToDelegate | Constrained delegation — can impersonate users to specific SPNs |
| AllowedToAct | RBCD — machine configured to allow delegation from attacker |
| HasSIDHistory | SID history abuse — may have rights in another domain |
| TrustedBy | Trust relationship between domains |

## Common attack chains (real-world patterns)
```
GenericAll on user → shadow cred → certipy auth → NT hash → PTH
GenericWrite on user → WriteSPN → targeted kerberoast → crack → new creds
AddKeyCredentialLink on user → pywhisker/certipy shadow → PKINIT → UnPAC-the-Hash → NT hash
WriteDACL on domain → grant DCSync → secretsdump → all hashes
ReadGMSAPassword → GMSA$ NT hash → PTH → check GMSA$ outbound rights
WriteAccountRestrictions on computer → RBCD → getST → psexec
AllExtendedRights → either ReadLAPS or ForceChangePassword depending on object type
GenericAll on GPO → pygpoabuse → localadmin on all computers in linked OU
DCSync → dump krbtgt → Golden Ticket → persistence
```

## Domain trust analysis
```
Check: Analysis → Find all Domain Trusts
Bidirectional trust = both domains may be exploitable
One-way trust: if you own the trusting domain, you can access the trusted one
SID filtering: if disabled, SID history abuse is possible cross-forest
External trusts: limited; forest trusts: broader access possible
```

## Gotchas
- **gMSA Kerberoast** → always fails; 256-bit random password, never cracks
- **Hash not cracking with rockyou** → not the intended path, pivot immediately
- **authenticationenabled=false** on cert template → skip
- **Path requires unreachable machine** → look for another edge
- **adminCount=1 objects** → ACL inheritance is blocked; changes to parent OU won't affect them
- **Protected Users group members** → no NTLM, no RC4, no delegation; AES Kerberos only
- **Disabled accounts** → can still have ACL edges; enable them if you have ForceChangePassword
- **Machine accounts (COMPUTER$)** → can be owned like users if you have creds/hashes for them
- **ADCS edges in BH CE** → use rusthound-ce collector, regular bloodhound-python misses these

## Key References
- https://bloodhound.specterops.io/resources/edges
- https://www.ired.team
- https://www.thehacker.recipes
- https://github.com/ly4k/Certipy/wiki
- https://0xdf.gitlab.io
