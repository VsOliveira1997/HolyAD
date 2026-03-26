---
name: bloodhound
description: Analyze BloodHound CE JSON files or plan AD attack paths using BloodHound data. Use when BloodHound output is available, when discussing ACL edges (GenericAll, GenericWrite, WriteSPN, ForceChangePassword, AddSelf, DCSync), Kerberoastable users, GMSA read rights, or ADCS certificate templates.
user-invocable: false
allowed-tools: Read
---

# BloodHound Analysis

## Core rule
BloodHound shows POSSIBLE paths. Always cross-reference with "User Notes" in context.
If a path is marked as rabbit hole → skip it entirely, do not revisit.

## Collect
```bash
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip   # includes ADCS
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip -k  # Kerberos-only
```

## First steps after loading
1. Mark owned users
2. "Shortest Paths from Owned Principals"
3. Check Outbound Object Control per owned user
4. "Find all Kerberoastable Accounts"
5. ADCS nodes if collected with rusthound-ce

## ACL edge → best abuse
| Edge | Primary abuse |
|------|--------------|
| GenericAll | Shadow cred > targeted kerberoast > password change |
| GenericWrite | Shadow cred or targeted kerberoast (add SPN) |
| WriteSPN | Targeted kerberoast |
| ForceChangePassword | Reset — check if account disabled first |
| WriteOwner | Take ownership → GenericAll → then above |
| AddSelf/AddMember | Join group → inherit permissions |
| ReadGMSAPassword | Get NTLM → PTH |
| WriteDACL | Grant DCSync rights |
| AllowedToDelegate | S4U2Self+Proxy → impersonate admin |
| AllowedToAct | RBCD |
| DCSync | Dump all hashes |

## Gotchas
- **gMSA Kerberoast** → always fails, 256-bit random password, never cracks
- **Hash not cracking after rockyou** → not the intended path, pivot
- **authenticationenabled=false** on ADCS template → skip
- **Path requires unreachable machine** → find another edge
- See references/chains.md for common HTB attack chains

## Key References
- https://www.ired.team — AD attack mechanics
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://www.thehacker.recipes
- https://github.com/ly4k/Certipy/wiki — ADCS ESC1-16
- https://0xdf.gitlab.io — HTB AD writeups