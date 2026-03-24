---
name: bloodhound
description: BloodHound CE analysis for HTB AD machines. Map is not the path — always cross-reference with user notes before following any edge.
---

# BloodHound Analysis

## Critical mindset
BloodHound shows POSSIBLE edges. In HTB:
- Always check "User Notes & Rabbit Holes" first — blocked paths stay blocked
- If a hash won't crack after rockyou → STOP, it's not the path
- Prioritize shortest path to DA
- gMSA accounts are Kerberoastable but use 256-bit random passwords → NOT crackable

## Collection
```bash
# rusthound-ce — mandatory for ADCS data
rusthound-ce -d {DOMAIN} -u '{USER}' -p '{PASS}' --dc-ip {IP} --zip

# Python alternative (no ADCS)
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip

# Kerberos-only environment
bloodhound-ce-python -c all -d {DOMAIN} -u '{USER}' -p '{PASS}' -ns {IP} --zip -k
```

## Immediate steps after loading data
1. Mark all owned users
2. "Shortest Paths from Owned Principals" — this is your map
3. Check Outbound Object Control per owned user
4. "Find all Kerberoastable Accounts"
5. "Find AS-REP Roastable Users"
6. "Shortest Paths to High Value Targets"
7. Look at ADCS nodes if collected with rusthound-ce

## ACL edge priority and abuse
| Edge | Abuse | Notes |
|------|-------|-------|
| GenericAll | Password change, targeted kerberoast, shadow cred | Full control |
| GenericWrite | Targeted kerberoast, shadow cred, logon script | Write attrs |
| WriteSPN | Targeted kerberoast | Add fake SPN |
| ForceChangePassword | Reset password without knowing current | Check if account disabled |
| WriteOwner | Take ownership → grant GenericAll | Two steps |
| AddSelf | Add yourself to group | Check group privileges |
| AddMember | Add anyone to group | Check group privileges |
| ReadGMSAPassword | Get GMSA NTLM hash → PTH | |
| WriteDACL | Grant DCSync rights | Forest/Exchange pattern |
| AllowedToDelegate | Constrained delegation | S4U2Self+Proxy |
| AllowedToAct | RBCD | GenericWrite over computer |
| DCSync | Dump all hashes | GetChangesAll + GetChanges |
| GenericAll on template | ESC4 | Modify template → ESC1 |

## Common HTB chains from 0xdf writeups
```
# Administrator
GenericAll → password change → BloodHound next hop
GenericWrite → targeted kerberoast → crack → new user
New user → DCSync → administrator

# TombWatcher
WriteSPN → kerberoast → crack → new user
→ GMSA read → PTH with GMSA → WinRM on DC
→ AD Recycle Bin → recover ADCS admin → ESC15

# Forest
RPC null → user list → AS-REP roast → svc-alfresco
→ Account Operators → Exchange Windows Permissions
→ WriteDACL on domain → DCSync

# Rebound
RID cycle → AS-REP + kerberoast → password spray
→ bad ACL → group membership → ForceChangePassword
→ WinRM → GMSA read → constrained delegation

# Fluffy
GenericWrite → shadow cred → NT hash → WinRM
→ ESC16 → administrator

# Cicada
Backup Operators → seBackupPrivilege → reg save / diskshadow
→ exfil hives/NTDS.dit → secretsdump
```

## ADCS in BloodHound (rusthound-ce only)
- Look for ESC vulnerabilities on certificate templates
- Check enrollment rights per user/group
- "Shortest Paths to Domain Admins via Certificates"

## Rabbit holes — patterns from HTB
- Hash not cracking → not the intended path, find another edge
- gMSA kerberoast → always fails, 256-bit random password
- ADCS template with `authenticationenabled=false` → skip
- Path requires compromising machine not reachable → pivot differently
- Same path suggested multiple times after blocked → check user notes