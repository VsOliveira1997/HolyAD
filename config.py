SYSTEM_PROMPT = """You are HolyAD — an HTB AD pentesting instructor. Guide step by step with a CTF mindset.

## Rules
- HTB machines have ONE intended path. Think: what did the creator want to teach?
- If blocked: DROP the path immediately, pivot to another vector
- Never suggest a path the user already confirmed doesn't work
- A hash that doesn't crack with rockyou is a RABBIT HOLE — move on
- Commands must use real values from context — never placeholders
- When you find credentials: test on ALL services first (SMB, LDAP, WinRM, MSSQL, RPC) before going deep
- Avoid repeating commands already in "Commands run" — check before suggesting

## Pre-Windows 2000 hint
If you see computer accounts in interesting groups → try password = lowercase hostname (no $)
netexec ldap <dc> -u 'HOST$' -p 'host' -k

## References
- https://www.ired.team (AD attack mechanics)
- https://0xdf.gitlab.io

## MANDATORY — end EVERY response with this exact block:
## Key findings from this analysis
- <one short bullet per important discovery: open port, user, hash, misconfiguration, confirmed rabbit hole>
- <if nothing new was found, write: nothing new discovered>

This block is parsed automatically. If it is missing or malformed, findings will not be saved."""


def build_claude_md(ctx: dict, skills_dir: str) -> str:
    """Build a focused CLAUDE.md based on session context."""
    import os

    lines = [SYSTEM_PROMPT, "\n\n"]

    # ── session context ────────────────────────────────────────────────────────
    lines.append("# Session\n")
    lines.append(f"- IP: {ctx['target']}\n")
    lines.append(f"- Auth: {ctx['type']}\n")
    if ctx.get('user'):
        lines.append(f"- User: {ctx['user']}\n")
    if ctx.get('pass'):
        lines.append(f"- Pass: {ctx['pass']}\n")
    if ctx.get('domain'):
        lines.append(f"- Domain: {ctx['domain']}\n")

    # ── findings ───────────────────────────────────────────────────────────────
    if ctx.get('findings'):
        lines.append("\n# Known Findings\n")
        for f in ctx['findings']:
            lines.append(f"- {f}\n")

    # ── commands already run ───────────────────────────────────────────────────
    if ctx.get('sent_commands'):
        lines.append("\n# Commands run (DO NOT repeat these)\n")
        for c in ctx['sent_commands']:
            lines.append(f"- {c}\n")

    # ── recon checklist ────────────────────────────────────────────────────────
    lines.append("""
# Recon Checklist
SMB → null/guest session, shares, RID cycling (--rid-brute), signing check
LDAP → anon bind, user descriptions (passwords often here), ldapdomaindump
RPC → rpcclient null: enumdomusers, enumdomgroups, querydispinfo
Kerberos → AS-REP roast (no creds needed), kerbrute userenum
Web (80/443/8080) → feroxbuster, vhosts (ffuf), source code — often intended entry
WinRM (5985/5986) → test creds immediately
MSSQL (1433) → xp_dirtree for Net-NTLMv2, xp_cmdshell if sa; linked servers for lateral movement
ADCS → certipy find -vulnerable -stdout; rusthound-ce for BloodHound ADCS data
Pre-Win2000 → check if computer accounts in special groups → password = lowercase hostname
BloodHound → collect with rusthound-ce (includes ADCS), mark owned, check outbound control
SYSVOL/GPP → netexec smb -M gpp_password; grep NETLOGON scripts for hardcoded creds
Shares → spider_plus all shares; grep for web.config, *.ps1, *.ini, connection strings
IPv6 → mitm6 + ntlmrelayx --delegate-access; works on almost every domain
PSO → check Fine-Grained Password Policies before spraying (service accounts may have lockout=0)
Local admin reuse → netexec smb subnet/24 -u administrator -H {HASH} --local-auth
Token privs → after any service shell: whoami /priv → SeImpersonate → GodPotato/PrintSpoofer
Services/tasks → check for domain accounts running services/scheduled tasks → token impersonation
""")

    # ── attack reference (compact) ─────────────────────────────────────────────
    if os.path.isdir(skills_dir):
        lines.append("# Attack Reference\n")
        for skill in sorted(os.listdir(skills_dir)):
            skill_path = os.path.join(skills_dir, skill, "SKILL.md")
            if not os.path.exists(skill_path):
                continue
            with open(skill_path) as f:
                content = f.read()
            desc = ""
            headers = []
            for line in content.split("\n"):
                if line.startswith("description:"):
                    desc = line.replace("description:", "").strip()
                elif line.startswith("## ") and not line.startswith("## Step"):
                    headers.append(line.strip("# ").strip())
            if desc:
                lines.append(f"\n**{skill}** — {desc}\n")
                if headers:
                    lines.append("Topics: " + " | ".join(headers[:6]) + "\n")

    return "".join(lines)