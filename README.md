# holyAD

A CLI assistant for learning Active Directory pentesting on HackTheBox machines, using Claude Code as the backend.

> **Warning:** This tool was built exclusively for use in authorized environments like HackTheBox. Never use it against systems without explicit permission.

---

## Requirements

- [Claude Code CLI](https://claude.ai/code) installed and authenticated (`claude --version`)
- Python 3.10+
- Claude Pro or Max plan (holyAD uses `claude -p` via SSO — no API key needed)

---

## Installation

```bash
# Clone or copy the project
git clone <repo> ~/tools/holyAD

# Make executable
chmod +x ~/tools/holyAD/holyad

# Symlink to PATH
sudo ln -s ~/tools/holyAD/holyad /usr/local/bin/holyad

# Verify
holyad
```

---

## Project Structure

```
holyAD/
├── holyad                  # main executable
├── session.py              # per-machine context management
├── filter.py               # filters irrelevant tool output
├── README.md
└── skills/
    ├── ad-recon/           # SMB, LDAP, RPC, Kerberos, Web enumeration
    ├── bloodhound/         # BloodHound CE analysis and attack paths
    ├── acl-abuse/          # GenericAll, WriteSPN, DCSync, Backup Operators
    ├── adcs/               # ESC1-16 exploitation with certipy
    └── lateral-movement/   # PTH, PTT, delegation, NTLMRelay, DPAPI
```

Each machine gets its own isolated folder under `~/.holyad/<ip>/`:

```
~/.holyad/10.10.10.10/
├── CLAUDE.md       # session context (credentials, findings, notes)
├── context.json    # structured state
├── bloodhound.md   # BloodHound analysis (persisted separately)
├── session.md      # compact findings log per step
├── report.md       # final report
└── last_output.txt # last captured command output
```

---

## Usage

### Start a session

```bash
# No credentials (black-box)
holyad --start 10.10.10.10

# With credentials (assume-breach)
holyad --start 10.10.10.10 pentest:MyP4ssw0rd!
```

Each `--start` creates a fully isolated session. Different machines never share context.

---

### Run tools and analyze output

```bash
# holyAD runs the command, shows output in real time, and sends it to Claude
holyad rustscan -a 10.10.10.10 --ulimit 5000 -- -sC -sV
holyad netexec smb 10.10.10.10 -u pentest -p 'MyP4ssw0rd!' --shares
holyad certipy find -u 'pentest@domain.htb' -p 'MyP4ssw0rd!' -dc-ip 10.10.10.10 -vulnerable -stdout
holyad evil-winrm -i 10.10.10.10 -u pentest -p 'MyP4ssw0rd!'
```

Each command is saved as "already executed" — Claude will never suggest the same command again.

---

### Send files for analysis

```bash
# Any saved output file
holyad output.txt
holyad nmap.xml ldap_dump.txt

# BloodHound files — auto-detected by filename
# Analysis is saved to bloodhound.md and persists between calls
holyad computers.json users.json groups.json domains.json
holyad 20260324_bloodhound.zip
```

BloodHound files are detected automatically (filenames like `computers.json`, `users.json`, `bloodhound.zip`) and receive dedicated treatment — focused analysis on attack paths, ACL edges, GMSA, and ADCS.

---

### Save notes and rabbit holes

```bash
# Use --add to save important observations
# These notes carry maximum weight — Claude treats them as ground truth
holyad --add "kerberoast hash won't crack with rockyou — confirmed rabbit hole"
holyad --add "port 5985 open — WinRM accessible with current credentials"
holyad --add "ADCS present — CA is domain.htb-CA-01"
holyad --add "SMB signing enabled — relay attacks won't work"
```

---

### Generate final report

```bash
holyad --report
# Saved to ~/.holyad/<ip>/report.md
```

---

## How Context Works

holyAD uses `claude -p` which is stateless by design. Context lives entirely in the session `CLAUDE.md`, rebuilt on every call with:

| Field | Description |
|-------|-------------|
| Credentials | IP, user, password, domain |
| `--add` notes | Your observations — max weight, never contradicted |
| BloodHound | Full analysis from `bloodhound.md` |
| Findings | Bullets auto-extracted from Claude's responses |
| Executed commands | All commands already run — never repeated |
| Session log | Compact findings per step |

**Skills** (`ad-recon`, `bloodhound`, `acl-abuse`, `adcs`, `lateral-movement`) are loaded automatically by Claude Code when relevant — zero token cost when not needed (progressive disclosure).

---

## Tips

**Be specific with `--add`**
```bash
# Bad
holyad --add "kerberoast didn't work"

# Good
holyad --add "a.white_adm is kerberoastable but hash won't crack — strong password, not the path"
```

**Send BloodHound early**
```bash
# Collect with rusthound-ce to include ADCS data
rusthound-ce -d domain.htb -u pentest -p 'MyP4ssw0rd!' --dc-ip 10.10.10.10 --zip
holyad *.json
```

**Block rabbit holes explicitly**
```bash
holyad --add "CONFIRMED RABBIT HOLE: ESC1 path fails — template not enrollable by pentest user"
```

**Large outputs**
If a tool generates output with binary blobs (e.g. ADFSDump, encrypted keys), save to `.txt` and replace the binary section with `[REDACTED]` before sending.

---

## Available Skills

| Skill | Triggered when |
|-------|---------------|
| `ad-recon` | Analyzing nmap/rustscan output, enumerating SMB/LDAP/RPC/Kerberos |
| `bloodhound` | BloodHound data available, discussing ACL edges or attack paths |
| `acl-abuse` | BloodHound shows an edge, planning escalation via AD permissions |
| `adcs` | ADCS present, certipy found vulnerable templates, ESC1-16 |
| `lateral-movement` | After gaining credentials or hashes, moving laterally |

---

## Technical References

- https://www.ired.team — AD attack mechanics and protocol internals
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://www.thehacker.recipes — structured attack paths by technique
- https://github.com/ly4k/Certipy/wiki — ADCS ESC1-16 documentation
- https://0xdf.gitlab.io — HTB AD writeups

---

## License

Educational use in authorized environments (HackTheBox, personal labs) only. Do not use against systems without explicit written authorization.