"""
orchestrator.py — autonomous pentest loop for holyAD

Three focused Claude calls per step:
  1. pick_skill    → which skill to use? (small: phase + findings tags only)
  2. pick_command  → what exact command?  (medium: SKILL.md + creds + findings)
  3. judge         → was this useful?     (small: cmd + trimmed output)

  + evaluate       → on track?            (small: state only, every N steps)

Raw command output is NEVER accumulated — only clean findings survive into state.
"""

import json
import os
import re
import shlex
import subprocess
import time

from filter import Filter

# ── constants ─────────────────────────────────────────────────────────────────

SKILLS_DIR     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
REGISTRY_FILE  = os.path.join(SKILLS_DIR, "registry.json")
CONTAINER_NAME = "holyad-box"
CONTAINER_IMAGE = "nwodtuhs/exegol:ad-3.1.6"
PHASES         = ["recon", "foothold", "lateral", "privesc", "domain_admin"]

# ── docker ────────────────────────────────────────────────────────────────────

def container_running() -> bool:
    r = subprocess.run(
        ["docker", "ps", "--filter", f"name=^{CONTAINER_NAME}$",
         "--filter", "status=running", "-q"],
        capture_output=True, text=True
    )
    return bool(r.stdout.strip())


def start_container():
    # pull image if not present — stream output so user can see progress
    r = subprocess.run(["docker", "image", "inspect", CONTAINER_IMAGE], capture_output=True)
    if r.returncode != 0:
        print(f"  [docker] pulling {CONTAINER_IMAGE}...")
        r = subprocess.run(["docker", "pull", CONTAINER_IMAGE])
        if r.returncode != 0:
            print("  [docker] pull failed")
            return False

    print("  [docker] starting container...", flush=True)
    r = subprocess.run([
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "--network", "host",
        "--privileged",
        CONTAINER_IMAGE,
        "tail", "-f", "/dev/null",
    ])
    if r.returncode != 0:
        return False
    for _ in range(10):
        if container_running():
            print("  [docker] ready")
            return True
        time.sleep(1)
    print("  [docker] timeout")
    return False


def kill_container():
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    print(f"  [docker] container '{CONTAINER_NAME}' removed")


# ── goal detection ────────────────────────────────────────────────────────────

_GOAL_PATTERNS = [
    r"\*pwn3d\*",
    r"nt authority\\system",
    r"Evil-WinRM shell v",
    r"secretsdump.*administrator.*:.*:::",
]
_GOAL_RE = [re.compile(p, re.IGNORECASE) for p in _GOAL_PATTERNS]


def goal_reached(output: str) -> bool:
    return any(r.search(output) for r in _GOAL_RE)


# ── prompts ───────────────────────────────────────────────────────────────────

PICK_SKILL_PROMPT = """\
You are a senior AD pentester. Choose the single best skill to use next.

Target: {ip}
Phase: {phase}
Objective: {objective}

Confirmed finding tags (what we know so far):
{finding_tags}

NOTE: If clock_skew is in the tags above, Kerberos will fail — prefer NTLM-based skills.

Dead ends already tried:
{dead_ends}

Available skills (name → description):
{skill_menu}

Rules:
- A skill is only available if its prerequisites are met by the finding tags above.
- Available skills list already respects prerequisites — only pick from it.
- Prefer skills that directly advance the objective for this phase.
- If no skill makes sense, reply: SKILL: none

Reply in this exact format:
SKILL: <skill_name>
REASON: <one line>
"""

PICK_COMMAND_PROMPT = """\
You are a senior AD pentester. Choose the single best command to run for this skill.

Target: {ip}
User: {user}  |  Pass: '{password}'  |  Domain: {domain}
Phase: {phase}

IMPORTANT: Passwords and hashes must always be wrapped in single quotes.
IMPORTANT: If Domain is empty, do not use domain prefix — use only the username.
IMPORTANT: Use nxc (NOT netexec) — the binary is called nxc in this environment.
IMPORTANT: If clock_skew is in the finding tags, Kerberos will fail — always use NTLM auth (no -k flag). Do NOT use faketime.
IMPORTANT: Impacket tools use .py suffix with NO prefix: GetUserSPNs.py, GetNPUsers.py,
           secretsdump.py, getTGT.py, getST.py, psexec.py, wmiexec.py, lookupsid.py,
           ticketer.py, addcomputer.py — NEVER use the impacket- prefix.
IMPORTANT: If open ports are unknown, run a port scan first:
           rustscan -a {ip} --ulimit 5000 -- -sC -sV

Confirmed findings:
{findings}

Commands already run — DO NOT repeat:
{commands_run}

Skill playbook for [{skill_name}]:
{skill_md}

HTB goal: get shell as any user → read user.txt → escalate → read root.txt from Administrator Desktop

Pick ONE specific command using real values. No placeholders.

Reply in this exact format:
CMD: <full command with real values>
REASON: <one line>
"""

JUDGE_PROMPT = """\
You are a senior AD pentester. Evaluate whether this command output is useful.

Command: {cmd}

Output (trimmed):
{output}

Objective: {objective}

Decide:
1. Is this output worth keeping? (did it reveal credentials, users, hashes, paths, or advance the attack?)
2. Extract only the concrete facts worth saving as findings.
3. Is this a dead end? (failed, access denied, timed out, nothing new)

Reply in this exact format:
USEFUL: yes|no
FINDINGS:
- <finding 1>
- <finding 2>
DEAD_END: yes|no
"""

EVALUATE_PROMPT = """\
Review this AD pentest session and assess if we are making progress.

Phase: {phase}
Steps taken: {steps}
Consecutive failures: {failures}
Objective: {objective}

Confirmed findings:
{findings}

Dead ends:
{dead_ends}

Are we moving toward the objective or stuck?

Reply in this exact format:
ON_TRACK: yes|no
PIVOT: <if no — which phase to move to: recon|foothold|lateral|privesc>
REASON: <one line>
"""

# ── state ─────────────────────────────────────────────────────────────────────

class OrchestratorState:
    """Lean state — only what the orchestrator needs to make decisions."""

    def __init__(self, session_dir: str):
        self._path = os.path.join(session_dir, "orch_state.json")
        if os.path.exists(self._path):
            with open(self._path) as f:
                self._data = json.load(f)
        else:
            self._data = {
                "objective": "get user shell and read user.txt, then escalate and read root.txt",
                "phase": "recon",
                "findings": [],          # human-readable strings
                "finding_tags": [],      # machine-readable signal keys from registry
                "dead_ends": [],
                "commands_run": [],
                "steps_taken": 0,
                "consecutive_failures": 0,
            }
            self._save()

    def _save(self):
        with open(self._path, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self._save()

    def add_finding(self, finding: str):
        if finding and finding not in self._data["findings"]:
            self._data["findings"].append(finding)
            self._save()

    def add_finding_tag(self, tag: str):
        tags = self._data.setdefault("finding_tags", [])
        if tag and tag not in tags:
            tags.append(tag)
            self._save()

    def add_dead_end(self, desc: str):
        if desc and desc not in self._data["dead_ends"]:
            self._data["dead_ends"].append(desc)
            self._save()

    def add_command(self, cmd: str):
        cmds = self._data.setdefault("commands_run", [])
        if cmd not in cmds:
            cmds.append(cmd)
            self._save()

    def increment_step(self):
        self._data["steps_taken"] += 1
        self._save()

    def increment_failures(self):
        self._data["consecutive_failures"] += 1
        self._save()

    def reset_failures(self):
        self._data["consecutive_failures"] = 0
        self._save()

    def format_list(self, key) -> str:
        items = self._data.get(key, [])
        return "\n".join(f"- {x}" for x in items) if items else "none"


# ── orchestrator ──────────────────────────────────────────────────────────────

class Orchestrator:
    MAX_FAILURES   = 3
    EVALUATE_EVERY = 5

    def __init__(self, session, session_dir: str):
        self.session     = session
        self.session_dir = session_dir
        self.ctx         = session.load()
        self.state       = OrchestratorState(session_dir)
        self._registry   = self._load_registry()

    # ── registry ──────────────────────────────────────────────────────────────

    def _load_registry(self) -> dict:
        if not os.path.exists(REGISTRY_FILE):
            return {"skills": {}, "finding_signals": {}}
        with open(REGISTRY_FILE) as f:
            return json.load(f)

    def _detect_signals(self, output: str) -> list[str]:
        """Map raw output text to finding_tag keys from registry."""
        signals = self._registry.get("finding_signals", {})
        found   = []
        lower   = output.lower()
        for tag, patterns in signals.items():
            for pat in patterns:
                if pat.lower() in lower:
                    found.append(tag)
                    break
        return found

    def _available_skills(self, phase: str) -> dict:
        """Return skills whose phase matches and all prerequisites are met."""
        # always re-derive tags from findings text to catch paraphrased mentions
        findings_text = "\n".join(self.state.get("findings", []))
        for tag in self._detect_signals(findings_text):
            self.state.add_finding_tag(tag)

        skills    = self._registry.get("skills", {})
        have_tags = set(self.state.get("finding_tags", []))
        available = {}

        for name, meta in skills.items():
            if phase not in meta.get("phases", []):
                continue
            reqs = meta.get("requires", [])
            if not all(r in have_tags for r in reqs):
                continue
            available[name] = meta

        return available

    def _read_skill_md(self, skill_name: str) -> str:
        path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
        if not os.path.exists(path):
            return f"(no SKILL.md found for {skill_name})"
        with open(path) as f:
            return f.read()

    # ── Claude calls ──────────────────────────────────────────────────────────

    def _call(self, prompt: str, timeout: int = 60) -> str | None:
        cmd = ["claude", "--dangerously-skip-permissions",
               "--output-format", "json", "-p"]
        env = os.environ.copy()

        env_file = os.path.join(os.path.expanduser("~/.holyad"), ".env")
        if os.path.exists(env_file):
            with open(env_file) as ef:
                for line in ef:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        env[k.strip()] = v.strip()

        try:
            proc = subprocess.run(
                cmd, input=prompt, capture_output=True,
                text=True, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            return None

        if not proc.stdout.strip():
            return None

        try:
            data = json.loads(proc.stdout.strip())
            return data.get("result", "").strip() or None
        except (json.JSONDecodeError, ValueError):
            return proc.stdout.strip() or None

    # ── three-step decision ───────────────────────────────────────────────────

    def pick_skill(self) -> str | None:
        """Step 1 — which skill to use? Returns skill name or None."""
        phase     = self.state.get("phase")
        available = self._available_skills(phase)

        if not available:
            # no skills unlocked — run port scan if not done yet
            cmds_run = self.state.get("commands_run", [])
            if any("nmap" in c or "rustscan" in c for c in cmds_run):
                return None  # port scan done but still nothing — genuinely stuck
            return "_port_scan"

        skill_menu = "\n".join(
            f"  {name}: {meta['description']}"
            for name, meta in available.items()
        )

        prompt   = PICK_SKILL_PROMPT.format(
            ip           = self.ctx.get("target", ""),
            phase        = phase,
            objective    = self.state.get("objective"),
            finding_tags = self.state.format_list("finding_tags"),
            dead_ends    = self.state.format_list("dead_ends"),
            skill_menu   = skill_menu,
        )
        response = self._call(prompt, timeout=60)
        if not response:
            return None

        for line in response.split("\n"):
            if line.strip().startswith("SKILL:"):
                skill = line.split("SKILL:", 1)[1].strip().lower()
                if skill in ("none", ""):
                    return None
                return skill
        return None

    def pick_command(self, skill_name: str) -> list[str] | None:
        """Step 2 — which exact command? Returns parsed command list."""
        if skill_name == "_port_scan":
            ip = self.ctx.get("target", "")
            return ["nmap", "-sC", "-sV", "-p-", "--min-rate", "5000", "-T4", ip]

        skill_md = self._read_skill_md(skill_name)

        prompt   = PICK_COMMAND_PROMPT.format(
            ip           = self.ctx.get("target", ""),
            user         = self.ctx.get("user", ""),
            password     = self.ctx.get("pass", ""),
            domain       = self.ctx.get("domain", ""),
            phase        = self.state.get("phase"),
            findings     = self.state.format_list("findings"),
            commands_run = self.state.format_list("commands_run"),
            skill_name   = skill_name,
            skill_md     = skill_md,
        )
        response = self._call(prompt, timeout=90)
        if not response:
            return None

        for line in response.split("\n"):
            if line.strip().startswith("CMD:"):
                cmd_str = line.split("CMD:", 1)[1].strip().strip("`").strip()
                if cmd_str.upper().startswith("DONE"):
                    return ["DONE", cmd_str]
                try:
                    return shlex.split(cmd_str)
                except ValueError:
                    return cmd_str.split()
        return None

    def judge(self, cmd: list[str], output: str) -> dict:
        """Step 3 — is this output worth keeping? Returns {useful, findings, dead_end}."""
        cmd_str = " ".join(cmd)
        output  = Filter.compress(output)

        MAX = 4000
        if len(output) > MAX:
            half   = MAX // 2
            output = output[:half] + "\n[... truncated ...]\n" + output[-half:]

        prompt   = JUDGE_PROMPT.format(
            cmd       = cmd_str,
            output    = output,
            objective = self.state.get("objective"),
        )
        response = self._call(prompt, timeout=90)

        result      = {"useful": False, "findings": [], "dead_end": True}
        in_findings = False

        if not response:
            return result

        for line in response.split("\n"):
            line = line.strip()
            if line.startswith("USEFUL:"):
                result["useful"] = "yes" in line.lower()
                in_findings = False
            elif line.startswith("FINDINGS:"):
                in_findings = True
            elif line.startswith("DEAD_END:"):
                result["dead_end"] = "yes" in line.lower()
                in_findings = False
            elif in_findings and line.startswith("-"):
                f = line[1:].strip()
                if f:
                    result["findings"].append(f)

        return result

    def evaluate_direction(self) -> dict:
        """Periodic check — are we making progress?"""
        prompt   = EVALUATE_PROMPT.format(
            phase    = self.state.get("phase"),
            steps    = self.state.get("steps_taken"),
            failures = self.state.get("consecutive_failures"),
            objective= self.state.get("objective"),
            findings = self.state.format_list("findings"),
            dead_ends= self.state.format_list("dead_ends"),
        )
        response = self._call(prompt, timeout=60)

        result = {"on_track": True, "pivot": None, "reason": ""}
        if not response:
            return result

        for line in response.split("\n"):
            line = line.strip()
            if line.startswith("ON_TRACK:"):
                result["on_track"] = "yes" in line.lower()
            elif line.startswith("PIVOT:"):
                result["pivot"] = line[6:].strip()
            elif line.startswith("REASON:"):
                result["reason"] = line[7:].strip()

        return result

    # ── execution ─────────────────────────────────────────────────────────────

    _SHELL_OPS = frozenset({
        '|', '||', ';', '&&', '&', '>', '>>', '<', '<<',
        '2>&1', '2>/dev/null', '2>>', '1>/dev/null',
    })

    def _build_shell_cmd(self, cmd: list[str]) -> str:
        parts = []
        for arg in cmd:
            if arg in self._SHELL_OPS or arg.startswith('2>') or arg.startswith('>>'):
                parts.append(arg)
            else:
                parts.append(shlex.quote(arg))
        return " ".join(parts)

    _EXEGOL_PATH = (
        "/root/.local/bin:/opt/tools/bin"
        ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )

    def execute(self, cmd: list[str]) -> str:
        cmd_str = self._build_shell_cmd(cmd)
        print(f"\n  → {cmd_str}\n")

        if not container_running():
            if not start_container():
                return "error: could not start docker container"

        ip      = self.ctx.get("target", "")
        workdir = f"/root/work/{ip}"

        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "mkdir", "-p", workdir],
            capture_output=True
        )

        # sync clock if skew detected
        if "clock_skew" in self.state.get("finding_tags", []):
            subprocess.run(
                ["docker", "exec", CONTAINER_NAME,
                 "bash", "-c", f"ntpdate -u {ip} 2>/dev/null || true"],
                capture_output=True
            )

        docker_cmd = [
            "docker", "exec",
            "-w", workdir,
            "-e", f"PATH={self._EXEGOL_PATH}",
            CONTAINER_NAME,
            "bash", "-c", cmd_str,
        ]

        out_lines = []
        try:
            proc = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            for line in proc.stdout:
                print(line, end="")
                out_lines.append(line)
            proc.wait()
        except Exception as e:
            err = f"error: {e}"
            print(f"  {err}")
            return err

        return "".join(out_lines)

    # ── file seeding ──────────────────────────────────────────────────────────

    def seed_from_files(self, filepaths: list[str]):
        MAX_FILE_CHARS = 6000

        for fp in filepaths:
            if not os.path.isfile(fp):
                print(f"  [seed] file not found: {fp}")
                continue

            print(f"  [seed] reading {os.path.basename(fp)}...", end=" ", flush=True)
            try:
                with open(fp, "r", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                print(f"error: {e}")
                continue

            if len(content) > MAX_FILE_CHARS:
                half = MAX_FILE_CHARS // 2
                content = content[:half] + "\n[... truncated ...]\n" + content[-half:]

            verdict = self.judge([f"file:{os.path.basename(fp)}"], content)
            print(f"{'useful' if verdict['useful'] else 'nothing new'}  ({len(verdict['findings'])} findings)")

            for finding in verdict["findings"]:
                self.state.add_finding(finding)
                print(f"  + {finding}")

            # detect signal tags from raw file content
            for tag in self._detect_signals(content):
                self.state.add_finding_tag(tag)

            # also detect from extracted findings text (catches paraphrased port mentions)
            findings_text = "\n".join(verdict["findings"])
            for tag in self._detect_signals(findings_text):
                self.state.add_finding_tag(tag)

        if self.state.get("findings"):
            print()

    # ── main loop ─────────────────────────────────────────────────────────────

    def run(self, max_steps: int = 0, seed_files: list[str] = None):
        if not self.ctx.get("target"):
            print("error: no active session — run 'holyad --start <ip>' first")
            return

        limit_str = str(max_steps) if max_steps > 0 else "unlimited"
        print(f"\n  [auto] target    : {self.ctx['target']}")
        print(f"  [auto] phase     : {self.state.get('phase')}")
        print(f"  [auto] objective : {self.state.get('objective')}")
        print(f"  [auto] max steps : {limit_str}\n")

        if seed_files:
            print(f"  [seed] loading {len(seed_files)} file(s)...\n")
            self.seed_from_files(seed_files)

        try:
            self._loop(max_steps)
        except KeyboardInterrupt:
            print("\n\n  [auto] interrupted — state saved to orch_state.json\n")

    def _loop(self, max_steps: int):
        step = 0
        while True:
            step += 1
            self.state.increment_step()
            phase     = self.state.get("phase")
            limit_str = f"/{max_steps}" if max_steps > 0 else ""
            print(f"  ── step {step}{limit_str}  phase: {phase} {'─' * 30}")

            # ── periodic direction check ──────────────────────────────────────
            if step > 1 and step % self.EVALUATE_EVERY == 0:
                print("  [evaluate] checking direction...", end=" ", flush=True)
                ev = self.evaluate_direction()
                if ev["on_track"]:
                    print("on track")
                else:
                    print(f"off track — {ev['reason']}")
                    if ev["pivot"] and ev["pivot"] in PHASES:
                        self.state.set("phase", ev["pivot"])
                        print(f"  [pivot] → {ev['pivot']}")
                    else:
                        print("  [stop] no valid pivot — stopping")
                        break

            # ── step 1: pick skill ────────────────────────────────────────────
            print("  [pick_skill] ...", end=" ", flush=True)
            skill = self.pick_skill()

            if not skill:
                print("no skill selected — stopping")
                break

            display = "port_scan" if skill == "_port_scan" else skill
            print(f"→ {display}")

            # ── step 2: pick command ──────────────────────────────────────────
            print("  [pick_cmd]   ...", end=" ", flush=True)
            cmd = self.pick_command(skill)

            if not cmd:
                print("no command generated — skipping")
                self.state.increment_failures()
                continue

            cmd_str = " ".join(cmd)

            if cmd[0].upper() == "DONE":
                print(f"\n  [auto] finished — {' '.join(cmd[1:])}\n")
                break

            print(f"→ {cmd_str}")

            # ── step 3: execute ───────────────────────────────────────────────
            output = self.execute(cmd)
            self.state.add_command(cmd_str)

            # ── goal check ────────────────────────────────────────────────────
            if goal_reached(output):
                print("\n  [auto] GOAL REACHED — shell or DA obtained\n")
                break

            # ── detect signal tags from raw output ────────────────────────────
            for tag in self._detect_signals(output):
                self.state.add_finding_tag(tag)

            # ── step 4: judge output ──────────────────────────────────────────
            print("  [judge]      ...", end=" ", flush=True)
            verdict = self.judge(cmd, output)
            print(f"useful: {'yes' if verdict['useful'] else 'no'}")

            for f in verdict["findings"]:
                self.state.add_finding(f)
                print(f"  + {f}")

            if verdict["dead_end"]:
                self.state.add_dead_end(cmd_str)
                self.state.increment_failures()
                print(f"  [dead end] marked — failures: {self.state.get('consecutive_failures')}")
            else:
                self.state.reset_failures()

            # ── stop if stuck ─────────────────────────────────────────────────
            if self.state.get("consecutive_failures", 0) >= self.MAX_FAILURES:
                print(f"\n  [auto] {self.MAX_FAILURES} consecutive failures — intervention needed")
                print("  tip: 'holyad --add \"observation\"' to add context, then retry\n")
                break

            # ── hard limit ────────────────────────────────────────────────────
            if max_steps > 0 and step >= max_steps:
                print(f"\n  [auto] max steps ({max_steps}) reached\n")
                break

            print()
