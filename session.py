import json
import os
from datetime import datetime, timezone

HOLYAD_BASE = os.path.expanduser("~/.holyad")

# active session pointer — tracks which IP is current
ACTIVE_FILE = os.path.join(HOLYAD_BASE, "active")

def get_session_dir(ip: str = None) -> str:
    """Return session dir for given IP, or current active session."""
    if ip:
        return os.path.join(HOLYAD_BASE, ip)
    if os.path.exists(ACTIVE_FILE):
        with open(ACTIVE_FILE) as f:
            ip = f.read().strip()
        return os.path.join(HOLYAD_BASE, ip)
    return None

class Session:
    def __init__(self, ip: str = None):
        self.session_dir = get_session_dir(ip)

    def _path(self, filename: str) -> str:
        return os.path.join(self.session_dir, filename)

    def init(self, ip: str, credentials: str = None):
        self.session_dir = os.path.join(HOLYAD_BASE, ip)
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(HOLYAD_BASE, exist_ok=True)

        # set as active session
        with open(ACTIVE_FILE, "w") as f:
            f.write(ip)

        session_type = "credentialed" if credentials else "non_credentialed"
        user, password = ("", "")
        if credentials and ":" in credentials:
            user, password = credentials.split(":", 1)

        data = {
            "target": ip,
            "type": session_type,
            "user": user,
            "pass": password,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "sent_commands": []
        }

        with open(self._path("context.json"), "w") as f:
            json.dump(data, f, indent=2)

        with open(self._path("report.md"), "w") as f:
            f.write(f"# HTB Session Report\n")
            f.write(f"- **Target:** {ip}\n")
            f.write(f"- **Type:** {session_type}\n")
            f.write(f"- **Started:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n---\n\n")

    def load(self) -> dict:
        if not self.session_dir:
            return {}
        path = self._path("context.json")
        if not os.path.exists(path):
            return {}
        with open(path) as f:
            return json.load(f)

    def save(self, data: dict):
        with open(self._path("context.json"), "w") as f:
            json.dump(data, f, indent=2)

    def log_response(self, response: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        with open(self._path("agent.log"), "a") as f:
            f.write(f"\n[{timestamp}]\n{response}\n")

    def save_report(self, content: str):
        with open(self._path("report.md"), "a") as f:
            f.write(f"\n## Report\n\n{content}\n")

    def save_output(self, cmd: str, output: str):
        with open(self._path("last_output.txt"), "w") as f:
            f.write(f"command: {cmd}\n\n{output}")