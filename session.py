import json
import os
from datetime import datetime, timezone

SESSION_FILE = os.path.join(os.path.expanduser("~/.holyad"), "context.json")
REPORT_FILE  = os.path.join(os.path.expanduser("~/.holyad"), "report.md")
LOG_FILE     = os.path.join(os.path.expanduser("~/.holyad"), "agent.log")

class Session:
    def init(self, ip: str, credentials: str = None):
        os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)

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

        with open(SESSION_FILE, "w") as f:
            json.dump(data, f, indent=2)

        with open(REPORT_FILE, "w") as f:
            f.write(f"# HTB Session Report\n")
            f.write(f"- **Target:** {ip}\n")
            f.write(f"- **Type:** {session_type}\n")
            f.write(f"- **Started:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n---\n\n")

    def load(self) -> dict:
        if not os.path.exists(SESSION_FILE):
            return {}
        with open(SESSION_FILE, "r") as f:
            return json.load(f)

    def save(self, data: dict):
        with open(SESSION_FILE, "w") as f:
            json.dump(data, f, indent=2)

    def log_response(self, response: str):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = datetime.now().strftime("%H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"\n[{timestamp}]\n{response}\n")

    def save_report(self, content: str):
        with open(REPORT_FILE, "a") as f:
            f.write(f"\n## Report\n\n{content}\n")