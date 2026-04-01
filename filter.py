import re

class Filter:
    # ANSI escape codes, carriage returns, repeated separators
    _ANSI_RE      = re.compile(r'\x1b\[[0-9;]*[mGKHFJA-Z]')
    _SEP_LINE_RE  = re.compile(r'^[=\-#\*_]{5,}\s*$', re.MULTILINE)
    _BLANK_RE     = re.compile(r'\n{3,}')

    @classmethod
    def compress(cls, output: str) -> str:
        """Strip formatting noise — ANSI codes, blank lines, separator lines."""
        output = cls._ANSI_RE.sub('', output)
        output = output.replace('\r', '')
        output = '\n'.join(line.rstrip() for line in output.split('\n'))
        output = cls._SEP_LINE_RE.sub('', output)
        output = cls._BLANK_RE.sub('\n\n', output)
        return output.strip()

    # signals that indicate a meaningful discovery
    SIGNALS = [
        # network
        r"\d+/tcp\s+open", r"\d+/udp\s+open",
        # services
        r"smb", r"ldap", r"kerberos", r"winrm", r"msrpc", r"mssql",
        # AD artifacts
        r"domain", r"forest", r"dc=", r"distinguishedname", r"objectclass",
        r"serviceprincipalname", r"spn", r"krbtgt",
        # credentials and hashes
        r"hash", r"ntlm", r"\$krb5", r"password", r"aes256", r"aes128",
        # shares
        r"share", r"disk", r"read only", r"read,write",
        # auth signals
        r"anonymous", r"null session", r"signing", r"status_logon_failure",
        r"status_access_denied", r"account_disabled",
        # tool specific
        r"found", r"valid", r"success", r"error.*login", r"bloodhound",
    ]

    # patterns that indicate useless output — discard immediately
    DISCARD = [
        r"command not found",
        r"invalid option",
        r"unrecognized",
        r"unknown flag",
        r"^usage:",
        r"try '--help'",
    ]

    @classmethod
    def should_send(cls, output: str, command: str = "") -> bool:
        output = cls.compress(output)
        output_lower = output.lower().strip()

        # layer 1: empty output
        if not output_lower:
            return False

        # layer 2: discard patterns
        for pattern in cls.DISCARD:
            if re.search(pattern, output_lower):
                return False

        # layer 3: signal detection
        for signal in cls.SIGNALS:
            if re.search(signal, output_lower):
                return True

        return False
