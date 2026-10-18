"""Dockerfile hardening rules."""
from __future__ import annotations

import re

from backend.engines.rules.model import PatternRule, rx
from backend.schemas import Severity

_I = re.IGNORECASE
CIS = "https://docs.docker.com/develop/develop-images/instructions/"

ROOT_USER = PatternRule(
    "DOCKER001", "Container runs as root", rx(r"^FROM\b", _I), Severity.MEDIUM, 0.7, "CWE-250",
    "The final image never switches to an unprivileged USER, so the application runs as root and "
    "a compromise of the process is a compromise of the container.",
    references=(CIS,),
)

UNPINNED_IMAGE = PatternRule(
    "DOCKER002", "Base image is not pinned", rx(r"^FROM\b", _I), Severity.LOW, 0.8, "CWE-829",
    "The base image uses the latest tag or no tag, so every build can silently pull different, "
    "unreviewed software.",
    references=(CIS,),
)

INSTRUCTION_RULES = (
    PatternRule(
        "DOCKER003", "ADD fetches a remote URL", rx(r"^ADD\s+(?:--\S+\s+)*https?://", _I),
        Severity.MEDIUM, 0.8, "CWE-829",
        "ADD downloads remote content without integrity verification.",
        references=(CIS,),
    ),
    PatternRule(
        "DOCKER004", "Remote script piped into a shell",
        rx(r"^RUN\b.*\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", _I),
        Severity.HIGH, 0.75, "CWE-494",
        "Piping a downloaded script into a shell executes whatever the remote server returns.",
    ),
    PatternRule(
        "DOCKER005", "Secret baked into the image",
        rx(r"^(?:ENV|ARG)\s+[\"']?\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)"
           r"\w*[\"']?(?:\s*=\s*|\s+)[\"']?[^\s\"'$]{4,}", _I),
        Severity.HIGH, 0.7, "CWE-798",
        "Values set with ENV or ARG are stored in the image layers and history, readable by anyone "
        "who can pull the image.",
    ),
    PatternRule(
        "DOCKER006", "World-writable permissions", rx(r"^RUN\b.*\bchmod\s+(?:-R\s+)?0?777\b", _I),
        Severity.MEDIUM, 0.8, "CWE-732",
        "chmod 777 lets every user and process in the container modify these files.",
    ),
    PatternRule(
        "DOCKER007", "sudo used in a build step", rx(r"^RUN\b.*\bsudo\b", _I),
        Severity.LOW, 0.6, "CWE-250",
        "sudo in an image usually means the runtime user can escalate to root.",
    ),
    PatternRule(
        "DOCKER008", "TLS verification disabled during build",
        rx(r"^RUN\b.*(?:--no-check-certificate|\bcurl\b[^\n]*\s(?:-k|--insecure)\b|"
           r"--trusted-host|sslverify\s*=\s*(?:0|false))", _I),
        Severity.MEDIUM, 0.8, "CWE-295",
        "Downloads made without certificate checks can be replaced in transit.",
    ),
    PatternRule(
        "DOCKER009", "SSH port exposed", rx(r"^EXPOSE\b.*\b22\b", _I),
        Severity.LOW, 0.6, "CWE-284",
        "Running SSH inside a container widens the attack surface; use docker exec instead.",
    ),
)
