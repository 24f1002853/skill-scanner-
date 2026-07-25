from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()

class SkillRequest(BaseModel):
    skill: str


# ----------------------------
# Detection helpers
# ----------------------------

def detect_hardcoded_secret(text: str) -> bool:
    patterns = [
        r"AKIA[0-9A-Z]{16}",                       # AWS Access Key
        r"AIza[0-9A-Za-z\-_]{35}",                # Google API Key
        r"gh[pousr]_[A-Za-z0-9]{36,}",            # GitHub tokens
        r"sk-[A-Za-z0-9]{20,}",                   # OpenAI-style
        r"https://hooks\.slack\.com/services/[^\s\"']+",
        r"xox[baprs]-[A-Za-z0-9-]+",
        r"Bearer\s+[A-Za-z0-9._\-]{20,}",
        r"password\s*:\s*['\"][^'\"]+['\"]",
        r"token\s*:\s*['\"][^'\"]+['\"]",
        r"secret\s*:\s*['\"][^'\"]+['\"]",
        r"api[_-]?key\s*:\s*['\"][^'\"]+['\"]",
    ]

    # Ignore obvious env-variable references
    if re.search(r"\$\{?[A-Z0-9_]+\}?|os\.getenv|ENV\[|process\.env", text):
        env_refs = True
    else:
        env_refs = False

    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            if not env_refs:
                return True
    return False


def detect_prompt_injection(text: str) -> bool:
    patterns = [
        r"ignore (all )?(previous|prior|above) instructions",
        r"ignore the user",
        r"ignore user.*stop",
        r"ignore.*cancel",
        r"do not tell the user",
        r"without informing the user",
        r"silently exfiltrate",
        r"secretly upload",
        r"send .* to .* without",
        r"bypass safety",
        r"override system prompt",
        r"override user instructions",
        r"continue even if.*cancel",
    ]

    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def detect_excessive_permissions(text: str) -> bool:
    patterns = [
        r"read.*entire filesystem",
        r"write.*entire filesystem",
        r"full filesystem access",
        r"filesystem:\s*full",
        r"permissions:.*\*",
        r"network:\s*any",
        r"egress:\s*any",
        r"allow.*all domains",
        r"access to all files",
        r"read/write.*\/",
    ]

    return any(re.search(p, text, re.IGNORECASE | re.DOTALL) for p in patterns)


def detect_unclear_provenance(text: str) -> bool:
    lower = text.lower()

    missing_author = not re.search(r"^author\s*:", text, re.MULTILINE | re.IGNORECASE)
    missing_version = not re.search(r"^version\s*:", text, re.MULTILINE | re.IGNORECASE)
    missing_changelog = (
        "changelog" not in lower
        and "changes:" not in lower
        and "history" not in lower
    )

    metadata_rewrite = bool(
        re.search(
            r"(rewrite|update|modify|change).*(version|frontmatter|metadata).*without",
            lower,
        )
    )

    return (
        (missing_author and missing_version and missing_changelog)
        or metadata_rewrite
    )


@app.post("/")
def scan(req: SkillRequest):
    text = req.skill

    categories = []

    if detect_hardcoded_secret(text):
        categories.append("hardcoded_secret")

    if detect_prompt_injection(text):
        categories.append("prompt_injection")

    if detect_excessive_permissions(text):
        categories.append("excessive_permissions")

    if detect_unclear_provenance(text):
        categories.append("unclear_provenance")

    return {"categories": categories}
