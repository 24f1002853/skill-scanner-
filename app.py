from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# -----------------------------
# Helper: Extract YAML frontmatter
# -----------------------------
def get_frontmatter(text: str):
    text = text.lstrip("\ufeff\r\n\t ")
    m = re.search(r"^---\s*\n(.*?)\n---\s*", text, re.DOTALL | re.MULTILINE)
    return m.group(1) if m else ""


# -----------------------------
# Hardcoded Secret
# -----------------------------
def detect_hardcoded_secret(text: str):

    # If only environment variables are used, don't flag.
    env_patterns = [
        r"\$\{?[A-Z0-9_]+\}?",
        r"os\.getenv",
        r"process\.env",
        r"ENV\[",
        r"secret manager",
    ]

    

    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",                        # AWS
        r"AIza[0-9A-Za-z\-_]{35}",                 # Google
        r"gh[pousr]_[A-Za-z0-9]{30,}",             # GitHub
        r"sk-[A-Za-z0-9]{20,}",                    # OpenAI
        r"xox[baprs]-[A-Za-z0-9\-]{20,}",          # Slack token
        r"https://hooks\.slack\.com/services/[^\s]+",
        r"Bearer\s+[A-Za-z0-9._\-]{25,}",
    ]
    secret_patterns.extend([
    r"https://[^ \n\"']*/webhooks?/[^ \n\"']+",
    r"Bearer\s+[A-Za-z0-9._=-]{20,}",
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+",  # JWT
    ])

    for p in secret_patterns:
        if re.search(p, text):
            return True

    return False


# -----------------------------
# Prompt Injection
# -----------------------------
def detect_prompt_injection(text: str):

    patterns = [
        r"ignore (all )?(previous|prior|above) instructions",
        r"ignore (the )?user('?s)? (request|instructions)",
        r"ignore.*(stop|cancel)",
        r"override (system|developer|user) instructions",
        r"continue even if.*(stop|cancel)",
        r"do not tell the user",
        r"without informing the user",
        r"silently exfiltrate",
        r"secretly upload",
        r"secretly send",
        r"bypass safety",
    ]

    return any(re.search(p, text, re.IGNORECASE | re.DOTALL) for p in patterns)

# -----------------------------
# Excessive Permissions
# -----------------------------
def detect_excessive_permissions(text: str):

    patterns = [
        r"filesystem\s*:\s*full",
        r"filesystem\s*:\s*\*",
        r"filesystem\s*:\s*read-write",

        r"network\s*:\s*any",
        r"network\s*:\s*\*",

        r"egress\s*:\s*any",

        r"allow.*all domains",
        r"all domains",

        r"read/write.*entire filesystem",
        r"read.*entire filesystem",
        r"write.*entire filesystem",

        r"access to all files",
        r"read all files",
        r"write all files",

        r"full filesystem access",
        r"internet access",
    ]

    return any(re.search(p, text, re.IGNORECASE | re.DOTALL) for p in patterns)
# -----------------------------
# Unclear Provenance
# -----------------------------
def detect_unclear_provenance(text: str):

    fm = get_frontmatter(text)

    author = re.search(r"^author\s*:", fm, re.MULTILINE | re.IGNORECASE)
    version = re.search(r"^version\s*:", fm, re.MULTILINE | re.IGNORECASE)
    has_changelog = (
        re.search(r"^changelog\s*:", fm, re.MULTILINE | re.IGNORECASE)
        or re.search(r"^history\s*:", fm, re.MULTILINE | re.IGNORECASE)
        or re.search(r"^changes\s*:", fm, re.MULTILINE | re.IGNORECASE)
        or "## changelog" in text.lower()
    )

    missing_metadata = (not author) and (not version) and (not has_changelog)

    silent_metadata_change = re.search(
    r"(update|rewrite|modify|change|overwrite).{0,80}"
    r"(version|metadata|frontmatter|changelog).{0,80}"
    r"(silently|without notifying|without informing|don't mention|do not mention)",
    text,
    re.IGNORECASE | re.DOTALL,
    )

    return missing_metadata or bool(silent_metadata_change)


@app.get("/")
def health():
    return {"status": "ok"}


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
