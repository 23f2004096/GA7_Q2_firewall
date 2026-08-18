from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict
from typing import Any
from urllib.parse import urlparse
import re


app = FastAPI()


# =========================================================
# ASSIGNED SCOPE
# =========================================================

ALLOWED_TENANT = "tenant-a7h1iwz"
ALLOWED_EMAIL_DOMAIN = "notify-msjfzdz.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


# =========================================================
# TOP-LEVEL INPUT SCHEMA
# =========================================================

class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provenance: str
    humanApproved: bool
    untrustedContent: str | None = None
    action: dict[str, Any]


# =========================================================
# RESPONSE HELPER
# =========================================================

def block(reason: str):
    return {
        "decision": "block",
        "reason": reason
    }


def allow():
    return {
        "decision": "allow",
        "reason": "ALLOW"
    }


# =========================================================
# HTML SAFETY
# =========================================================

def unsafe_html(html: str) -> bool:

    # Block <script>
    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return True

    # Block <iframe>
    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return True

    # Block inline event handlers such as:
    # onclick=
    # onload=
    # onerror=
    if re.search(r"\bon[a-zA-Z]+\s*=", html, re.IGNORECASE):
        return True

    # Block javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return True

    return False


# =========================================================
# ARGUMENT SCHEMA HELPERS
# =========================================================

def is_string(value):
    return isinstance(value, str)


def exact_keys(obj: dict, expected: set[str]) -> bool:
    return set(obj.keys()) == expected


# =========================================================
# MAIN ENDPOINT
# =========================================================

@app.post("/action-firewall")
def action_firewall(payload: dict[str, Any]):

    # -----------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # -----------------------------------------------------

    try:
        request = ActionRequest.model_validate(payload)
    except Exception:
        return block("INVALID_SCHEMA")

    if request.provenance not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    if not isinstance(request.humanApproved, bool):
        return block("INVALID_SCHEMA")

    if request.untrustedContent is not None:
        if not isinstance(request.untrustedContent, str):
            return block("INVALID_SCHEMA")

    if not isinstance(request.action, dict):
        return block("INVALID_SCHEMA")

    # Action must contain exactly tool + args
    if not exact_keys(request.action, {"tool", "args"}):
        return block("INVALID_SCHEMA")

    tool = request.action["tool"]
    args = request.action["args"]

    if not isinstance(tool, str):
        return block("INVALID_SCHEMA")

    if not isinstance(args, dict):
        return block("INVALID_SCHEMA")


    # -----------------------------------------------------
    # 2. TOOL ALLOWLIST
    # -----------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")


    # -----------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # -----------------------------------------------------

    # =====================================================
    # SEARCH
    # =====================================================

    if tool == "search":

        if not exact_keys(args, {"query"}):
            return block("INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return block("INVALID_SCHEMA")

        if not (1 <= len(query) <= 200):
            return block("INVALID_SCHEMA")


    # =====================================================
    # LOOKUP_RECORD
    # =====================================================

    elif tool == "lookup_record":

        if not exact_keys(args, {"tenantId", "recordId"}):
            return block("INVALID_SCHEMA")

        tenant_id = args["tenantId"]
        record_id = args["recordId"]

        if not isinstance(tenant_id, str):
            return block("INVALID_SCHEMA")

        if not isinstance(record_id, str):
            return block("INVALID_SCHEMA")

        if record_id == "":
            return block("INVALID_SCHEMA")


    # =====================================================
    # SEND_EMAIL
    # =====================================================

    elif tool == "send_email":

        if not exact_keys(args, {"to", "subject", "body"}):
            return block("INVALID_SCHEMA")

        to = args["to"]
        subject = args["subject"]
        body = args["body"]

        if not isinstance(to, str):
            return block("INVALID_SCHEMA")

        if not isinstance(subject, str):
            return block("INVALID_SCHEMA")

        if not isinstance(body, str):
            return block("INVALID_SCHEMA")


    # =====================================================
    # RENDER_HTML
    # =====================================================

    elif tool == "render_html":

        if not exact_keys(args, {"html"}):
            return block("INVALID_SCHEMA")

        html = args["html"]

        if not isinstance(html, str):
            return block("INVALID_SCHEMA")


    # -----------------------------------------------------
    # 4. TENANT SCOPE
    # -----------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ALLOWED_TENANT:
            return block("TENANT_SCOPE")


    # -----------------------------------------------------
    # 5. EMAIL EGRESS
    # -----------------------------------------------------

    if tool == "send_email":

        email = args["to"].strip()

        # Basic email structure check
        if "@" not in email:
            return block("EGRESS_DENIED")

        local_part, domain = email.rsplit("@", 1)

        if not local_part or not domain:
            return block("EGRESS_DENIED")

        # EXACT domain comparison
        if domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")


    # -----------------------------------------------------
    # 6. HUMAN APPROVAL
    # -----------------------------------------------------

    if tool == "send_email":

        if request.humanApproved is not True:
            return block("APPROVAL_REQUIRED")


    # -----------------------------------------------------
    # 7. HTML SAFETY
    # -----------------------------------------------------

    if tool == "render_html":

        if unsafe_html(args["html"]):
            return block("UNSAFE_OUTPUT")


    # -----------------------------------------------------
    # EVERYTHING PASSED
    # -----------------------------------------------------

    return allow()


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def root():
    return {"status": "ok"}