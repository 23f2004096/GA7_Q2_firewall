from fastapi import FastAPI, Request
from typing import Any
import re


app = FastAPI()

ALLOWED_TENANT = "tenant-a7h1iwz"
ALLOWED_EMAIL_DOMAIN = "notify-msjfzdz.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


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


def exact_keys(obj: dict, expected: set[str]) -> bool:
    return set(obj.keys()) == expected


def unsafe_html(html: str) -> bool:

    # script tags
    if re.search(r"<\s*script\b", html, re.IGNORECASE):
        return True

    # iframe tags
    if re.search(r"<\s*iframe\b", html, re.IGNORECASE):
        return True

    # inline event handlers:
    # onclick=
    # onload=
    # onerror=
    if re.search(r"\bon[a-zA-Z]+\s*=", html, re.IGNORECASE):
        return True

    # javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return True

    return False


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/action-firewall")
async def action_firewall(request: Request):

    # =====================================================
    # 1. TOP-LEVEL JSON SCHEMA
    # =====================================================

    try:
        payload = await request.json()
    except Exception:
        return block("INVALID_SCHEMA")

    if not isinstance(payload, dict):
        return block("INVALID_SCHEMA")

    # Required top-level fields
    required = {
        "provenance",
        "humanApproved",
        "action"
    }

    allowed_top_level = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action"
    }

    # Reject missing or extra fields
    if not required.issubset(payload.keys()):
        return block("INVALID_SCHEMA")

    if not set(payload.keys()).issubset(allowed_top_level):
        return block("INVALID_SCHEMA")

    provenance = payload["provenance"]
    human_approved = payload["humanApproved"]
    action = payload["action"]

    # provenance
    if provenance not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    # humanApproved
    if not isinstance(human_approved, bool):
        return block("INVALID_SCHEMA")

    # untrustedContent, if supplied
    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return block("INVALID_SCHEMA")

    # action
    if not isinstance(action, dict):
        return block("INVALID_SCHEMA")

    if not exact_keys(action, {"tool", "args"}):
        return block("INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]

    if not isinstance(tool, str):
        return block("INVALID_SCHEMA")

    if not isinstance(args, dict):
        return block("INVALID_SCHEMA")


    # =====================================================
    # 2. TOOL ALLOWLIST
    # =====================================================

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")


    # =====================================================
    # 3. TOOL ARGUMENT SCHEMA
    # =====================================================

    if tool == "search":

        if not exact_keys(args, {"query"}):
            return block("INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return block("INVALID_SCHEMA")

        if len(query) < 1 or len(query) > 200:
            return block("INVALID_SCHEMA")


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


    elif tool == "send_email":

        if not exact_keys(args, {"to", "subject", "body"}):
            return block("INVALID_SCHEMA")

        if not isinstance(args["to"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["subject"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["body"], str):
            return block("INVALID_SCHEMA")


    elif tool == "render_html":

        if not exact_keys(args, {"html"}):
            return block("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return block("INVALID_SCHEMA")


    # =====================================================
    # 4. TENANT SCOPE
    # =====================================================

    if tool == "lookup_record":

        if args["tenantId"] != ALLOWED_TENANT:
            return block("TENANT_SCOPE")


    # =====================================================
    # 5. EMAIL EGRESS
    # =====================================================

    if tool == "send_email":

        email = args["to"]

        if "@" not in email:
            return block("EGRESS_DENIED")

        parts = email.rsplit("@", 1)

        if len(parts) != 2:
            return block("EGRESS_DENIED")

        local_part, domain = parts

        if local_part == "":
            return block("EGRESS_DENIED")

        # EXACT domain match
        if domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")


    # =====================================================
    # 6. HUMAN APPROVAL
    # =====================================================

    if tool == "send_email":

        if human_approved is not True:
            return block("APPROVAL_REQUIRED")


    # =====================================================
    # 7. HTML SAFETY
    # =====================================================

    if tool == "render_html":

        if unsafe_html(args["html"]):
            return block("UNSAFE_OUTPUT")


    # =====================================================
    # SUCCESS
    # =====================================================

    return allow()