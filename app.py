from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
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


def result(decision, reason):
    return JSONResponse(
        content={
            "decision": decision,
            "reason": reason
        }
    )


def block(reason):
    return result("block", reason)


def allow():
    return result("allow", "ALLOW")


def exact_keys(obj, expected):
    return isinstance(obj, dict) and set(obj.keys()) == expected


def unsafe_html(html):
    # script
    if re.search(r"<\s*script\b", html, re.I):
        return True

    # iframe
    if re.search(r"<\s*iframe\b", html, re.I):
        return True

    # inline event handlers: onclick, onload, onerror, etc.
    if re.search(r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=", html, re.I):
        return True

    # javascript: URLs
    if re.search(r"javascript\s*:", html, re.I):
        return True

    return False


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/action-firewall")
async def action_firewall(request: Request):

    # =====================================================
    # 1. TOP-LEVEL SCHEMA
    # =====================================================

    try:
        raw = await request.body()
        payload = json.loads(raw)
    except Exception:
        return block("INVALID_SCHEMA")

    if not isinstance(payload, dict):
        return block("INVALID_SCHEMA")

    allowed_top = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action"
    }

    required_top = {
        "provenance",
        "humanApproved",
        "action"
    }

    if not required_top.issubset(payload.keys()):
        return block("INVALID_SCHEMA")

    if not set(payload.keys()).issubset(allowed_top):
        return block("INVALID_SCHEMA")

    if not isinstance(payload["provenance"], str):
        return block("INVALID_SCHEMA")

    if payload["provenance"] not in {"trusted", "untrusted"}:
        return block("INVALID_SCHEMA")

    if not isinstance(payload["humanApproved"], bool):
        return block("INVALID_SCHEMA")

    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return block("INVALID_SCHEMA")

    action = payload["action"]

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

        if not isinstance(args["query"], str):
            return block("INVALID_SCHEMA")

        if not 1 <= len(args["query"]) <= 200:
            return block("INVALID_SCHEMA")


    elif tool == "lookup_record":

        if not exact_keys(args, {"tenantId", "recordId"}):
            return block("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return block("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return block("INVALID_SCHEMA")

        if args["recordId"] == "":
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
    # 5. EGRESS
    # =====================================================

    if tool == "send_email":

        email = args["to"]

        if "@" not in email:
            return block("EGRESS_DENIED")

        local, domain = email.rsplit("@", 1)

        if local == "" or domain == "":
            return block("EGRESS_DENIED")

        if domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")


    # =====================================================
    # 6. APPROVAL
    # =====================================================

    if tool == "send_email":

        if payload["humanApproved"] is not True:
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