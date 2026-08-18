from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Any, Dict
import json
import re

app = FastAPI()


# =========================================================
# ACTION FIREWALL
# =========================================================

ASSIGNED_TENANT = "tenant-lqccake"
ALLOWED_EMAIL_DOMAIN = "notify-dm117fp.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def firewall_result(decision: str, reason: str):
    return {
        "decision": decision,
        "reason": reason,
    }


def exact_keys(obj: dict, expected: set[str]) -> bool:
    return set(obj.keys()) == expected


def unsafe_html(html: str) -> bool:

    unsafe_patterns = [
        r"<\s*script\b",
        r"</\s*script\s*>",
        r"<\s*iframe\b",
        r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
        r"javascript\s*:",
    ]

    for pattern in unsafe_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            return True

    return False


def valid_email_for_domain(email: str) -> bool:

    pattern = (
        r"^[^@\s]+@"
        + re.escape(ALLOWED_EMAIL_DOMAIN)
        + r"$"
    )

    return re.fullmatch(pattern, email) is not None


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/action-firewall")
async def action_firewall(request: Request):

    # ---------------------------------------------------------
    # 1. Top-level schema
    # ---------------------------------------------------------

    try:
        raw_body = await request.body()
        payload = json.loads(raw_body)
    except Exception:
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(payload, dict):
        return firewall_result("block", "INVALID_SCHEMA")

    required_keys = {
        "provenance",
        "humanApproved",
        "action",
    }

    allowed_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    if not required_keys.issubset(payload.keys()):
        return firewall_result("block", "INVALID_SCHEMA")

    if not set(payload.keys()).issubset(allowed_keys):
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(payload["provenance"], str):
        return firewall_result("block", "INVALID_SCHEMA")

    if payload["provenance"] not in {
        "trusted",
        "untrusted",
    }:
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(payload["humanApproved"], bool):
        return firewall_result("block", "INVALID_SCHEMA")

    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return firewall_result("block", "INVALID_SCHEMA")

    action = payload["action"]

    if not isinstance(action, dict):
        return firewall_result("block", "INVALID_SCHEMA")

    if not exact_keys(action, {"tool", "args"}):
        return firewall_result("block", "INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]

    if not isinstance(tool, str):
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(args, dict):
        return firewall_result("block", "INVALID_SCHEMA")


    # ---------------------------------------------------------
    # 2. Tool allowlist
    # ---------------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return firewall_result("block", "TOOL_NOT_ALLOWED")


    # ---------------------------------------------------------
    # 3. Tool argument schemas
    # ---------------------------------------------------------

    if tool == "search":

        if not exact_keys(args, {"query"}):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["query"], str):
            return firewall_result("block", "INVALID_SCHEMA")

        if not 1 <= len(args["query"]) <= 200:
            return firewall_result("block", "INVALID_SCHEMA")


    elif tool == "lookup_record":

        if not exact_keys(args, {"tenantId", "recordId"}):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return firewall_result("block", "INVALID_SCHEMA")

        if args["recordId"] == "":
            return firewall_result("block", "INVALID_SCHEMA")


    elif tool == "send_email":

        if not exact_keys(args, {"to", "subject", "body"}):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["to"], str):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["subject"], str):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["body"], str):
            return firewall_result("block", "INVALID_SCHEMA")


    elif tool == "render_html":

        if not exact_keys(args, {"html"}):
            return firewall_result("block", "INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return firewall_result("block", "INVALID_SCHEMA")


    # ---------------------------------------------------------
    # 4. Tenant scope
    # ---------------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return firewall_result("block", "TENANT_SCOPE")


    # ---------------------------------------------------------
    # 5. Egress
    # ---------------------------------------------------------

    if tool == "send_email":

        if not valid_email_for_domain(args["to"]):
            return firewall_result("block", "EGRESS_DENIED")


    # ---------------------------------------------------------
    # 6. Human approval
    # ---------------------------------------------------------

    if tool == "send_email":

        if payload["humanApproved"] is not True:
            return firewall_result(
                "block",
                "APPROVAL_REQUIRED"
            )


    # ---------------------------------------------------------
    # 7. HTML safety
    # ---------------------------------------------------------

    if tool == "render_html":

        if unsafe_html(args["html"]):
            return firewall_result(
                "block",
                "UNSAFE_OUTPUT"
            )


    # ---------------------------------------------------------
    # Everything passed
    # ---------------------------------------------------------

    return firewall_result("allow", "ALLOW")