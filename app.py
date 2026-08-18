from fastapi import FastAPI, Body, Request
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit
import re


app = FastAPI()

# =========================================================
# ACTION FIREWALL
# =========================================================

ASSIGNED_TENANT = "tenant-lqccake"
ALLOWED_EMAIL_DOMAIN = "notify-dm117fp.example"


class ActionFirewallRequest(BaseModel):
    provenance: str
    humanApproved: bool
    untrustedContent: str | None = None
    action: Dict[str, Any]


def firewall_result(decision: str, reason: str):
    return {
        "decision": decision,
        "reason": reason,
    }


@app.post("/action-firewall")
def action_firewall(req: ActionFirewallRequest):

    # ---------------------------------------------------------
    # 1. Top-level schema
    # ---------------------------------------------------------

    if req.provenance not in ("trusted", "untrusted"):
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(req.humanApproved, bool):
        return firewall_result("block", "INVALID_SCHEMA")

    if req.untrustedContent is not None and not isinstance(
        req.untrustedContent, str
    ):
        return firewall_result("block", "INVALID_SCHEMA")

    if not isinstance(req.action, dict):
        return firewall_result("block", "INVALID_SCHEMA")

    if "tool" not in req.action or "args" not in req.action:
        return firewall_result("block", "INVALID_SCHEMA")

    tool = req.action["tool"]
    args = req.action["args"]

    if not isinstance(tool, str) or not isinstance(args, dict):
        return firewall_result("block", "INVALID_SCHEMA")

    # ---------------------------------------------------------
    # 2. Tool allowlist
    # ---------------------------------------------------------

    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html",
    }

    if tool not in allowed_tools:
        return firewall_result("block", "TOOL_NOT_ALLOWED")

    # ---------------------------------------------------------
    # 3. Tool argument schemas
    # ---------------------------------------------------------

    if tool == "search":

        if (
            set(args.keys()) != {"query"}
            or not isinstance(args.get("query"), str)
            or not (1 <= len(args["query"]) <= 200)
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    elif tool == "lookup_record":

        if (
            set(args.keys()) != {"tenantId", "recordId"}
            or not isinstance(args.get("tenantId"), str)
            or not isinstance(args.get("recordId"), str)
            or args["recordId"] == ""
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    elif tool == "send_email":

        if (
            set(args.keys()) != {"to", "subject", "body"}
            or not isinstance(args.get("to"), str)
            or not isinstance(args.get("subject"), str)
            or not isinstance(args.get("body"), str)
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    elif tool == "render_html":

        if (
            set(args.keys()) != {"html"}
            or not isinstance(args.get("html"), str)
        ):
            return firewall_result("block", "INVALID_SCHEMA")

    # ---------------------------------------------------------
    # 4. Tenant scope
    # ---------------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return firewall_result("block", "TENANT_SCOPE")

    # ---------------------------------------------------------
    # 5. Egress restrictions
    # ---------------------------------------------------------

    if tool == "send_email":

        to = args["to"]

        if "@" not in to:
            return firewall_result("block", "EGRESS_DENIED")

        domain = to.rsplit("@", 1)[1]

        if domain != ALLOWED_EMAIL_DOMAIN:
            return firewall_result("block", "EGRESS_DENIED")

    # ---------------------------------------------------------
    # 6. Human approval
    # ---------------------------------------------------------

    if tool == "send_email":

        if req.humanApproved is not True:
            return firewall_result("block", "APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # 7. HTML safety
    # ---------------------------------------------------------

    if tool == "render_html":

        html_value = args["html"]

        unsafe_patterns = [
            r"<script\b",
            r"</script\s*>",
            r"<iframe\b",
            r"\bon[a-z]+\s*=",
            r"javascript\s*:",
        ]

        for pattern in unsafe_patterns:

            if re.search(
                pattern,
                html_value,
                flags=re.IGNORECASE,
            ):
                return firewall_result("block", "UNSAFE_OUTPUT")

    return firewall_result("allow", "ALLOW")