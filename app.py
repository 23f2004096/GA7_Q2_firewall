# =========================================================
# ACTION FIREWALL
# =========================================================

from fastapi import Request
import json
import re


ASSIGNED_TENANT = "tenant-lqccake"
ALLOWED_EMAIL_DOMAIN = "notify-dm117fp.example"

ALLOWED_TENANT = "tenant-a7h1iwz"
ALLOWED_EMAIL_DOMAIN = "notify-msjfzdz.example"

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
        # <script ...>
        r"<\s*script\b",

        # </script>
        r"</\s*script\s*>",

        # <iframe ...>
        r"<\s*iframe\b",

        # onclick=, onload=, onerror=, onmouseover=, etc.
        r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",

        # javascript:
        r"javascript\s*:",
    ]

    for pattern in unsafe_patterns:
        if re.search(pattern, html, flags=re.IGNORECASE):
            return True

    return False


def valid_email_for_domain(email: str) -> bool:

    # Must be:
    # something@notify-dm117fp.example
    #
    # No second @
    # No whitespace
    # Non-empty local part

    pattern = (
        r"^[^@\s]+@"
        + re.escape(ALLOWED_EMAIL_DOMAIN)
        + r"$"
    )

    return re.fullmatch(pattern, email) is not None


# =========================================================
# ACTION FIREWALL ENDPOINT
# =========================================================

@app.post("/action-firewall")
async def action_firewall(request: Request):

    # ---------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # ---------------------------------------------------------

    try:
        raw_body = await request.body()

        payload = json.loads(raw_body)

    except Exception:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Top-level must be an object
    if not isinstance(payload, dict):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Exactly these top-level fields are permitted.
    #
    # untrustedContent is optional.
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

    # Missing required field
    if not required_keys.issubset(payload.keys()):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Unexpected top-level field
    if not set(payload.keys()).issubset(allowed_keys):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # provenance
    provenance = payload["provenance"]

    if not isinstance(provenance, str):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    if provenance not in {
        "trusted",
        "untrusted",
    }:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # humanApproved
    human_approved = payload["humanApproved"]

    if not isinstance(human_approved, bool):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # untrustedContent is optional
    if "untrustedContent" in payload:

        if not isinstance(
            payload["untrustedContent"],
            str
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

    # action
    action = payload["action"]

    if not isinstance(action, dict):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Action must contain EXACTLY:
    #
    # {
    #     "tool": "...",
    #     "args": {...}
    # }

    if not exact_keys(
        action,
        {"tool", "args"}
    ):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    tool = action["tool"]
    args = action["args"]

    if not isinstance(tool, str):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    if not isinstance(args, dict):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )


    # ---------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # ---------------------------------------------------------

    if tool not in ALLOWED_TOOLS:

        return firewall_result(
            "block",
            "TOOL_NOT_ALLOWED"
        )


    # ---------------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMAS
    # ---------------------------------------------------------

    # =========================================================
    # SEARCH
    # =========================================================

    if tool == "search":

        # EXACTLY {"query": "..."}
        if not exact_keys(
            args,
            {"query"}
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        query = args["query"]

        if not isinstance(query, str):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        # 1-200 characters
        if not (1 <= len(query) <= 200):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =========================================================
    # LOOKUP RECORD
    # =========================================================

    elif tool == "lookup_record":

        # EXACTLY:
        #
        # {
        #     "tenantId": "...",
        #     "recordId": "..."
        # }

        if not exact_keys(
            args,
            {
                "tenantId",
                "recordId",
            }
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        tenant_id = args["tenantId"]
        record_id = args["recordId"]

        if not isinstance(
            tenant_id,
            str
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        if not isinstance(
            record_id,
            str
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        # recordId must be non-empty
        if record_id == "":
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =========================================================
    # SEND EMAIL
    # =========================================================

    elif tool == "send_email":

        # EXACTLY:
        #
        # {
        #     "to": "...",
        #     "subject": "...",
        #     "body": "..."
        # }

        if not exact_keys(
            args,
            {
                "to",
                "subject",
                "body",
            }
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        to = args["to"]
        subject = args["subject"]
        body = args["body"]

        if not isinstance(to, str):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        if not isinstance(subject, str):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        if not isinstance(body, str):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =========================================================
    # RENDER HTML
    # =========================================================

    elif tool == "render_html":

        # EXACTLY:
        #
        # {
        #     "html": "..."
        # }

        if not exact_keys(
            args,
            {"html"}
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        html = args["html"]

        if not isinstance(html, str):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # ---------------------------------------------------------
    # 4. TENANT SCOPE
    # ---------------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:

            return firewall_result(
                "block",
                "TENANT_SCOPE"
            )


    # ---------------------------------------------------------
    # 5. EGRESS RESTRICTION
    # ---------------------------------------------------------

    if tool == "send_email":

        to = args["to"]

        if not valid_email_for_domain(to):

            return firewall_result(
                "block",
                "EGRESS_DENIED"
            )


    # ---------------------------------------------------------
    # 6. HUMAN APPROVAL
    # ---------------------------------------------------------

    if tool == "send_email":

        if human_approved is not True:

            return firewall_result(
                "block",
                "APPROVAL_REQUIRED"
            )


    # ---------------------------------------------------------
    # 7. HTML SAFETY
    # ---------------------------------------------------------

    if tool == "render_html":

        if unsafe_html(args["html"]):

            return firewall_result(
                "block",
                "UNSAFE_OUTPUT"
            )


    # ---------------------------------------------------------
    # ALL CHECKS PASSED
    # ---------------------------------------------------------

    return firewall_result(
        "allow",
        "ALLOW"
    )