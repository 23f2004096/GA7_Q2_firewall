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
    """
    Block:
      - <script>
      - </script>
      - <iframe>
      - inline event handlers such as onclick=, onerror=, onload=
      - javascript: URLs

    IMPORTANT:
      data: URIs are intentionally allowed.
    """

    unsafe_patterns = [
        # Script tags
        r"<\s*script\b",

        # Closing script tags
        r"</\s*script\s*>",

        # Iframe tags
        r"<\s*iframe\b",

        # Inline event handlers:
        # onclick=
        # onload=
        # onerror=
        # onmouseover=
        # onanimationstart=
        # etc.
        r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",

        # javascript: URLs
        r"javascript\s*:",
    ]

    for pattern in unsafe_patterns:
        if re.search(pattern, html, flags=re.IGNORECASE):
            return True

    return False


def valid_email_for_domain(email: str) -> bool:
    """
    Recipient must have exactly the assigned domain.

    Allowed:
        person@notify-dm117fp.example

    Block:
        person@gmail.com
        person@evilnotify-dm117fp.example
        person@notify-dm117fp.example.evil.com
        person@@notify-dm117fp.example
        @notify-dm117fp.example

    """

    pattern = (
        r"^[^@\s]+@"
        + re.escape(ALLOWED_EMAIL_DOMAIN)
        + r"$"
    )

    return re.fullmatch(pattern, email) is not None


@app.get("/")
def root():
    return {
        "status": "ok"
    }


# =========================================================
# ACTION FIREWALL ENDPOINT
# =========================================================

@app.post("/action-firewall")
async def action_firewall(request: Request):

    # -----------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # -----------------------------------------------------

    # Read raw request body ourselves.
    # This prevents FastAPI/Pydantic from returning
    # its own 422 response for malformed JSON.
    try:
        raw_body = await request.body()
        payload = json.loads(raw_body)
    except Exception:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Top-level must be a JSON object.
    if not isinstance(payload, dict):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    required_keys = {
        "provenance",
        "humanApproved",
        "action",
    }

    allowed_top_level_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    # Missing required fields
    if not required_keys.issubset(payload.keys()):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Extra top-level fields
    if not set(payload.keys()).issubset(
        allowed_top_level_keys
    ):
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

    # Optional untrustedContent
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
        {
            "tool",
            "args",
        }
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


    # -----------------------------------------------------
    # 2. TOOL ALLOWLIST
    # -----------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return firewall_result(
            "block",
            "TOOL_NOT_ALLOWED"
        )


    # -----------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # -----------------------------------------------------

    # =====================================================
    # SEARCH
    # =====================================================

    if tool == "search":

        # EXACT:
        # {"query": "..."}
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

        # Query must contain 1-200 characters.
        if not (1 <= len(query) <= 200):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =====================================================
    # LOOKUP RECORD
    # =====================================================

    elif tool == "lookup_record":

        # EXACT:
        # {"tenantId": "...", "recordId": "..."}
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

        # recordId must be non-empty.
        if record_id == "":
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =====================================================
    # SEND EMAIL
    # =====================================================

    elif tool == "send_email":

        # EXACT:
        # {"to": "...", "subject": "...", "body": "..."}
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


    # =====================================================
    # RENDER HTML
    # =====================================================

    elif tool == "render_html":

        # EXACT:
        # {"html": "..."}
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


    # -----------------------------------------------------
    # 4. TENANT SCOPE
    # -----------------------------------------------------

    if tool == "lookup_record":

        if args["tenantId"] != ASSIGNED_TENANT:
            return firewall_result(
                "block",
                "TENANT_SCOPE"
            )


    # -----------------------------------------------------
    # 5. EMAIL DOMAIN
    # -----------------------------------------------------

    if tool == "send_email":

        if not valid_email_for_domain(
            args["to"]
        ):
            return firewall_result(
                "block",
                "EGRESS_DENIED"
            )


    # -----------------------------------------------------
    # 6. HUMAN APPROVAL
    # -----------------------------------------------------

    if tool == "send_email":

        if human_approved is not True:
            return firewall_result(
                "block",
                "APPROVAL_REQUIRED"
            )


    # -----------------------------------------------------
    # 7. HTML SAFETY
    # -----------------------------------------------------

    if tool == "render_html":

        if unsafe_html(args["html"]):
            return firewall_result(
                "block",
                "UNSAFE_OUTPUT"
            )


    # -----------------------------------------------------
    # ALL CHECKS PASSED
    # -----------------------------------------------------

    return firewall_result(
        "allow",
        "ALLOW"
    )


# =========================================================
# TERRAFORM PLAN
# =========================================================

class TerraformPlanRequest(BaseModel):
    environment: str
    state: Dict[str, Any]
    providerVersion: str
    destroyApproved: bool
    resource: Dict[str, Any]


REQUIRED_LABELS = {
    "owner": "student-mitnf",
    "environment": "production",
    "cost_center": "cc-5zx9",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

STATEFUL_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


@app.post("/terraform/plan")
def terraform_plan(req: TerraformPlanRequest):

    if not isinstance(req.environment, str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(req.state, dict):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(req.providerVersion, str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(req.destroyApproved, bool):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(req.resource, dict):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if (
        not isinstance(req.state.get("backend"), str)
        or not isinstance(req.state.get("locked"), bool)
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    resource = req.resource

    if not isinstance(resource.get("address"), str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(resource.get("type"), str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(resource.get("action"), str):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(resource.get("labels"), dict):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if resource.get("secret") is not None and not isinstance(
        resource.get("secret"), str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(resource.get("forceDestroy"), bool):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if resource.get("action") not in {
        "create",
        "update",
        "delete",
    }:
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if req.environment != "prod-csr1mn":
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH",
        }

    if (
        req.state.get("backend") not in ALLOWED_BACKENDS
        or req.state.get("locked") is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE",
        }

    provider = req.providerVersion.strip()

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider not in allowed_provider_versions:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER",
        }

    labels = resource.get("labels")

    for key, expected_value in REQUIRED_LABELS.items():

        if labels.get(key) != expected_value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS",
            }

    secret = resource.get("secret")

    if secret is not None:

        if (
            not isinstance(secret, str)
            or not secret.startswith("secret://")
            or len(secret) <= len("secret://")
        ):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET",
            }

    if (
        resource.get("action") == "delete"
        and resource.get("type") in STATEFUL_DELETE_TYPES
        and req.destroyApproved is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED",
        }

    if (
        resource.get("type") == "storage_bucket"
        and resource.get("forceDestroy") is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY",
        }

    return {
        "decision": "approve",
        "reason": "APPROVE",
    }