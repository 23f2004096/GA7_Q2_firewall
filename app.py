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


# =========================================================
# HTML SAFETY
# =========================================================

def unsafe_html(html: str) -> bool:
    """
    Block:
      - <script>
      - </script>
      - <iframe>
      - inline event handlers such as onclick=, onerror=, onload=
      - javascript: URLs

    IMPORTANT:
      data: URIs are allowed.
    """

    unsafe_patterns = [
        # <script>
        r"<\s*script\b",

        # </script>
        r"</\s*script\s*>",

        # <iframe>
        r"<\s*iframe\b",

        # onclick=, onload=, onerror=, onmouseover=, etc.
        r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",

        # javascript:
        r"javascript\s*:",
    ]

    for pattern in unsafe_patterns:
        if re.search(
            pattern,
            html,
            flags=re.IGNORECASE
        ):
            return True

    return False


# =========================================================
# EMAIL DOMAIN VALIDATION
# =========================================================

def valid_email_for_domain(email: str) -> bool:
    """
    Recipient must have exactly the assigned email domain.

    Allowed:
        person@notify-dm117fp.example

    Block:
        person@gmail.com
        person@evilnotify-dm117fp.example
        person@notify-dm117fp.example.evil.com
        person@@notify-dm117fp.example
        @notify-dm117fp.example

    data: is irrelevant here because this is an email
    recipient field, not HTML.
    """

    pattern = (
        r"^[^@\s]+@"
        + re.escape(ALLOWED_EMAIL_DOMAIN)
        + r"$"
    )

    return re.fullmatch(
        pattern,
        email
    ) is not None


# =========================================================
# HEALTH / ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "status": "ok"
    }


# =========================================================
# ACTION FIREWALL
# =========================================================

@app.post("/action-firewall")
async def action_firewall(request: Request):

    # =====================================================
    # 1. TOP-LEVEL SCHEMA
    # =====================================================

    # Parse the raw JSON ourselves.
    # This ensures malformed requests return our required
    # JSON response instead of FastAPI's default 422.

    try:
        raw_body = await request.body()
        payload = json.loads(raw_body)

    except Exception:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Top-level must be a JSON object.
    if type(payload) is not dict:
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

    # Missing required keys.
    if not required_keys.issubset(
        payload.keys()
    ):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # Extra top-level keys.
    if not set(payload.keys()).issubset(
        allowed_top_level_keys
    ):
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # -----------------------------------------------------
    # provenance
    # -----------------------------------------------------

    provenance = payload["provenance"]

    if type(provenance) is not str:
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

    # -----------------------------------------------------
    # humanApproved
    # -----------------------------------------------------

    human_approved = payload["humanApproved"]

    if type(human_approved) is not bool:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    # -----------------------------------------------------
    # untrustedContent
    # -----------------------------------------------------

    if "untrustedContent" in payload:

        if type(
            payload["untrustedContent"]
        ) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

    # IMPORTANT:
    #
    # We DO NOT inspect untrustedContent for suspicious
    # phrases.
    #
    # Prompt injection inside untrustedContent does not
    # change the verdict by itself.
    #
    # Only the actual action is evaluated.


    # -----------------------------------------------------
    # action
    # -----------------------------------------------------

    action = payload["action"]

    if type(action) is not dict:
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

    if type(tool) is not str:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )

    if type(args) is not dict:
        return firewall_result(
            "block",
            "INVALID_SCHEMA"
        )


    # =====================================================
    # 2. TOOL ALLOWLIST
    # =====================================================

    if tool not in ALLOWED_TOOLS:

        return firewall_result(
            "block",
            "TOOL_NOT_ALLOWED"
        )


    # =====================================================
    # 3. TOOL ARGUMENT SCHEMAS
    # =====================================================

    # =====================================================
    # SEARCH
    # =====================================================

    if tool == "search":

        # EXACTLY:
        #
        # {"query": "..."}
        #

        if not exact_keys(
            args,
            {"query"}
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        query = args["query"]

        if type(query) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        # 1-200 characters inclusive.
        if not (
            1 <= len(query) <= 200
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =====================================================
    # LOOKUP RECORD
    # =====================================================

    elif tool == "lookup_record":

        # EXACTLY:
        #
        # {
        #     "tenantId": "...",
        #     "recordId": "..."
        # }
        #

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

        if type(tenant_id) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        if type(record_id) is not str:
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

        # EXACTLY:
        #
        # {
        #     "to": "...",
        #     "subject": "...",
        #     "body": "..."
        # }
        #

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

        if type(to) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        if type(subject) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        if type(body) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =====================================================
    # RENDER HTML
    # =====================================================

    elif tool == "render_html":

        # EXACTLY:
        #
        # {"html": "..."}
        #

        if not exact_keys(
            args,
            {"html"}
        ):
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )

        html = args["html"]

        if type(html) is not str:
            return firewall_result(
                "block",
                "INVALID_SCHEMA"
            )


    # =====================================================
    # 4. TENANT SCOPE
    # =====================================================

    if tool == "lookup_record":

        tenant_id = args["tenantId"]

        # The tenant must match EXACTLY.
        #
        # No prefix matching.
        # No substring matching.
        # No case-insensitive matching.
        # No wildcard.
        #
        # Example:
        #
        # tenant-lqccake       -> ALLOW
        # tenant-lqccake-x     -> BLOCK
        # TENANT-LQCCAKE       -> BLOCK
        # attacker             -> BLOCK

        if tenant_id != ASSIGNED_TENANT:

            return firewall_result(
                "block",
                "TENANT_SCOPE"
            )


    # =====================================================
    # 5. EMAIL DOMAIN / EGRESS
    # =====================================================

    if tool == "send_email":

        to = args["to"]

        # The recipient domain must match EXACTLY.
        #
        # This check happens BEFORE human approval.
        #
        # Therefore:
        #
        # wrong domain + approved
        #       -> EGRESS_DENIED
        #
        # wrong domain + not approved
        #       -> EGRESS_DENIED
        #
        # correct domain + not approved
        #       -> APPROVAL_REQUIRED
        #
        # correct domain + approved
        #       -> continue

        if not valid_email_for_domain(to):

            return firewall_result(
                "block",
                "EGRESS_DENIED"
            )


    # =====================================================
    # 6. HUMAN APPROVAL
    # =====================================================

    if tool == "send_email":

        # Email is the side-effecting action.
        #
        # It requires explicit:
        #
        # "humanApproved": true
        #

        if human_approved is not True:

            return firewall_result(
                "block",
                "APPROVAL_REQUIRED"
            )


    # =====================================================
    # 7. HTML SAFETY
    # =====================================================

    if tool == "render_html":

        html = args["html"]

        if unsafe_html(html):

            return firewall_result(
                "block",
                "UNSAFE_OUTPUT"
            )


    # =====================================================
    # EVERYTHING PASSED
    # =====================================================

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

    if not isinstance(
        req.environment,
        str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        req.state,
        dict
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        req.providerVersion,
        str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        req.destroyApproved,
        bool
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        req.resource,
        dict
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if (
        not isinstance(
            req.state.get("backend"),
            str
        )
        or not isinstance(
            req.state.get("locked"),
            bool
        )
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    resource = req.resource

    if not isinstance(
        resource.get("address"),
        str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        resource.get("type"),
        str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        resource.get("action"),
        str
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        resource.get("labels"),
        dict
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if (
        resource.get("secret") is not None
        and not isinstance(
            resource.get("secret"),
            str
        )
    ):
        return {
            "decision": "reject",
            "reason": "INVALID_PLAN",
        }

    if not isinstance(
        resource.get("forceDestroy"),
        bool
    ):
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
        req.state.get("backend")
        not in ALLOWED_BACKENDS
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
        and resource.get("type")
        in STATEFUL_DELETE_TYPES
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