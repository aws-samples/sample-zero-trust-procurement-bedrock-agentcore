#!/usr/bin/env python3
"""
setup_phase5_gateway.py — create Phase5ApprovalGateway with Cognito JWT auth.

This is the architecturally correct Phase 5 OBO gateway. It uses CUSTOM_JWT
(Cognito) authorization so Cedar can enforce user role via JWT claims:

  principal is AgentCore::OAuthUser
  principal.hasTag("role") && principal.getTag("role") == "admin"

The Cognito ID token (carrying role: admin/operator from the pre-token Lambda)
flows end-to-end as the Bearer credential on every tool call.

What this script does:
  1. Creates Phase5ApprovalGateway (authorizerType=CUSTOM_JWT, Cognito OIDC).
  2. Creates approve_payment + get_approval_status Lambda targets.
  3. Creates Phase5PolicyEngine (Cedar).
  4. Loads Cedar policies from policies/phase5-*.cedar.
  5. Attaches policy engine in ENFORCE mode.
  6. Writes PHASE5_GATEWAY_URL + PHASE5_GATEWAY_ARN to .env.demo.

Run after: make setup-procurement-gateway

Usage:
    python scripts/setup_phase5_gateway.py
"""

import os
import re
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# ── Environment ─────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(REPO_ROOT / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
if not PROFILE_NAME:
    sys.exit("ERROR: AWS_PROFILE is not set.")

REGION = os.environ.get("AWS_REGION", "us-east-1")

# Cognito OIDC config (exported by CDK ApprovalStack → setup_demo.py → .env.demo)
COGNITO_OIDC_DISCOVERY_URL = os.environ.get("COGNITO_OIDC_DISCOVERY_URL", "")
COGNITO_APP_CLIENT_ID = os.environ.get("COGNITO_APP_CLIENT_ID", "")

# Lambda ARNs for approval tools (reuse same Lambdas as ProcurementGateway)
APPROVE_PAYMENT_FN_ARN     = os.environ.get("APPROVE_PAYMENT_FN_ARN", "")
GET_APPROVAL_STATUS_FN_ARN = os.environ.get("GET_APPROVAL_STATUS_FN_ARN", "")

# Gateway service role (same role used for ProcurementGateway — grants Lambda invoke)
GATEWAY_SERVICE_ROLE_ARN = os.environ.get("PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN", "")

GATEWAY_NAME = "Phase5ApprovalGateway"
PE_NAME      = "Phase5PolicyEngine"
POLICIES_DIR = REPO_ROOT / "policies"

# Tool targets: only approval tools on this gateway
TOOL_TARGETS = [
    {
        "target_name": "ProcurementTools-approve-payment",
        "fn_arn":      APPROVE_PAYMENT_FN_ARN,
        "schema": {
            "name": "approve_payment",
            "description": (
                "Evaluate an invoice amount against approval thresholds. "
                "Phase 5: Cedar enforces principal.getTag('role') == 'admin' "
                "via Cognito JWT claim on Phase5ApprovalGateway."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "invoice_id":  {"type": "string"},
                    "vendor_id":   {"type": "string"},
                    "amount":      {"type": "integer", "description": "Invoice amount in dollars"},
                    "vendor_name": {"type": "string"},
                },
                "required": ["invoice_id", "vendor_id", "amount"],
            },
        },
    },
    {
        "target_name": "ProcurementTools-get-approval-status",
        "fn_arn":      GET_APPROVAL_STATUS_FN_ARN,
        "schema": {
            "name": "get_approval_status",
            "description": (
                "Return the current approval status for a given invoice ID. "
                "Phase 5: accessible to admin users via JWT role claim."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "invoice_id": {"type": "string"},
                },
                "required": ["invoice_id"],
            },
        },
    },
]

# Cedar policies: (policy_name, cedar_file, placeholder_key)
POLICIES = [
    ("Phase5ApprovalPermitPolicy", POLICIES_DIR / "phase5-approval-obo.cedar"),
    ("Phase5ApprovalLimitPolicy",  POLICIES_DIR / "phase5-approval-limit.cedar"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def control_client():
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client(
        "bedrock-agentcore-control"
    )


def poll(desc: str, get_fn, ready: str, failed: list,
         interval: int = 10, timeout: int = 300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = get_fn()
        status = result.get("status", "")
        if status == ready:
            return result
        if status in failed:
            sys.exit(
                f"\nERROR: {desc} entered {status}. "
                f"Reasons: {result.get('statusReasons', [])}"
            )
        print(f"  [wait] {desc} status={status} — retrying in {interval}s ...")
        time.sleep(interval)  # nosemgrep: arbitrary-sleep
    sys.exit(f"\nERROR: Timed out waiting for {desc}")


def update_env_demo(updates: dict) -> None:
    path = REPO_ROOT / ".env.demo"
    if not path.exists():
        sys.exit("\nERROR: .env.demo not found. Run 'make setup' first.")
    text = path.read_text()
    for key, value in updates.items():
        pat = re.compile(rf"^#?\s*{re.escape(key)}=.*$", re.MULTILINE)
        line = f"{key}={value}"
        text = pat.sub(line, text) if pat.search(text) else text + f"\n{line}\n"
    path.write_text(text)


def find_by_name(client, list_method: str, name: str, list_key: str, **kw) -> dict | None:
    try:
        resp = getattr(client, list_method)(**kw)
        for item in resp.get(list_key, []):
            if item.get("name") == name:
                return item
    except ClientError:
        pass
    return None


# ── Gateway ───────────────────────────────────────────────────────────────────

def create_or_get_gateway(client) -> tuple[str, str]:
    """Create (or find) Phase5ApprovalGateway with CUSTOM_JWT auth. Returns (gateway_id, gateway_url)."""
    print(f"\n[gateway] checking for '{GATEWAY_NAME}' ...")
    existing = find_by_name(client, "list_gateways", GATEWAY_NAME, "items")
    if existing:
        gw_id = existing["gatewayId"]
        print(f"  found existing: {gw_id}")
        # Fetch full details to get URL
        details = client.get_gateway(gatewayIdentifier=gw_id)
        return gw_id, details.get("gatewayUrl", "")

    print(f"  creating '{GATEWAY_NAME}' (authorizerType=CUSTOM_JWT) ...")
    resp = client.create_gateway(
        name=GATEWAY_NAME,
        description=(
            "Phase 5 OBO gateway — Cognito JWT auth. "
            "Cedar enforces principal.getTag('role') == 'admin' via JWT claim. "
            "Approval tools only (approve_payment, get_approval_status)."
        ),
        roleArn=GATEWAY_SERVICE_ROLE_ARN,
        protocolType="MCP",
        authorizerType="CUSTOM_JWT",
        authorizerConfiguration={
            "customJWTAuthorizer": {
                "discoveryUrl": COGNITO_OIDC_DISCOVERY_URL,
                "allowedAudience": [COGNITO_APP_CLIENT_ID],
            }
        },
        protocolConfiguration={"mcp": {"searchType": "SEMANTIC"}},
    )
    gw_id = resp["gatewayId"]
    print(f"  created: {gw_id}")

    result = poll(
        f"Gateway '{GATEWAY_NAME}'",
        lambda: client.get_gateway(gatewayIdentifier=gw_id),
        ready="READY", failed=["CREATE_FAILED", "UPDATE_FAILED"],
    )
    gw_url = result.get("gatewayUrl", "")
    print(f"  READY: {gw_url}")
    return gw_id, gw_url


# ── Targets ───────────────────────────────────────────────────────────────────

def create_targets(client, gateway_id: str) -> None:
    """Create approval Lambda targets on Phase5ApprovalGateway."""
    print(f"\n[targets] creating {len(TOOL_TARGETS)} Lambda targets ...")
    for entry in TOOL_TARGETS:
        target_name = entry["target_name"]
        fn_arn = entry["fn_arn"]
        schema = entry["schema"]

        existing = find_by_name(
            client, "list_gateway_targets", target_name, "items",
            gatewayIdentifier=gateway_id,
        )
        if existing:
            print(f"  [target] found existing: {target_name}")
            continue

        if not fn_arn:
            print(f"  [target] SKIP: {target_name} (missing fn_arn)")
            continue

        print(f"  [target] creating '{target_name}' → {fn_arn.split(':')[-1]} ...")
        resp = client.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=target_name,
            description=schema["description"][:200],
            targetConfiguration={
                "mcp": {
                    "lambda": {
                        "lambdaArn": fn_arn,
                        "toolSchema": {"inlinePayload": [schema]},
                    }
                }
            },
            credentialProviderConfigurations=[
                {"credentialProviderType": "GATEWAY_IAM_ROLE"}
            ],
        )
        poll(
            f"Target '{target_name}'",
            lambda tid=resp["targetId"]: client.get_gateway_target(
                gatewayIdentifier=gateway_id, targetId=tid
            ),
            ready="READY",
            failed=["SYNCHRONIZE_UNSUCCESSFUL", "DELETE_UNSUCCESSFUL"],
        )
        print(f"  [target] READY: {target_name}")


# ── Policy Engine ─────────────────────────────────────────────────────────────

def create_or_get_policy_engine(client) -> str:
    print(f"\n[policy-engine] checking for '{PE_NAME}' ...")
    existing = find_by_name(client, "list_policy_engines", PE_NAME, "policyEngines")
    if existing:
        pe_id = existing["policyEngineId"]
        print(f"  found existing: {pe_id}")
        return pe_id

    print(f"  creating '{PE_NAME}' ...")
    resp = client.create_policy_engine(
        name=PE_NAME,
        description=(
            "Cedar policies for Phase5ApprovalGateway (JWT auth). "
            "Enforces user role from Cognito JWT claim (principal.getTag('role')). "
            "Permit: admin can approve_payment + get_approval_status. "
            "Forbid: approve_payment when amount >= 500."
        ),
    )
    pe_id = resp["policyEngineId"]
    print(f"  created: {pe_id}")
    poll(
        f"PolicyEngine '{PE_NAME}'",
        lambda: client.get_policy_engine(policyEngineId=pe_id),
        ready="ACTIVE", failed=["CREATE_FAILED"],
    )
    print(f"  ACTIVE: {pe_id}")
    return pe_id


def create_or_get_policy(client, pe_id: str, name: str, cedar_file: Path, gateway_arn: str) -> str:
    existing = find_by_name(
        client, "list_policies", name, "policies", policyEngineId=pe_id
    )
    if existing:
        print(f"  [policy] found existing: {name}")
        return existing["policyId"]

    cedar_statement = cedar_file.read_text().replace("{{PHASE5_GATEWAY_ARN}}", gateway_arn)

    print(f"  [policy] creating '{name}' from {cedar_file.name} ...")
    resp = client.create_policy(
        policyEngineId=pe_id,
        name=name,
        description=f"Phase 5 OBO Cedar policy — {cedar_file.stem}",
        definition={"cedar": {"statement": cedar_statement}},
        validationMode="IGNORE_ALL_FINDINGS",
    )
    p_id = resp["policyId"]
    poll(
        f"Policy '{name}'",
        lambda: client.get_policy(policyEngineId=pe_id, policyId=p_id),
        ready="ACTIVE", failed=["CREATE_FAILED"],
    )
    print(f"  [policy] ACTIVE: {name}")
    return p_id


def attach_policy_engine(client, gateway_id: str, pe_id: str) -> None:
    mode = "ENFORCE"
    print(f"\n[gateway] attaching Phase5PolicyEngine (mode={mode}) ...")
    current = client.get_gateway(gatewayIdentifier=gateway_id)
    if current.get("policyEngineConfiguration", {}).get("arn", "").endswith(pe_id):
        print(f"  policy engine already attached.")
        return

    pe_info = client.get_policy_engine(policyEngineId=pe_id)
    pe_arn = pe_info["policyEngineArn"]

    update_kwargs = {
        "gatewayIdentifier": gateway_id,
        "name": current["name"],
        "roleArn": current["roleArn"],
        "protocolType": current["protocolType"],
        "authorizerType": current["authorizerType"],
        "policyEngineConfiguration": {
            "arn": pe_arn,
            "mode": mode,
        },
    }
    for field in ("description", "protocolConfiguration", "authorizerConfiguration"):
        if current.get(field):
            update_kwargs[field] = current[field]

    client.update_gateway(**update_kwargs)
    poll(
        "Phase5ApprovalGateway (policy engine attach)",
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        ready="READY", failed=["UPDATE_FAILED"],
    )
    print(f"  policy engine attached in {mode} mode.")


# ── Validation ────────────────────────────────────────────────────────────────

def validate_env() -> None:
    missing = []
    if not COGNITO_OIDC_DISCOVERY_URL:
        missing.append("COGNITO_OIDC_DISCOVERY_URL")
    if not COGNITO_APP_CLIENT_ID:
        missing.append("COGNITO_APP_CLIENT_ID")
    if not APPROVE_PAYMENT_FN_ARN:
        missing.append("APPROVE_PAYMENT_FN_ARN")
    if not GET_APPROVAL_STATUS_FN_ARN:
        missing.append("GET_APPROVAL_STATUS_FN_ARN")
    if not GATEWAY_SERVICE_ROLE_ARN:
        missing.append("PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN")
    if missing:
        sys.exit(
            "\nERROR: Missing in .env.demo:\n"
            + "\n".join(f"  {k}" for k in missing)
            + "\n\nRun 'make deploy && make setup' first."
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[setup-phase5-gateway] profile={PROFILE_NAME}  region={REGION}")
    validate_env()

    client = control_client()

    # 1. Gateway (CUSTOM_JWT — Cognito ID token as Bearer)
    gateway_id, gateway_url = create_or_get_gateway(client)

    # 2. Lambda targets (approve_payment + get_approval_status)
    create_targets(client, gateway_id)

    # 3. Policy engine
    pe_id = create_or_get_policy_engine(client)

    # 4. Cedar policies (substitute gateway ARN placeholder)
    gw_state = client.get_gateway(gatewayIdentifier=gateway_id)
    gateway_arn = gw_state["gatewayArn"]
    for policy_name, cedar_file in POLICIES:
        create_or_get_policy(client, pe_id, policy_name, cedar_file, gateway_arn)

    # 5. Attach policy engine in ENFORCE mode
    attach_policy_engine(client, gateway_id, pe_id)

    # 6. Persist outputs
    update_env_demo({
        "PHASE5_GATEWAY_ID":  gateway_id,
        "PHASE5_GATEWAY_URL": gateway_url,
        "PHASE5_GATEWAY_ARN": gateway_arn,
        "PHASE5_POLICY_ENGINE_ID": pe_id,
    })

    print(f"""
[setup-phase5-gateway] done.

  Gateway             : {gateway_id}
  Gateway URL         : {gateway_url}
  Auth                : CUSTOM_JWT (Cognito ID token as Bearer)
  Policy Engine       : {pe_id} (ENFORCE)
  Cedar policies      : Phase5ApprovalPermitPolicy (role=admin) + Phase5ApprovalLimitPolicy (amount<500)

  OBO story:
    Cognito ID token (role: admin/operator) flows as Bearer to Phase5ApprovalGateway.
    Cedar evaluates principal.getTag("role") — only admin is permitted.
    PHASE5_GATEWAY_URL written to .env.demo.

  Next steps:
    make configure-agents   — push PHASE5_GATEWAY_URL env var to ApprovalAgent runtime
    make ui                 — open Streamlit demo (Phase 5 tab)
""")


if __name__ == "__main__":
    main()
