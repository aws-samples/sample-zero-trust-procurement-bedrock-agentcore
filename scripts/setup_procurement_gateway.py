#!/usr/bin/env python3
"""
setup_procurement_gateway.py — create the single ProcurementGateway.

Creates a single authoritative agent-to-tool gateway that:

  1. Registers all six Lambda tool functions as MCP targets.
  2. Uses AWS_IAM auth — agents authenticate via SigV4 (execution role).
  3. Attaches a Cedar policy engine (LOG_ONLY to start, ENFORCE via toggle_policy_mode.py).

Zero Trust story — Gateway as Agent-to-Tool Authorization Layer:
  BEFORE (no gateway): agents call Lambda tools directly — any agent can call
    any tool; no identity check; no per-tool constraint; no audit trail.

  AFTER  (this script): agents authenticate via SigV4 with their IAM execution
    role. Cedar evaluates principal.id (the role ARN) on every tool call:
      OrchestratorAgent (orchestrator-execution-role) → read_invoice, show_identity
      VendorAgent       (vendor-execution-role)       → validate_vendor, get_vendor_terms
      ApprovalAgent     (approval-execution-role)     → approve_payment (forbid: amount>=500),
                                                        get_approval_status

This is NOT a human-to-agent entry layer.  Human callers invoke Agent Runtimes
directly via SigV4 InvokeAgentRuntime + Runtime resource policy (Phase 1).

What this script does:
  1. Creates ProcurementGateway (authorizerType=AWS_IAM).
  2. Creates six Lambda targets under the single gateway.
  3. Creates ProcurementPolicyEngine (Cedar).
  4. Loads Cedar policies from policies/.
  5. Attaches policy engine in LOG_ONLY mode.
  6. Creates workload identities for all three agents if not present.
  7. Writes gateway ID/URL and policy engine ID to .env.demo.

Run after: make deploy && make setup && make configure-agents

Usage:
    python scripts/setup_procurement_gateway.py

boto3 service names:
  Control plane: bedrock-agentcore-control
  Data plane:    bedrock-agentcore
"""

import json
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

# Lambda ARNs — populated by CDK stacks (setup_demo.py writes them to .env.demo)
READ_INVOICE_FN_ARN        = os.environ.get("READ_INVOICE_FN_ARN", "")
SHOW_IDENTITY_FN_ARN       = os.environ.get("SHOW_IDENTITY_FN_ARN", "")
VALIDATE_VENDOR_FN_ARN     = os.environ.get("VALIDATE_VENDOR_FN_ARN", "")
GET_VENDOR_TERMS_FN_ARN    = os.environ.get("GET_VENDOR_TERMS_FN_ARN", "")
APPROVE_PAYMENT_FN_ARN     = os.environ.get("APPROVE_PAYMENT_FN_ARN", "")
GET_APPROVAL_STATUS_FN_ARN = os.environ.get("GET_APPROVAL_STATUS_FN_ARN", "")

# Single gateway service role (covers all tool Lambdas via wildcard)
PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN = os.environ.get(
    "PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN", ""
)


GATEWAY_NAME      = "ProcurementGateway"
PE_NAME           = "ProcurementPolicyEngine"
POLICIES_DIR      = REPO_ROOT / "policies"


# ── Tool schemas ──────────────────────────────────────────────────────────────
# Each target maps one Lambda to one tool.  Cedar action names use the pattern:
#   TargetName___tool_name  (triple underscores)

TOOL_TARGETS = [
    {
        "target_name": "ProcurementTools-read-invoice",
        "fn_arn_key":  "READ_INVOICE_FN_ARN",
        "schema": {
            "name": "read_invoice",
            "description": (
                "Read a procurement invoice by ID from the invoices table. "
                "Returns vendor, amount, and status. "
                "ZT: only OrchestratorAgent workload identity may call this tool."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "invoice_id": {
                        "type": "string",
                        "description": "Invoice identifier (e.g. INV-001, INV-002)",
                    }
                },
                "required": ["invoice_id"],
            },
        },
    },
    {
        "target_name": "ProcurementTools-show-identity",
        "fn_arn_key":  "SHOW_IDENTITY_FN_ARN",
        "schema": {
            "name": "show_identity",
            "description": (
                "Return the IAM execution identity of the Lambda function via STS GetCallerIdentity. "
                "Used in Phase 2 to confirm the orchestrator's execution role after "
                "AmazonDynamoDBFullAccess is detached. "
                "ZT: only OrchestratorAgent workload identity may call this tool."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "target_name": "ProcurementTools-validate-vendor",
        "fn_arn_key":  "VALIDATE_VENDOR_FN_ARN",
        "schema": {
            "name": "validate_vendor",
            "description": (
                "Check whether a vendor ID and name are on the approved vendor list. "
                "Returns approval status, risk level, and payment terms. "
                "ZT: only VendorAgent workload identity may call this tool."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vendor_id":   {"type": "string", "description": "Vendor identifier"},
                    "vendor_name": {"type": "string", "description": "Vendor name from invoice"},
                },
                "required": ["vendor_id", "vendor_name"],
            },
        },
    },
    {
        "target_name": "ProcurementTools-get-vendor-terms",
        "fn_arn_key":  "GET_VENDOR_TERMS_FN_ARN",
        "schema": {
            "name": "get_vendor_terms",
            "description": (
                "Retrieve payment terms and credit limit for an approved vendor. "
                "ZT: only VendorAgent workload identity may call this tool."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vendor_id": {"type": "string", "description": "Vendor identifier"},
                },
                "required": ["vendor_id"],
            },
        },
    },
    {
        "target_name": "ProcurementTools-approve-payment",
        "fn_arn_key":  "APPROVE_PAYMENT_FN_ARN",
        "schema": {
            "name": "approve_payment",
            "description": (
                "Evaluate an invoice amount against approval thresholds. "
                "Auto-approves amounts <= $500; escalates higher amounts. "
                "ZT: Cedar permits ApprovalAgent identity; forbids amount >= 500."
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
        "fn_arn_key":  "GET_APPROVAL_STATUS_FN_ARN",
        "schema": {
            "name": "get_approval_status",
            "description": (
                "Return the current approval status for a given invoice ID. "
                "ZT: only ApprovalAgent workload identity may call this tool."
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

# Cedar policies: (policy_name, cedar_file)
POLICIES = [
    ("ProcurementOrchestratorPolicy", POLICIES_DIR / "procurement-orchestrator.cedar"),
    ("ProcurementVendorPolicy",       POLICIES_DIR / "procurement-vendor.cedar"),
    ("ProcurementApprovalPolicy",      POLICIES_DIR / "procurement-approval.cedar"),
    ("ProcurementApprovalLimitPolicy", POLICIES_DIR / "procurement-approval-limit.cedar"),
]

# Workload identities: (name, role_tag)
WORKLOAD_IDENTITIES = [
    ("OrchestratorAgent", "orchestrator"),
    ("VendorAgent",       "vendor-agent"),
    ("ApprovalAgent",     "approval-agent"),
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


# ── Workload identities ───────────────────────────────────────────────────────

def ensure_workload_identities(client) -> None:
    """Create workload identities for all three agents if not present. Always ensures tags are set."""
    print("\n[workload-identities] ensuring workload identities for all agents ...")
    for name, role in WORKLOAD_IDENTITIES:
        try:
            result = client.get_workload_identity(name=name)
            print(f"  found existing: {name} ({result['workloadIdentityArn']})")
            # Ensure tags are set (idempotent)
            client.tag_resource(
                resourceArn=result["workloadIdentityArn"],
                tags={"demo": "zt-agentcore", "role": role},
            )
            print(f"    tagged: role={role}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            print(f"  creating workload identity: {name} (role={role}) ...")
            result = client.create_workload_identity(
                name=name,
                tags={"demo": "zt-agentcore", "role": role},
            )
            print(f"  created: {result['workloadIdentityArn']}")


# ── Gateway ───────────────────────────────────────────────────────────────────

def create_or_get_gateway(client) -> tuple[str, str]:
    """Create (or find) ProcurementGateway with AWS_IAM auth. Returns (gateway_id, gateway_url)."""
    print(f"\n[gateway] checking for '{GATEWAY_NAME}' ...")
    existing = find_by_name(client, "list_gateways", GATEWAY_NAME, "items")
    if existing:
        gw_id = existing["gatewayId"]
        print(f"  found existing: {gw_id}")
        details = client.get_gateway(gatewayIdentifier=gw_id)
        return gw_id, details.get("gatewayUrl", "")

    create_kwargs = dict(
        name=GATEWAY_NAME,
        description=(
            "ZT demo: single agent-to-tool gateway. "
            "Agents authenticate via SigV4 (IAM execution role). "
            "Cedar policies enforce which agent can call which tool."
        ),
        roleArn=PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN,
        protocolType="MCP",
        authorizerType="AWS_IAM",
        protocolConfiguration={"mcp": {"searchType": "SEMANTIC"}},
    )
    print(f"  creating '{GATEWAY_NAME}' (authorizerType=AWS_IAM) ...")

    resp = client.create_gateway(**create_kwargs)
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

def create_targets(client, gateway_id: str, fn_arns: dict) -> None:
    """Create one Lambda target per tool."""
    print(f"\n[targets] creating {len(TOOL_TARGETS)} Lambda targets ...")
    for entry in TOOL_TARGETS:
        target_name = entry["target_name"]
        fn_arn = fn_arns.get(entry["fn_arn_key"], "")
        schema = entry["schema"]

        existing = find_by_name(
            client, "list_gateway_targets", target_name, "items",
            gatewayIdentifier=gateway_id,
        )
        if existing:
            print(f"  [target] found existing: {target_name}")
            continue

        if not fn_arn:
            print(f"  [target] SKIP: {target_name} (missing env {entry['fn_arn_key']})")
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
            "Cedar policies for ProcurementGateway. "
            "Enforces agent workload identity → tool authorization. "
            "Orchestrator: read_invoice. Vendor: validate/terms. "
            "Approval: approve_payment (forbid amount>=500) + get_status."
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
        p_id = existing["policyId"]
        print(f"  [policy] found existing: {name}")
        return p_id

    # Substitute gateway ARN placeholder in Cedar statement
    cedar_statement = cedar_file.read_text().replace("{{GATEWAY_ARN}}", gateway_arn)

    print(f"  [policy] creating '{name}' from {cedar_file.name} ...")
    resp = client.create_policy(
        policyEngineId=pe_id,
        name=name,
        description=f"ZT procurement Cedar policy — {cedar_file.stem}",
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


def attach_policy_engine(client, gateway_id: str, pe_id: str,
                          mode: str = "LOG_ONLY") -> None:
    print(f"\n[gateway] attaching ProcurementPolicyEngine (mode={mode}) ...")
    current = client.get_gateway(gatewayIdentifier=gateway_id)
    if current.get("policyEngineConfiguration", {}).get("arn", "").endswith(pe_id):
        print(f"  policy engine already attached.")
        return

    # Get the policy engine ARN
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
        "ProcurementGateway (policy engine attach)",
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        ready="READY", failed=["UPDATE_FAILED"],
    )
    print(f"  policy engine attached in {mode} mode.")



# ── Validation ────────────────────────────────────────────────────────────────

def validate_env() -> dict:
    fn_arns = {
        "READ_INVOICE_FN_ARN":        READ_INVOICE_FN_ARN,
        "SHOW_IDENTITY_FN_ARN":       SHOW_IDENTITY_FN_ARN,
        "VALIDATE_VENDOR_FN_ARN":     VALIDATE_VENDOR_FN_ARN,
        "GET_VENDOR_TERMS_FN_ARN":    GET_VENDOR_TERMS_FN_ARN,
        "APPROVE_PAYMENT_FN_ARN":     APPROVE_PAYMENT_FN_ARN,
        "GET_APPROVAL_STATUS_FN_ARN": GET_APPROVAL_STATUS_FN_ARN,
    }
    missing = [k for k, v in fn_arns.items() if not v]
    if missing or not PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN:
        lines = [f"  {k}" for k in (missing + (
            ["PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN"]
            if not PROCUREMENT_GATEWAY_SERVICE_ROLE_ARN else []
        ))]
        sys.exit(
            "\nERROR: Missing in .env.demo:\n"
            + "\n".join(lines)
            + "\n\nRun 'make deploy && make setup' first."
        )
    return fn_arns


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[setup-procurement-gateway] profile={PROFILE_NAME}  region={REGION}")
    fn_arns = validate_env()

    client = control_client()

    # 1. Workload identities (all three agents — used for Phase 5 on-behalf-of)
    ensure_workload_identities(client)

    # 2. Gateway (AWS_IAM — agents authenticate via SigV4)
    gateway_id, gateway_url = create_or_get_gateway(client)

    # 3. Lambda targets (one per tool)
    create_targets(client, gateway_id, fn_arns)

    # 4. Policy engine
    pe_id = create_or_get_policy_engine(client)

    # 5. Cedar policies
    gw_state = client.get_gateway(gatewayIdentifier=gateway_id)
    gateway_arn = gw_state["gatewayArn"]
    for policy_name, cedar_file in POLICIES:
        create_or_get_policy(client, pe_id, policy_name, cedar_file, gateway_arn)

    # 6. Attach policy engine (LOG_ONLY to start)
    attach_policy_engine(client, gateway_id, pe_id, mode="LOG_ONLY")

    # 7. Persist outputs
    update_env_demo({
        "PROCUREMENT_GATEWAY_ID":  gateway_id,
        "PROCUREMENT_GATEWAY_URL": gateway_url,
        "PROCUREMENT_GATEWAY_ARN": gateway_arn,
        "PROCUREMENT_POLICY_ENGINE_ID": pe_id,
    })

    print(f"""
[setup-procurement-gateway] done.

  Gateway             : {gateway_id}
  Gateway URL         : {gateway_url}
  Auth                : AWS_IAM (agents authenticate via SigV4)
  Policy Engine       : {pe_id} (LOG_ONLY)
  Cedar policies      : orchestrator / vendor / approval (permit + forbid limit)

  ZT story — agent-to-tool authorization layer:
    Gateway URL written to .env.demo as PROCUREMENT_GATEWAY_URL.
    Agents sign requests with IAM execution role; Cedar checks principal.id per tool.

  Next steps:
    make phase1                                        — show resource policy on Runtime (human-to-agent)
    python scripts/toggle_policy_mode.py ENFORCE       — switch Cedar to ENFORCE for tool-level enforcement
    make phase5                                        — on-behalf-of: user role visible at tool call
""")


if __name__ == "__main__":
    main()
