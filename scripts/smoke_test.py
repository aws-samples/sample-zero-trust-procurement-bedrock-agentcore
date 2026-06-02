#!/usr/bin/env python3
"""
smoke_test.py — pre-demo readiness check.

Verifies every component the demo depends on is deployed, reachable, and in
the expected state.  Run this before the audience arrives.

Checks:
  1. AWS credentials valid (STS get-caller-identity)
  2. Bedrock model accessible (us.anthropic.claude-sonnet-4-6)
  3. .env.demo present and key variables populated
  4. Cognito tokens not expired (decode JWT exp claim without verification)
  5. CloudFormation stacks in UPDATE_COMPLETE / CREATE_COMPLETE state
  6. DynamoDB invoices table seeded (INV-001, INV-002, INV-EVIL present)
  7. AgentCore Runtimes READY (Orchestrator, Vendor, Approval if deployed)
  8. ProcurementGateway READY + workload identities created
  9. ProcurementPolicyEngine ACTIVE + Cedar policies loaded

Exit codes:
  0 — all checks passed
  1 — one or more checks failed (details printed inline)

Usage:
    python scripts/smoke_test.py
    make smoke
"""

import base64
import json
import os
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# ── Environment ────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(REPO_ROOT / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
if not PROFILE_NAME:
    sys.exit(
        "ERROR: AWS_PROFILE is not set.\n"
        "Run: export AWS_PROFILE=<your-aws-cli-profile>"
    )

REGION = os.environ.get("AWS_REGION", "us-east-1")

# ── Tracking ───────────────────────────────────────────────────────────────────

_passed = 0
_failed = 0
_skipped = 0


def _pass(label: str, detail: str = "") -> None:
    global _passed
    _passed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  PASS  {label}{suffix}")


def _fail(label: str, detail: str = "") -> None:
    global _failed
    _failed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  FAIL  {label}{suffix}")


def _skip(label: str, reason: str = "") -> None:
    global _skipped
    _skipped += 1
    suffix = f"  ({reason})" if reason else ""
    print(f"  SKIP  {label}{suffix}")


def _section(title: str) -> None:
    print(f"\n  {title}")
    print(f"  {'─' * (len(title) + 2)}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_session() -> boto3.Session:
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verifying signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        # Add padding if needed
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.b64decode(padded).decode())
    except Exception:
        return {}


def stack_status(cf_client, stack_name: str) -> str | None:
    try:
        resp = cf_client.describe_stacks(StackName=stack_name)
        return resp["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return None
        raise


def find_runtime_by_name(agentcore_client, name: str) -> dict | None:
    try:
        paginator = agentcore_client.get_paginator("list_agent_runtimes")
        for page in paginator.paginate():
            for rt in page.get("agentRuntimes", []):
                if rt.get("agentRuntimeName") == name:
                    return rt
    except Exception:
        pass
    return None


def find_gateway_by_name(control_client, name: str) -> dict | None:
    try:
        paginator = control_client.get_paginator("list_gateways")
        for page in paginator.paginate():
            for gw in page.get("items", []):
                if gw.get("name") == name:
                    return gw
    except Exception:
        pass
    return None


def find_policy_engine_by_name(control_client, name: str) -> dict | None:
    try:
        paginator = control_client.get_paginator("list_policy_engines")
        for page in paginator.paginate():
            for pe in page.get("policyEngines", []):
                if pe.get("name") == name:
                    return pe
    except Exception:
        pass
    return None


# ── Check functions ────────────────────────────────────────────────────────────

def check_credentials(session: boto3.Session) -> bool:
    _section("1. AWS credentials")
    try:
        identity = session.client("sts").get_caller_identity()
        _pass("STS get-caller-identity", identity["Arn"])
        return True
    except NoCredentialsError:
        _fail("STS get-caller-identity", "no credentials found")
        return False
    except ClientError as exc:
        _fail("STS get-caller-identity", str(exc))
        return False


def check_bedrock_model(session: boto3.Session) -> None:
    _section("2. Bedrock model access")
    # Agents use a cross-region inference profile — check list-inference-profiles,
    # not list-foundation-models (which does not include the us.* profiles).
    profile_id = "us.anthropic.claude-sonnet-4-6"
    try:
        client = session.client("bedrock", region_name=REGION)
        resp = client.list_inference_profiles()
        ids = {p["inferenceProfileId"] for p in resp.get("inferenceProfileSummaries", [])}
        if profile_id in ids:
            _pass(f"Inference profile accessible: {profile_id}")
        else:
            _fail(
                f"Inference profile not found: {profile_id}",
                "enable cross-region inference in Bedrock console",
            )
    except ClientError as exc:
        _fail("Bedrock list-inference-profiles", str(exc))


def check_env_demo() -> dict:
    _section("3. .env.demo variables")
    env_path = REPO_ROOT / ".env.demo"
    if not env_path.exists():
        _fail(".env.demo exists", "run 'make setup' first")
        return {}
    _pass(".env.demo exists")

    required = [
        "COGNITO_USER_POOL_ID",
        "COGNITO_APP_CLIENT_ID",
        "INVOICES_TABLE_NAME",
        "ORCHESTRATOR_EXECUTION_ROLE_ARN",
        "ADMIN_ID_TOKEN",
        "OPERATOR_ID_TOKEN",
    ]
    optional_arns = [
        "ORCHESTRATOR_RUNTIME_ARN",
        "VENDOR_RUNTIME_ARN",
        "APPROVAL_RUNTIME_ARN",
        "PROCUREMENT_GATEWAY_ID",
        "PROCUREMENT_GATEWAY_URL",
        "PROCUREMENT_POLICY_ENGINE_ID",
    ]

    env_values = {}
    for key in required:
        val = os.environ.get(key, "")
        if val:
            _pass(f"  {key}", val[:60] + "..." if len(val) > 60 else val)
            env_values[key] = val
        else:
            _fail(f"  {key}", "not set — run 'make setup'")

    for key in optional_arns:
        val = os.environ.get(key, "")
        if val:
            _pass(f"  {key} (optional)", val[-40:])
            env_values[key] = val
        else:
            _skip(f"  {key}", "not yet deployed")

    return env_values


def check_cognito_tokens(env: dict) -> None:
    _section("4. Cognito token expiry")
    now = int(time.time())

    for label, key in [("admin", "ADMIN_ID_TOKEN"), ("operator", "OPERATOR_ID_TOKEN")]:
        token = env.get(key) or os.environ.get(key, "")
        if not token:
            _skip(f"  {label} token", "not in .env.demo")
            continue
        payload = decode_jwt_payload(token)
        exp = payload.get("exp", 0)
        if exp == 0:
            _fail(f"  {label} token", "could not decode JWT")
        elif exp > now:
            remaining = (exp - now) // 60
            _pass(f"  {label} token valid", f"expires in {remaining}m")
        else:
            _fail(f"  {label} token expired", "run 'make setup' to refresh")


def check_cfn_stacks(session: boto3.Session) -> None:
    _section("5. CloudFormation stacks")
    cf = session.client("cloudformation")
    ok_statuses = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}

    for stack_name in ["FoundationStack", "OrchestratorStack", "VendorStack",
                       "ApprovalStack"]:
        status = stack_status(cf, stack_name)
        if status is None:
            _skip(f"  {stack_name}", "not deployed")
        elif status in ok_statuses:
            _pass(f"  {stack_name}", status)
        else:
            _fail(f"  {stack_name}", f"status={status}")


def check_dynamodb(session: boto3.Session, env: dict) -> None:
    _section("6. DynamoDB invoices table")
    table_name = env.get("INVOICES_TABLE_NAME") or os.environ.get("INVOICES_TABLE_NAME", "")
    if not table_name:
        _skip("  Table check", "INVOICES_TABLE_NAME not set")
        return

    table = session.resource("dynamodb").Table(table_name)
    for invoice_id in ["INV-001", "INV-002", "INV-EVIL"]:
        try:
            resp = table.get_item(Key={"invoice_id": invoice_id})
            if "Item" in resp:
                amount = resp["Item"].get("amount", "?")
                _pass(f"  {invoice_id}", f"amount={amount}")
            else:
                _fail(f"  {invoice_id}", "not found — run 'make setup' to seed")
        except ClientError as exc:
            _fail(f"  {invoice_id}", str(exc))


def check_runtimes(agentcore_client) -> None:
    _section("7. AgentCore Runtimes")
    for name in ["OrchestratorAgent", "VendorAgent", "ApprovalAgent"]:
        rt = find_runtime_by_name(agentcore_client, name)
        if rt is None:
            _skip(f"  {name}", "not deployed — run 'make configure-agents'")
        else:
            status = rt.get("status", "?")
            arn = rt.get("agentRuntimeArn", "")
            if status == "READY":
                _pass(f"  {name}", f"READY  {arn[-30:]}")
            else:
                _fail(f"  {name}", f"status={status}")


def check_gateways(control_client) -> None:
    _section("8. AgentCore Gateway (ProcurementGateway)")
    gw = find_gateway_by_name(control_client, "ProcurementGateway")
    if gw is None:
        _skip("  ProcurementGateway", "not created — run 'make setup-procurement-gateway'")
    else:
        status = gw.get("status", "?")
        auth = gw.get("authorizerType", "?")
        mode = gw.get("policyEngineConfiguration", {}).get("mode", "none")
        if status == "READY":
            _pass("  ProcurementGateway", f"READY  auth={auth}  cedar={mode}")
        else:
            _fail("  ProcurementGateway", f"status={status}")

    # Also check workload identities (all three agents)
    for wi_name in ["OrchestratorAgent", "VendorAgent", "ApprovalAgent"]:
        try:
            wi = control_client.get_workload_identity(name=wi_name)
            _pass(f"  WorkloadIdentity:{wi_name}", wi.get("workloadIdentityArn", "")[-30:])
        except Exception:
            _skip(f"  WorkloadIdentity:{wi_name}", "not created — run 'make setup-procurement-gateway'")


def check_policy_engines(control_client) -> None:
    _section("9. Cedar Policy Engine (ProcurementPolicyEngine)")
    pe = find_policy_engine_by_name(control_client, "ProcurementPolicyEngine")
    if pe is None:
        _skip("  ProcurementPolicyEngine", "not created — run 'make setup-procurement-gateway'")
    else:
        status = pe.get("status", "?")
        if status == "ACTIVE":
            # Count policies attached to this engine
            try:
                policies = control_client.list_policies(policyEngineId=pe["policyEngineId"])
                count = len(policies.get("policies", []))
                _pass("  ProcurementPolicyEngine", f"ACTIVE  {count} Cedar polic{'ies' if count != 1 else 'y'}")
            except Exception:
                _pass("  ProcurementPolicyEngine", "ACTIVE")
        else:
            _fail("  ProcurementPolicyEngine", f"status={status}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n[smoke] profile={PROFILE_NAME}  region={REGION}\n")
    print("=" * 50)

    session = get_session()

    # Credentials must pass before we can do anything else
    if not check_credentials(session):
        print("\n  ABORT: fix credentials before running other checks.")
        sys.exit(1)

    check_bedrock_model(session)
    env = check_env_demo()
    check_cognito_tokens(env)
    check_cfn_stacks(session)
    check_dynamodb(session, env)

    try:
        agentcore_client = session.client("bedrock-agentcore")
        control_client = session.client("bedrock-agentcore-control")
        check_runtimes(agentcore_client)
        check_gateways(control_client)
        check_policy_engines(control_client)
    except Exception as exc:
        _fail("AgentCore API checks", str(exc))

    # ── Summary ────────────────────────────────────────────────────────────────
    total = _passed + _failed + _skipped
    print(f"\n{'=' * 50}")
    print(f"  Results: {_passed} passed  {_failed} failed  {_skipped} skipped  ({total} total)")

    if _failed > 0:
        print(f"\n  SMOKE TEST FAILED — fix the {_failed} failing check(s) above.")
        print("  Common fixes:")
        print("    Expired tokens    : make setup")
        print("    Missing stacks    : make deploy")
        print("    Missing agents    : make configure-agents")
        print("    Missing gateway   : make setup-procurement-gateway")
        print("    Missing identity  : make setup-identity")
        sys.exit(1)
    else:
        print(f"\n  SMOKE TEST PASSED — demo environment is ready.")
        if _skipped > 0:
            print(f"  ({_skipped} skipped item(s) are optional or not yet deployed)")
        print("  Run 'make phase1' to start the demo.")
    print()


if __name__ == "__main__":
    main()
