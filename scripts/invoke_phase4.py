#!/usr/bin/env python3
"""
invoke_phase4.py — Phase 4 demo: three-tier A2A procurement workflow.

Demonstrates the complete Zero Trust procurement flow with all three agents
and resource policies gating every A2A hop.

Demo scenarios:
  INV-001  V001 ACME  $450   → vendor approved + auto-approve   (happy path)
  INV-002  V002 Tech  $750   → vendor approved + Cedar forbid blocks payment
  INV-EVIL V999 Fake  $100   → vendor NOT approved → approval never reached

Usage:
    python scripts/invoke_phase4.py
"""

import json
import os
import sys
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(REPO_ROOT / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
if not PROFILE_NAME:
    sys.exit("ERROR: AWS_PROFILE is not set.")

REGION = os.environ.get("AWS_REGION", "us-east-1")
ORCHESTRATOR_ARN = os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")
VENDOR_ARN = os.environ.get("VENDOR_RUNTIME_ARN", "")
APPROVAL_ARN = os.environ.get("APPROVAL_RUNTIME_ARN", "")


def invoke_runtime(client, arn: str, prompt: str) -> str:
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=arn,
        runtimeSessionId=str(uuid.uuid4()),
        payload=json.dumps({"prompt": prompt}).encode(),
    )
    raw = resp["response"].read()
    try:
        return json.loads(raw).get("response", raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return raw.decode()


def show_resource_policies(control_client) -> None:
    print("""
  A2A Resource Policies (who can invoke each Runtime):
  ┌──────────────────────────────────────────────────────────────┐""")

    for label, arn in [
        ("OrchestratorAgent", os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")),
        ("VendorAgent",       VENDOR_ARN),
        ("ApprovalAgent",     APPROVAL_ARN),
    ]:
        if not arn:
            print(f"  │  {label:20s}  no ARN set")
            continue
        try:
            resp = control_client.get_resource_policy(resourceArn=arn)
            doc = json.loads(resp.get("policy", "{}"))
            stmts = doc.get("Statement", [])
            if stmts:
                stmt = stmts[0]
                effect = stmt.get("Effect", "")
                if effect == "Deny":
                    # Deny+Condition pattern: allow-list is in StringNotLike
                    excepted = stmt.get("Condition", {}).get("StringNotLike", {}).get("aws:PrincipalArn", [])
                    if isinstance(excepted, str):
                        excepted = [excepted]
                    print(f"  │  {label:20s}  deny-all EXCEPT {len(excepted)} principal(s)")
                else:
                    raw = stmt.get("Principal", {})
                    if isinstance(raw, str):
                        principals = [raw]
                    else:
                        p = raw.get("AWS", [])
                        principals = [p] if isinstance(p, str) else p
                    print(f"  │  {label:20s}  allow {len(principals)} principal(s)")
            else:
                print(f"  │  {label:20s}  empty policy")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NoSuchResourcePolicyException"):
                print(f"  │  {label:20s}  NO resource policy (open to any caller)")
            else:
                print(f"  │  {label:20s}  error: {exc}")

    print("  └──────────────────────────────────────────────────────────────┘")


def run_scenario(client, label: str, prompt: str, expected: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"{'─' * 60}")
    print(f"  Expected: {expected}")
    print("  Invoking OrchestratorAgent ...\n")

    try:
        result = invoke_runtime(client, ORCHESTRATOR_ARN, prompt)
        print(f"  Agent response (truncated):\n  {result[:400]}...")
    except ClientError as exc:
        print(f"  ERROR: {exc.response['Error']['Message']}")


def main() -> None:
    print(f"[phase4] profile={PROFILE_NAME}  region={REGION}")

    for name, val in [("ORCHESTRATOR", ORCHESTRATOR_ARN), ("VENDOR", VENDOR_ARN), ("APPROVAL", APPROVAL_ARN)]:
        if not val:
            sys.exit(f"ERROR: {name}_RUNTIME_ARN not set. Run 'make configure-agents' first.")

    session = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
    runtime_client = session.client("bedrock-agentcore")
    control_client = session.client("bedrock-agentcore-control")

    print("""
╔══════════════════════════════════════════════════════════════╗
║  Phase 4: Full Three-Tier A2A Flow + Defense in Depth        ║
║  ZT Pillar: Assume Breach                                    ║
╚══════════════════════════════════════════════════════════════╝
""")

    show_resource_policies(control_client)

    run_scenario(
        runtime_client,
        "Scenario 1: INV-001 — $450, ACME (happy path)",
        "Process invoice INV-001.",
        "Three A2A hops, all gated by resource policies → auto-approved",
    )

    run_scenario(
        runtime_client,
        "Scenario 2: INV-002 — $750, TechEquip (escalation)",
        "Process invoice INV-002.",
        "Vendor approved → amount triggers escalation at approval step",
    )

    run_scenario(
        runtime_client,
        "Scenario 3: INV-EVIL — prompt injection + unknown vendor",
        "Process invoice INV-EVIL.",
        "Vendor V999 rejected → ApprovalAgent never called → injection blocked",
    )

    print(f"""
{'═' * 60}
  PHASE 4 SUMMARY
{'═' * 60}
  Three independent controls stopped unauthorized actions:
    1. Resource policies — only OrchestratorAgent can invoke sub-agents
    2. Vendor validation — unknown vendor V999 rejected before approval
    3. Cedar forbid     — amount >= $500 blocked at the gateway

  Each control works independently. Even if one is bypassed,
  the others still protect the system. That is defense in depth.

  Next: make phase5    (on-behalf-of identity propagation)
        make ui        (Streamlit UI — Phase 4 & 5 with identity switcher)
""")


if __name__ == "__main__":
    main()
