#!/usr/bin/env python3
"""
invoke_phase3.py — Phase 3: Cedar agent-to-tool authorization at ProcurementGateway.

ZT Pillar: Least Privilege + Enforce at Point-of-Action
Control:   ProcurementGateway + Cedar policy engine

Shows:
  1. INV-001 ($450) → Cedar ALLOW → payment auto-approved
  2. INV-002 ($750) → Cedar DENY (amount >= $500)
     LOG_ONLY: DENY logged, Lambda still runs
     ENFORCE:  DENY binding, Lambda never invoked (count=0)

Usage: python scripts/invoke_phase3.py
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

PROFILE = os.environ.get("AWS_PROFILE")
if not PROFILE:
    sys.exit("ERROR: AWS_PROFILE is not set.")

REGION = os.environ.get("AWS_REGION", "us-east-1")
RUNTIME_ARN = os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")
GATEWAY_ID = os.environ.get("PROCUREMENT_GATEWAY_ID", "")

if not RUNTIME_ARN:
    sys.exit("ERROR: ORCHESTRATOR_RUNTIME_ARN not set. Run 'make configure-agents' first.")


def _session():
    return boto3.Session(profile_name=PROFILE, region_name=REGION)


def _invoke(prompt: str) -> str:
    """Invoke OrchestratorAgent and return the response text."""
    client = _session().client("bedrock-agentcore")
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=RUNTIME_ARN,
        runtimeSessionId=str(uuid.uuid4()),
        payload=json.dumps({"prompt": prompt}).encode(),
    )
    raw = resp["response"].read()
    try:
        return json.loads(raw).get("response", raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return raw.decode()


def _get_cedar_mode() -> str:
    """Get current Cedar policy mode from gateway."""
    if not GATEWAY_ID:
        return "unknown"
    try:
        gw = _session().client("bedrock-agentcore-control").get_gateway(gatewayIdentifier=GATEWAY_ID)
        return gw.get("policyEngineConfiguration", {}).get("mode", "unknown")
    except Exception:
        return "unknown"


def main():
    mode = _get_cedar_mode()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  Phase 3: Cedar Agent-to-Tool Authorization                  ║
║  ZT Pillar: Least Privilege + Enforce at Point-of-Action     ║
╚══════════════════════════════════════════════════════════════╝

  Cedar mode: {mode}

  Cedar policies on ProcurementGateway:
  ┌─────────────────────────────────────────────────────────────┐
  │ permit: OrchestratorAgent → read_invoice, show_identity     │
  │ permit: VendorAgent       → validate_vendor, get_terms      │
  │ permit: ApprovalAgent     → approve_payment, get_status     │
  │ forbid: approve_payment when amount >= $500                 │
  │                                                             │
  │ No permit = default deny.  Forbid overrides any permit.     │
  └─────────────────────────────────────────────────────────────┘
""")

    # ── Scenario 1: Allowed path ──────────────────────────────────────────────
    print("─" * 60)
    print("  TEST 1: INV-001 ($450) — Cedar should ALLOW")
    print("─" * 60)
    print("  Invoking OrchestratorAgent ...\n")

    try:
        result = _invoke("Process invoice INV-001.")
        print(f"  Agent response:\n  {result[:300]}...")
    except ClientError as exc:
        print(f"  ERROR: {exc.response['Error']['Message']}")

    # ── Scenario 2: Amount constraint ─────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  TEST 2: INV-002 ($750) — Cedar forbid should DENY (amount >= $500)")
    print("─" * 60)
    if mode == "LOG_ONLY":
        print("  Mode: LOG_ONLY — DENY is logged but Lambda still runs")
    elif mode == "ENFORCE":
        print("  Mode: ENFORCE — DENY blocks Lambda invocation")
    print("  Invoking OrchestratorAgent ...\n")

    try:
        result = _invoke("Process invoice INV-002.")
        print(f"  Agent response:\n  {result[:300]}...")
    except ClientError as exc:
        print(f"  ERROR: {exc.response['Error']['Message']}")

    print("""
  ┌──────────────────────────────────────────────────────────┐
  │  CHECK THE PROOF                                         │
  │  The agent's text above may fabricate results.           │
  │  The real proof is in CloudWatch:                        │
  │                                                          │
  │  1. aws/spans: run the query below for ALLOW vs DENY     │
  │  2. Lambda: zt-demo-approve-payment invocation count     │
  │     LOG_ONLY  = count goes UP   (Lambda ran despite DENY) │
  │     ENFORCE   = count stays FLAT (Lambda never called)    │
  └──────────────────────────────────────────────────────────┘""")

    # ── Where to see Cedar decisions ──────────────────────────────────────────
    print(f"""
{'─' * 60}
  WHERE TO SEE CEDAR DECISIONS
{'─' * 60}

  CloudWatch → Logs Insights → select log group: aws/spans

  Query (shows ALLOW and DENY decisions side by side):
    fields @timestamp,
           attributes.aws.agentcore.policy.authorization_decision as decision,
           attributes.aws.agentcore.policy.determining_policies.0 as policy,
           attributes.aws.agentcore.policy.authorization_reason as reason,
           attributes.aws.agentcore.gateway.policy.mode as mode
    | filter name like /Policy.Authorize/
    | sort @timestamp desc
    | limit 20

  What to look for:
    • decision=ALLOW → permit matched, Lambda executed
    • decision=DENY  → forbid matched (amount >= 500)
      reason shows: "Policy evaluation denied due to ProcurementApprovalLimitPolicy"
    • In LOG_ONLY: DENY is logged but Lambda still runs
    • In ENFORCE:  DENY blocks Lambda — invocation count = 0

  Or visually: CloudWatch → GenAI Observability → Traces
    Click any trace → look for "Policy" spans inline with tool calls.
""")

    # ── Summary ───────────────────────────────────────────────────────────────
    next_steps = (
        "  Next: python scripts/toggle_policy_mode.py ENFORCE  (switch Cedar to binding mode)\n"
        "        make phase4                                    (full flow with A2A auth)"
        if mode == "LOG_ONLY" else
        "  Next: python scripts/toggle_policy_mode.py LOG_ONLY  (switch back to observe mode)\n"
        "        make phase4                                     (full flow with A2A auth)"
    )
    print(f"""{'═' * 60}
  PHASE 3 SUMMARY
{'═' * 60}
  Cedar mode: {mode}
  • Agent IAM execution role = principal identity at the Gateway
  • Cedar default-deny: wrong agent role → blocked (no permit rule)
  • Explicit forbid: approve_payment blocked when amount >= $500
  • DENY decisions visible in aws/spans with determining policy name
  • LOG_ONLY → ENFORCE: observe first, enforce when ready (no code change)

{next_steps}
""")


if __name__ == "__main__":
    main()
