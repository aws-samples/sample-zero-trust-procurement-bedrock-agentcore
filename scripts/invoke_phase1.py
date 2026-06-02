#!/usr/bin/env python3
"""
invoke_phase1.py — Phase 1 demo: Human → Agent Runtime Resource Policy.

Demonstrates the inbound Zero Trust control on the OrchestratorAgent Runtime:

  ZT PILLAR: Verify Explicitly (ingress)
  CONTROL:   Runtime resource-based policy (dual-gate with identity policy)

  BEFORE (no resource policy):
    Any IAM principal whose identity policy grants:
      bedrock-agentcore:InvokeAgentRuntime
    on this Runtime ARN can invoke the agent.
    → Any compromised credential in the account reaches the agent.

  AFTER (resource policy applied):
    The Runtime has an allow-list of permitted principals.
    BOTH gates must pass:
      1. Caller's identity policy must allow InvokeAgentRuntime
      2. Runtime resource policy must allow the caller's principal
    → Only explicitly named roles can invoke. Unlisted callers get
      AccessDeniedException before any agent code runs.

What this script shows:
  1. The current resource policy on the OrchestratorAgent Runtime.
  2. The dual-gate model diagram.
  3. An authorised invocation (current profile) → succeeds.
  4. Summary of what an unauthorised caller would see.

Usage:
    python scripts/invoke_phase1.py

Prerequisites:
    - .env.demo with ORCHESTRATOR_RUNTIME_ARN populated
      (run 'make configure-agents && make setup-identity' first)
    - AWS_PROFILE set in environment
"""

import json
import os
import sys
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# ── Environment ────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(REPO_ROOT / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
if not PROFILE_NAME:
    sys.exit("ERROR: AWS_PROFILE is not set.")

REGION = os.environ.get("AWS_REGION", "us-east-1")
RUNTIME_ARN = os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")


# ── Helpers ────────────────────────────────────────────────────────────────────

def banner(title: str, width: int = 60) -> None:
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print('=' * width)


def get_control_client():
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client(
        "bedrock-agentcore-control"
    )


def get_runtime_client():
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client(
        "bedrock-agentcore"
    )


def invoke_agent(client, arn: str, prompt: str) -> dict:
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=arn,
        runtimeSessionId=str(uuid.uuid4()),
        payload=json.dumps({"prompt": prompt}).encode(),
    )
    raw = resp["response"].read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"response": raw.decode()}


# ── Demo sections ──────────────────────────────────────────────────────────────

def show_resource_policy(client) -> None:
    banner("Step 1: OrchestratorAgent Runtime Resource Policy")
    print("""
  The resource policy is attached directly to the Runtime ARN.
  It acts as an explicit allow-list of principals that may invoke this agent.

  BEFORE (no policy): any caller with InvokeAgentRuntime IAM permission
    can reach this runtime — broad inbound surface.

  AFTER (policy applied): BOTH conditions must be true:
    1. Caller's identity policy allows bedrock-agentcore:InvokeAgentRuntime
    2. Runtime resource policy allows the caller's principal ARN
""")
    if not RUNTIME_ARN:
        print("  ORCHESTRATOR_RUNTIME_ARN not set — skipping policy display.")
        print("  Run 'make configure-agents && make setup-identity' first.")
        return

    try:
        resp = client.get_resource_policy(resourceArn=RUNTIME_ARN)
        doc = json.loads(resp.get("policy", "{}"))
        print("  Resource policy document:")
        print(json.dumps(doc, indent=4))

        stmts = doc.get("Statement", [])
        if stmts:
            stmt = stmts[0]
            # Handle deny-based policy (DenyUnlessAllowListed)
            condition = stmt.get("Condition", {})
            not_like = condition.get("StringNotLike", {}).get("aws:PrincipalArn", [])
            if not_like:
                if isinstance(not_like, str):
                    not_like = [not_like]
                print(f"\n  Deny all EXCEPT ({len(not_like)} principals):")
                for p in not_like:
                    print(f"    [ALLOW] {p}")
            else:
                # Fallback for allow-based policy
                principal = stmt.get("Principal", {})
                principals = principal.get("AWS", []) if isinstance(principal, dict) else []
                if isinstance(principals, str):
                    principals = [principals]
                print(f"\n  Allowed principals ({len(principals)}):")
                for p in principals:
                    print(f"    [ALLOW] {p}")
        else:
            print("\n  WARNING: No Statement found in policy document.")

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("ResourceNotFoundException", "NoSuchResourcePolicyException"):
            print(
                "  [!] No resource policy found.\n"
                "  Run 'make setup-identity' to attach the inbound resource policy."
            )
        else:
            print(f"  ERROR: {exc}")


def show_dual_gate_model() -> None:
    banner("Step 2: Dual-Gate Enforcement Model")
    print("""
  Both gates must ALLOW the call. Either DENY blocks the invocation.

  Human caller (IAM principal, e.g. demo user / CI role)
       │
       │  bedrock-agentcore:InvokeAgentRuntime
       │
       ▼
  ┌─────────────────────────────────────────────────┐
  │  Gate 1: Identity-Based IAM Policy              │
  │  "Does the caller's role ALLOW this action?"    │
  │  → Evaluated from the caller's IAM permissions  │
  └──────────────────┬──────────────────────────────┘
                     │ ALLOW
                     ▼
  ┌─────────────────────────────────────────────────┐
  │  Gate 2: Runtime Resource-Based Policy          │
  │  "Does this Runtime ALLOW this principal?"      │
  │  → Evaluated against the Runtime's policy       │
  └──────────────────┬──────────────────────────────┘
                     │ ALLOW
                     ▼
  ┌─────────────────────────────────────────────────┐
  │  OrchestratorAgent Runtime (microVM)            │
  │  Execution role: orchestrator-execution-role    │
  │  Agent code starts running                      │
  └─────────────────────────────────────────────────┘

  Unlisted caller → Gate 2 returns AccessDeniedException
  → Agent code NEVER executes (blast radius = zero for that caller)
""")


def invoke_as_authorised_caller(runtime_client) -> None:
    banner("Step 3: Authorised Invocation — Current Profile")
    print(f"  Profile: {PROFILE_NAME}")
    print(f"  Runtime: {RUNTIME_ARN or '(ORCHESTRATOR_RUNTIME_ARN not set)'}\n")

    if not RUNTIME_ARN:
        print("  Skipping live invocation — ORCHESTRATOR_RUNTIME_ARN not set.")
        return

    print("  Prompt: 'Read invoice INV-001'\n")
    print("  Sending invoke_agent_runtime ...")
    try:
        result = invoke_agent(runtime_client, RUNTIME_ARN, "Read invoice INV-001.")
        print(json.dumps(result, indent=2))
        print("\n  [PASS] Invocation succeeded — current profile is in the resource policy.")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "AccessDeniedException":
            print(
                f"\n  [EXPECTED DENY] AccessDeniedException — this profile is NOT in the\n"
                f"  resource policy.  Add it via 'make setup-identity' to allow access.\n"
                f"\n  Error: {exc.response['Error']['Message']}"
            )
        else:
            print(f"  ERROR ({code}): {exc.response['Error']['Message']}")


def show_unauthorised_summary() -> None:
    banner("Step 4: What an Unauthorised Caller Sees")
    print("""
  If a principal NOT listed in the resource policy attempts:

    client.invoke_agent_runtime(agentRuntimeArn=RUNTIME_ARN, ...)

  The response is:

    botocore.exceptions.ClientError:
      An error occurred (AccessDeniedException) when calling the
      InvokeAgentRuntime operation:
      User: arn:aws:sts::ACCOUNT:assumed-role/unknown-role/session
      is not authorized to perform: bedrock-agentcore:InvokeAgentRuntime
      on resource: arn:aws:bedrock-agentcore:us-east-1:ACCOUNT:agent-runtime/...

  The agent microVM never starts. No tools are called. No data is read.
  Blast radius for the unlisted principal = zero.

  ZT PRINCIPLE: Assume Breach — even if credentials are compromised,
  the attacker cannot reach the agent without being in the allow-list.
""")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[phase1] profile={PROFILE_NAME}  region={REGION}")
    print(
        "\n  ZT Pillar: Verify Explicitly (Human → Agent ingress)\n"
        "  Control:   Runtime resource-based policy (dual-gate with identity policy)"
    )

    control = get_control_client()
    runtime = get_runtime_client()

    show_resource_policy(control)
    show_dual_gate_model()
    invoke_as_authorised_caller(runtime)
    show_unauthorised_summary()

    banner("Phase 1 Summary")
    print("""
  Zero Trust controls demonstrated:
    Dual-gate enforcement: identity policy AND resource policy must both ALLOW
    Allow-list model: unlisted principals blocked before agent code runs
    Audit trail: AccessDeniedException logged to CloudTrail (caller ARN, resource)

  Next demo commands:
    make phase2                                        — IAM execution role blast radius (broad vs scoped)
    make phase3                                        — Cedar agent-to-tool authorization (LOG_ONLY mode)
    python scripts/toggle_policy_mode.py ENFORCE       — switch Cedar to binding mode
""")


if __name__ == "__main__":
    main()
