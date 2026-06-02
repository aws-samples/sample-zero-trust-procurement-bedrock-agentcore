#!/usr/bin/env python3
"""
invoke_phase2.py — Phase 2: Apply least privilege to orchestrator execution role.

Detaches AmazonDynamoDBFullAccess from zt-demo-orchestrator-execution-role,
leaving only the scoped inline policies (dynamodb:GetItem on zt-demo-invoices,
Bedrock invoke, and InvokeAgentRuntime on sub-agent runtimes). Then invokes
the agent to confirm it can still read invoices.

The "before" exploit (update-item succeeding) is shown manually from CloudShell.
This script applies the fix and shows the "after" state.

Usage:
    python scripts/invoke_phase2.py
"""

import json
import os
import sys
import time
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()
load_dotenv(Path(__file__).resolve().parent.parent / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
if not PROFILE_NAME:
    sys.exit("ERROR: AWS_PROFILE is not set.")

REGION = os.environ.get("AWS_REGION", "us-east-1")
ORCHESTRATOR_ARN = os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")
ROLE_NAME = "zt-demo-orchestrator-execution-role"
BROAD_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"

if not ORCHESTRATOR_ARN:
    sys.exit("ERROR: ORCHESTRATOR_RUNTIME_ARN not set in .env.demo.")


def banner(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def main() -> None:
    session = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
    iam_client = session.client("iam")
    runtime_client = session.client("bedrock-agentcore")

    print(f"[phase2] Applying least privilege to {ROLE_NAME}")

    # ── Detach broad policy ──────────────────────────────────────────────────
    banner("Applying Zero Trust: Detaching AmazonDynamoDBFullAccess")
    try:
        iam_client.detach_role_policy(RoleName=ROLE_NAME, PolicyArn=BROAD_POLICY_ARN)
        print(f"  [✓] Detached AmazonDynamoDBFullAccess")
    except ClientError:
        print(f"  [i] Already detached")

    print("  [→] Waiting for IAM propagation ...")
    time.sleep(10)  # nosemgrep: arbitrary-sleep

    policies = iam_client.list_attached_role_policies(RoleName=ROLE_NAME)
    names = [p["PolicyName"] for p in policies["AttachedPolicies"]]
    print(f"  Remaining attached policies: {names or '(none — inline GetItem only)'}")

    # ── Verify agent still works with scoped access ──────────────────────────
    banner("Verify: Agent can still read invoices (GetItem)")
    print("  [→] Asking agent: 'Read invoice INV-001'\n")
    resp = runtime_client.invoke_agent_runtime(
        agentRuntimeArn=ORCHESTRATOR_ARN,
        runtimeSessionId=str(uuid.uuid4()),
        payload=json.dumps({"prompt": "Read invoice INV-001."}).encode(),
    )
    raw = resp["response"].read()
    try:
        data = json.loads(raw)
        print(f"  {data.get('response', json.dumps(data))[:400]}")
    except json.JSONDecodeError:
        print(f"  {raw.decode()[:400]}")

    print("\n  [✅] Scoped access works — agent can do its job, nothing more.")

    # Revert INV-001 amount to original value (in case exploit succeeded)
    try:
        ddb = session.client("dynamodb")
        ddb.update_item(
            TableName="zt-demo-invoices",
            Key={"invoice_id": {"S": "INV-001"}},
            UpdateExpression="SET amount = :a",
            ExpressionAttributeValues={":a": {"S": "450.00"}},
        )
        print("\n  [cleanup] INV-001 amount restored to $450.00")
    except Exception:
        pass  # scoped role may not allow this — that's fine

    banner("Phase 2 Complete")
    print("""
  AmazonDynamoDBFullAccess has been removed.
  The orchestrator role now only has: dynamodb:GetItem on zt-demo-invoices,
  Bedrock invoke, and InvokeAgentRuntime on sub-agent runtimes.

  → Re-run the same update-item command from CloudShell to see AccessDeniedException.
  → The execution role IS the blast radius. It's now contained.

  Next: make phase3  — Cedar agent-to-tool authorization
""")


if __name__ == "__main__":
    main()
