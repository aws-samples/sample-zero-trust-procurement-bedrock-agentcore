#!/usr/bin/env python3
"""
setup_approval_resource_policy.py — A2A setup: ApprovalAgent Runtime resource policy.

Completes the three-tier A2A Zero Trust chain:

  Tier 1 → Tier 2:  OrchestratorAgent → VendorAgent
    Secured by make setup-a2a: VendorAgent resource policy restricts to OrchestratorAgent role.

  Tier 2 → Tier 3:  OrchestratorAgent → ApprovalAgent  (THIS SCRIPT)
    ApprovalAgent Runtime gets a resource policy restricting InvokeAgentRuntime
    to OrchestratorAgent's execution role only.

After this script:
  - Human → OrchestratorAgent         : Runtime resource policy (Phase 1 / make setup-identity)
  - OrchestratorAgent execution role  : scoped IAM              (Phase 2)
  - Agent → tool                      : ProcurementGateway + Cedar (Phase 3)
  - OrchestratorAgent → VendorAgent   : resource policy gate    (make setup-a2a)
  - OrchestratorAgent → ApprovalAgent : resource policy gate    (make setup-a2a)  ← just applied

boto3 service: bedrock-agentcore-control

Run after: make configure-agents
"""

import json
import os
import re
import sys
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
APPROVAL_RUNTIME_ARN = os.environ.get("APPROVAL_RUNTIME_ARN", "")
ORCHESTRATOR_EXECUTION_ROLE_ARN = os.environ.get("ORCHESTRATOR_EXECUTION_ROLE_ARN", "")

WORKLOAD_IDENTITY_NAME = "ApprovalAgent"


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_client():
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client(
        "bedrock-agentcore-control"
    )


def get_caller_arn() -> str:
    sts = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client("sts")
    return sts.get_caller_identity()["Arn"]


def normalise_arn(arn: str) -> str:
    if ":assumed-role/" in arn:
        parts = arn.split(":")
        account_id = parts[4]
        role_session = parts[5].replace("assumed-role/", "")
        role_name = role_session.rsplit("/", 1)[0]
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    return arn


def update_env_demo(updates: dict[str, str]) -> None:
    path = REPO_ROOT / ".env.demo"
    if not path.exists():
        sys.exit("\nERROR: .env.demo not found. Run 'make setup' first.")
    text = path.read_text()
    for key, value in updates.items():
        pattern = re.compile(rf"^#?\s*{re.escape(key)}=.*$", re.MULTILINE)
        replacement = f"{key}={value}"
        if pattern.search(text):
            text = pattern.sub(replacement, text)
        else:
            text += f"\n{replacement}\n"
    path.write_text(text)


# ── Workload Identity ──────────────────────────────────────────────────────────

def create_or_get_workload_identity(client) -> str:
    print(f"\n[identity] checking for existing '{WORKLOAD_IDENTITY_NAME}' ...")
    try:
        response = client.get_workload_identity(name=WORKLOAD_IDENTITY_NAME)
        arn = response["workloadIdentityArn"]
        print(f"  found existing: {arn}")
        return arn
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    print(f"  creating '{WORKLOAD_IDENTITY_NAME}' ...")
    response = client.create_workload_identity(
        name=WORKLOAD_IDENTITY_NAME,
        tags={
            "demo": "zt-agentcore",
            "role": "approval-agent",
        },
    )
    arn = response["workloadIdentityArn"]
    print(f"  created: {arn}")
    return arn


# ── Resource Policy ────────────────────────────────────────────────────────────

def build_resource_policy(caller_arn: str) -> dict:
    """
    Allowed A2A callers for ApprovalAgent Runtime:
      - orchestrator-execution-role : OrchestratorAgent A2A invocation
      - demo presenter role         : direct testing
    """
    raw_arns = [
        ORCHESTRATOR_EXECUTION_ROLE_ARN,
        caller_arn,
    ]
    principals = list({normalise_arn(a) for a in raw_arns if a})

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowA2AFromOrchestrator",
                "Effect": "Allow",
                "Principal": {"AWS": principals},
                "Action": "bedrock-agentcore:InvokeAgentRuntime",
                "Resource": APPROVAL_RUNTIME_ARN,
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": REGION}
                },
            }
        ],
    }


def show_current_policy(client, runtime_arn: str) -> None:
    try:
        resp = client.get_resource_policy(resourceArn=runtime_arn)
        doc = json.loads(resp.get("policy", "{}"))
        print(f"\n  Current resource policy on ApprovalAgent Runtime:")
        print(json.dumps(doc, indent=4))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("ResourceNotFoundException", "NoSuchResourcePolicyException"):
            print(f"\n  No resource policy attached yet.")
        else:
            raise


def apply_resource_policy(client, runtime_arn: str, policy: dict) -> None:
    print(f"\n[resource-policy] applying to ApprovalAgent Runtime ...")
    print(f"  Runtime ARN: {runtime_arn}")
    print(f"  Allowed principals:")
    for p in policy["Statement"][0]["Principal"]["AWS"]:
        print(f"    - {p}")

    client.put_resource_policy(
        resourceArn=runtime_arn,
        policy=json.dumps(policy),
    )
    print(f"  [resource-policy] applied.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[setup-approval-resource-policy] profile={PROFILE_NAME}  region={REGION}")

    if not APPROVAL_RUNTIME_ARN:
        sys.exit(
            "\nERROR: APPROVAL_RUNTIME_ARN not set in .env.demo.\n"
            "Run 'make configure-agents' first."
        )

    client = get_client()
    caller_arn = get_caller_arn()

    print(f"\n  Approval Runtime ARN : {APPROVAL_RUNTIME_ARN}")
    print(f"  Caller ARN           : {caller_arn}")

    # ── BEFORE ────────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  BEFORE: Resource policy on ApprovalAgent Runtime")
    print(f"{'─'*60}")
    show_current_policy(client, APPROVAL_RUNTIME_ARN)

    # ── Workload Identity ──────────────────────────────────────────────────────
    wi_arn = create_or_get_workload_identity(client)

    # ── Apply Resource Policy ──────────────────────────────────────────────────
    policy = build_resource_policy(caller_arn)
    apply_resource_policy(client, APPROVAL_RUNTIME_ARN, policy)

    # ── AFTER ─────────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  AFTER: Resource policy on ApprovalAgent Runtime")
    print(f"{'─'*60}")
    show_current_policy(client, APPROVAL_RUNTIME_ARN)

    # ── Persist ───────────────────────────────────────────────────────────────
    update_env_demo({"APPROVAL_WORKLOAD_IDENTITY_ARN": wi_arn})

    allowed_count = len(policy["Statement"][0]["Principal"]["AWS"])
    print(f"""
[setup-approval-resource-policy] done.

  Workload Identity ARN : {wi_arn}
  Resource policy       : applied (ALLOW for {allowed_count} principal(s))

  Three-tier A2A chain now complete:
    OrchestratorAgent → VendorAgent   : resource policy (make setup-a2a)
    OrchestratorAgent → ApprovalAgent : resource policy (make setup-a2a)  ← just applied

  Every A2A hop is gated — no sub-agent can be invoked by an
  arbitrary caller, even if they hold InvokeAgentRuntime in their IAM policy.

  Run 'make phase4' to see the full three-tier procurement demo.
""")


if __name__ == "__main__":
    main()
