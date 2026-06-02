#!/usr/bin/env python3
"""
setup_vendor_resource_policy.py — A2A setup: VendorAgent Runtime resource policy.

Applies the second A2A Zero Trust gate:

  BEFORE:  VendorAgent Runtime has NO resource policy.
           Any caller with bedrock-agentcore:InvokeAgentRuntime in their IAM
           identity policy can invoke VendorAgent directly — regardless of role.

  AFTER:   VendorAgent Runtime has a resource policy.
           Only explicitly listed principals (OrchestratorAgent execution role
           and the demo presenter's role) may invoke the Runtime.  All other
           callers are blocked at the resource level even if their identity
           policy allows InvokeAgentRuntime.

This is the inbound complement to Phase 2's execution-role scoping:
  Phase 2: scoped execution role            → limits what the agent can DO   (egress)
  Phase 1: Orchestrator resource policy     → limits who can CALL it         (ingress)
  make setup-a2a: Vendor resource policy    → limits who can CALL VendorAgent (A2A ingress)

Dual-gate model:
  To invoke VendorAgent, a caller must pass BOTH:
    Gate 1 (identity policy):  bedrock-agentcore:InvokeAgentRuntime ALLOW
    Gate 2 (resource policy):  principal listed in VendorAgent resource policy

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
VENDOR_RUNTIME_ARN = os.environ.get("VENDOR_RUNTIME_ARN", "")
ORCHESTRATOR_EXECUTION_ROLE_ARN = os.environ.get("ORCHESTRATOR_EXECUTION_ROLE_ARN", "")

WORKLOAD_IDENTITY_NAME = "VendorAgent"


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_client():
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client(
        "bedrock-agentcore-control"
    )


def get_caller_arn() -> str:
    sts = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client("sts")
    return sts.get_caller_identity()["Arn"]


def normalise_arn(arn: str) -> str:
    """Convert assumed-role ARN to base role ARN for policy stability across sessions.

    arn:aws:sts::123:assumed-role/MyRole/session → arn:aws:iam::123:role/MyRole
    """
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
    """Create (or find existing) VendorAgent workload identity. Returns ARN."""
    print(f"\n[identity] checking for existing workload identity '{WORKLOAD_IDENTITY_NAME}' ...")
    try:
        response = client.get_workload_identity(name=WORKLOAD_IDENTITY_NAME)
        arn = response["workloadIdentityArn"]
        print(f"  [identity] found existing: {arn}")
        return arn
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    print(f"  [identity] creating '{WORKLOAD_IDENTITY_NAME}' ...")
    response = client.create_workload_identity(
        name=WORKLOAD_IDENTITY_NAME,
        tags={
            "demo": "zt-agentcore",
            "role": "vendor-agent",
        },
    )
    arn = response["workloadIdentityArn"]
    print(f"  [identity] created: {arn}")
    return arn


# ── Resource Policy ────────────────────────────────────────────────────────────

def build_resource_policy(caller_arn: str) -> dict:
    """
    Build VendorAgent Runtime resource policy.

    Allowed principals:
      - orchestrator-execution-role   (OrchestratorAgent's IAM role — A2A caller)
      - current caller's IAM role     (demo presenter for direct testing)

    ZT enforcement: only OrchestratorAgent can invoke VendorAgent directly.
    Any other caller (including users with InvokeAgentRuntime in their identity
    policy) is blocked at the resource level.
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
                "Resource": VENDOR_RUNTIME_ARN,
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
        print(f"\n  Current resource policy on VendorAgent Runtime:")
        print(json.dumps(doc, indent=4))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("ResourceNotFoundException", "NoSuchResourcePolicyException"):
            print(f"\n  No resource policy attached yet.")
        else:
            raise


def apply_resource_policy(client, runtime_arn: str, policy: dict) -> None:
    print(f"\n[resource-policy] applying to VendorAgent Runtime ...")
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
    print(f"[setup-vendor-resource-policy] profile={PROFILE_NAME}  region={REGION}")

    if not VENDOR_RUNTIME_ARN:
        sys.exit(
            "\nERROR: VENDOR_RUNTIME_ARN not set in .env.demo.\n"
            "Run 'make configure-agents' first."
        )

    client = get_client()
    caller_arn = get_caller_arn()

    print(f"\n  Vendor Runtime ARN  : {VENDOR_RUNTIME_ARN}")
    print(f"  Caller ARN          : {caller_arn}")

    # ── BEFORE ────────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  BEFORE: Resource policy on VendorAgent Runtime")
    print(f"{'─'*60}")
    show_current_policy(client, VENDOR_RUNTIME_ARN)
    print(
        "\n  Without a resource policy, ANY principal with:\n"
        "    bedrock-agentcore:InvokeAgentRuntime\n"
        "  can invoke VendorAgent — no A2A caller verification."
    )

    # ── Workload Identity ──────────────────────────────────────────────────────
    wi_arn = create_or_get_workload_identity(client)

    # ── Apply Resource Policy ──────────────────────────────────────────────────
    policy = build_resource_policy(caller_arn)
    apply_resource_policy(client, VENDOR_RUNTIME_ARN, policy)

    # ── AFTER ─────────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  AFTER: Resource policy on VendorAgent Runtime")
    print(f"{'─'*60}")
    show_current_policy(client, VENDOR_RUNTIME_ARN)

    # ── Persist ───────────────────────────────────────────────────────────────
    update_env_demo({"VENDOR_WORKLOAD_IDENTITY_ARN": wi_arn})

    allowed_count = len(policy["Statement"][0]["Principal"]["AWS"])
    print(f"""
[setup-vendor-resource-policy] done.

  Workload Identity ARN : {wi_arn}
  Resource policy       : applied (ALLOW for {allowed_count} principal(s))

  Zero Trust A2A controls now active on VendorAgent:
    Gate 1 (IAM identity):   caller must have InvokeAgentRuntime in identity policy
    Gate 2 (resource policy): caller must be listed in VendorAgent resource policy

  Authorised A2A callers:
    OrchestratorAgent execution role → A2A invoke from Orchestrator
    Demo presenter role              → direct invocation for testing

  All other callers are blocked at the resource-policy gate — even if they
  hold bedrock-agentcore:InvokeAgentRuntime in their own identity policy.

  Run 'make phase4' to see the full A2A authentication demo.
""")


if __name__ == "__main__":
    main()
