#!/usr/bin/env python3
"""
setup_workload_identity.py — Phase 1 setup: Workload Identity + OrchestratorAgent Runtime resource policy.

Two complementary Zero Trust controls demonstrated here:

  1. WORKLOAD IDENTITY
     Creates a named identity for OrchestratorAgent in AgentCore's central
     identity directory.  This is the agent's verifiable "who am I?" answer,
     distinct from its IAM execution role (which answers "what can I do?").

  2. RUNTIME RESOURCE POLICY (inbound IAM scoping)
     Attaches a resource-based policy to the OrchestratorAgent Runtime ARN.
     Only explicitly listed principals may invoke the Runtime — even if a
     caller holds the `bedrock-agentcore:InvokeAgentRuntime` IAM permission
     in their identity policy, the Runtime's own resource policy forms a
     second gate.

     This is the INBOUND complement to Phase 2's OUTBOUND execution-role scoping:
       Phase 1: resource policy        → limits who can CALL the agent (ingress)
       Phase 2: scoped execution role  → limits what the agent can DO (egress)

boto3 service:  bedrock-agentcore-control  (control plane)

Run after: make configure-agents  (so ORCHESTRATOR_RUNTIME_ARN is in .env.demo)
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
RUNTIME_ARN = os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")
ORCHESTRATOR_ROLE_ARN = os.environ.get("ORCHESTRATOR_EXECUTION_ROLE_ARN", "")
GATEWAY_ROLE_ARN = os.environ.get("GATEWAY_SERVICE_ROLE_ARN", "")

WORKLOAD_IDENTITY_NAME = "OrchestratorAgent"


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_client():
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client(
        "bedrock-agentcore-control"
    )


def get_caller_arn() -> str:
    """Return the ARN of the current AWS caller (for the demo resource policy)."""
    sts = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION).client("sts")
    return sts.get_caller_identity()["Arn"]


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
    """Create (or find existing) Workload Identity. Returns workloadIdentityArn."""
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
        # allowedResourceOauth2ReturnUrls: not needed for this agent
        # (no 3LO OAuth flows in the demo — A2A uses IAM-signed tokens)
        tags={
            "demo": "zt-agentcore",
            "role": "orchestrator",
        },
    )
    arn = response["workloadIdentityArn"]
    print(f"  [identity] created: {arn}")
    return arn


# ── Resource Policy ────────────────────────────────────────────────────────────

def build_resource_policy(caller_arn: str, account: str) -> dict:
    """
    Build the Runtime resource policy.

    Allowed principals (all must ALSO have the identity-based IAM permission):
      - orchestrator-execution-role   (the agent's own execution role)
      - gateway-service-role          (AgentCore Gateway → Runtime A2A routing)
      - current caller's IAM role     (demo scripts running on the presenter's machine)

    Everything else is implicitly denied by the default-deny model.
    """
    allowed_arns = [a for a in [
        ORCHESTRATOR_ROLE_ARN,
        GATEWAY_ROLE_ARN,
        caller_arn,
    ] if a]

    # Normalise assumed-role ARN → base role ARN so the policy is session-independent.
    # arn:aws:sts::123:assumed-role/MyRole/session → arn:aws:iam::123:role/MyRole
    def normalise(arn: str) -> str:
        if ":assumed-role/" in arn:
            parts = arn.split(":")
            account_id = parts[4]
            role_session = parts[5].replace("assumed-role/", "")
            role_name = role_session.rsplit("/", 1)[0]
            return f"arn:aws:iam::{account_id}:role/{role_name}"
        return arn

    principals = list({normalise(a) for a in allowed_arns})

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyUnlessAllowListed",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "bedrock-agentcore:InvokeAgentRuntime",
                "Resource": RUNTIME_ARN,
                "Condition": {
                    "StringNotLike": {
                        "aws:PrincipalArn": principals
                    }
                },
            },
        ],
    }


def apply_resource_policy(client, runtime_arn: str, policy: dict) -> None:
    """Attach resource policy to the Runtime ARN."""
    print(f"\n[identity] applying resource policy to Runtime ...")
    print(f"  ARN: {runtime_arn}")
    stmt = policy["Statement"][0]
    allowed = stmt["Condition"]["StringNotLike"]["aws:PrincipalArn"]
    if isinstance(allowed, str):
        allowed = [allowed]
    print(f"  Deny all EXCEPT:")
    for p in allowed:
        print(f"    [ALLOW] {p}")

    client.put_resource_policy(
        resourceArn=runtime_arn,
        policy=json.dumps(policy),
    )
    print(f"  [identity] resource policy applied.")


def show_current_policy(client, runtime_arn: str) -> None:
    """Print the current resource policy for display."""
    try:
        response = client.get_resource_policy(resourceArn=runtime_arn)
        doc = json.loads(response.get("policy", "{}"))
        print(f"\n  Current resource policy on Runtime:")
        print(json.dumps(doc, indent=4))
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "ResourceNotFoundException",
            "NoSuchResourcePolicyException",
        ):
            print(f"\n  No resource policy attached yet.")
        else:
            raise


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[setup-identity] profile={PROFILE_NAME}  region={REGION}")

    if not RUNTIME_ARN:
        sys.exit(
            "\nERROR: ORCHESTRATOR_RUNTIME_ARN not set in .env.demo.\n"
            "Run 'make configure-agents' first to deploy the Orchestrator Runtime."
        )

    client = get_client()
    caller_arn = get_caller_arn()
    account = caller_arn.split(":")[4]

    print(f"\n  Runtime ARN  : {RUNTIME_ARN}")
    print(f"  Caller ARN   : {caller_arn}")

    # ── Step 1: Show existing policy (before) ─────────────────────────────────
    print(f"\n{'─'*60}")
    print("  BEFORE: Resource policy on Runtime")
    print(f"{'─'*60}")
    show_current_policy(client, RUNTIME_ARN)
    print(
        "\n  Without a resource policy, ANY IAM principal with:\n"
        "    bedrock-agentcore:InvokeAgentRuntime (in their identity policy)\n"
        "  can invoke this Runtime — no additional gate."
    )

    # ── Step 2: Create Workload Identity ─────────────────────────────────────
    wi_arn = create_or_get_workload_identity(client)

    # ── Step 3: Apply resource policy (after) ─────────────────────────────────
    policy = build_resource_policy(caller_arn, account)
    apply_resource_policy(client, RUNTIME_ARN, policy)

    print(f"\n{'─'*60}")
    print("  AFTER: Resource policy on Runtime")
    print(f"{'─'*60}")
    show_current_policy(client, RUNTIME_ARN)

    # ── Step 4: Persist to .env.demo ──────────────────────────────────────────
    update_env_demo({
        "ORCHESTRATOR_WORKLOAD_IDENTITY_ARN": wi_arn,
    })

    print(f"""
[setup-identity] done.

  Workload Identity ARN : {wi_arn}
  Resource policy       : applied (DENY unless in allow-list)

  Zero Trust controls now active on OrchestratorAgent:
    Ingress (Phase 1):  resource policy        → only known principals can invoke
    Egress  (Phase 2):  scoped execution role  → GetItem on invoices ONLY

  Run 'make phase1' to walk through the resource policy demo.
""")


if __name__ == "__main__":
    main()
