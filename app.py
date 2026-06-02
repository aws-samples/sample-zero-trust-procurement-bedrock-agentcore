#!/usr/bin/env python3
"""
CDK App entry point.

Identity resolution — two supported modes:

  Named profile (recommended for live demo):
    export AWS_PROFILE=zt-demo-deployer
    cdk deploy --all
    All of CDK, boto3, and the AWS CLI use the same named profile.

  Environment credentials (CI / temporary sessions / assumed roles):
    Leave AWS_PROFILE unset.  boto3 uses the default credential chain
    (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN or instance
    profile).  A warning is printed so the difference is always visible.

Account ID and region are resolved from the active credentials at synth time —
no hardcoded IDs anywhere in the repo.
"""
import os
import sys

import aws_cdk as cdk
from aws_cdk import Aspects
import boto3
from cdk_nag import AwsSolutionsChecks
from botocore.exceptions import ProfileNotFound
from dotenv import load_dotenv

# Load .env if present (ignored in CI where env vars are injected directly)
load_dotenv()

# ── Credential resolution ─────────────────────────────────────────────────────
profile_name = os.environ.get("AWS_PROFILE")

if profile_name:
    try:
        session = boto3.Session(profile_name=profile_name)
        # Validate the profile has live credentials before proceeding.
        session.client("sts").get_caller_identity()
    except ProfileNotFound:
        sys.exit(
            f"\nERROR: AWS profile '{profile_name}' not found in ~/.aws/config.\n"
            f"Run:   aws configure --profile {profile_name}\n"
            f"Then retry the CDK command.\n"
        )
else:
    # Environment-credentials mode: use the default boto3 chain.
    print(
        "WARNING: AWS_PROFILE is not set — using default credential chain.\n"
        "         Set AWS_PROFILE=zt-demo-deployer for the demo setup.",
        file=sys.stderr,
    )
    session = boto3.Session()

# ── Account + region from the active credentials ──────────────────────────────
# Resolved at synth time so every stack receives explicit Environment values.
# Explicit environments prevent CDK from using environment-agnostic synthesis,
# which would make cross-stack ARN references unreliable.
account = session.client("sts").get_caller_identity()["Account"]
region = session.region_name or os.environ.get("AWS_REGION", "us-east-1")

env = cdk.Environment(account=account, region=region)

# ── App ───────────────────────────────────────────────────────────────────────
app = cdk.App()

# Stacks are added here incrementally as each implementation step completes.

# Step 1: Foundation — Cognito, IAM roles, DynamoDB
from infra.stacks.foundation_stack import FoundationStack
foundation = FoundationStack(app, "FoundationStack", env=env)

# Step 3: Gateway Lambda tools + service role
from infra.stacks.orchestrator_stack import OrchestratorStack
orchestrator = OrchestratorStack(app, "OrchestratorStack", foundation=foundation, env=env)

# Step 5: VendorAgent Lambda tools
from infra.stacks.vendor_stack import VendorStack
vendor = VendorStack(app, "VendorStack", foundation=foundation, env=env)

# Step 7: ApprovalAgent Lambda tools
from infra.stacks.approval_stack import ApprovalStack
approval = ApprovalStack(app, "ApprovalStack", foundation=foundation, env=env)

Aspects.of(app).add(AwsSolutionsChecks())

app.synth()
