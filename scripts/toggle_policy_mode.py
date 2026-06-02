#!/usr/bin/env python3
"""
toggle_policy_mode.py — switch the ProcurementGateway Cedar policy engine
between LOG_ONLY and ENFORCE.

Usage:
    python scripts/toggle_policy_mode.py LOG_ONLY
    python scripts/toggle_policy_mode.py ENFORCE

Called directly or from the Streamlit UI sidebar to switch Cedar enforcement mode.

Phase 3 demo point:
  LOG_ONLY  → Cedar evaluates every agent tool call and logs ALLOW/DENY to
              CloudWatch, but the Lambda still executes on a DENY. This lets
              you observe what WOULD be blocked without actually blocking.
  ENFORCE   → Cedar decision is binding. A DENY stops the Lambda entirely.
              approve_payment with amount >= 500 → Cedar DENY → Lambda never runs.
"""

import os
import sys
from pathlib import Path

import boto3
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv()
load_dotenv(REPO_ROOT / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
REGION = os.environ.get("AWS_REGION", "us-east-1")
GATEWAY_ID = os.environ.get("PROCUREMENT_GATEWAY_ID", "")
POLICY_ENGINE_ID = os.environ.get("PROCUREMENT_POLICY_ENGINE_ID", "")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("LOG_ONLY", "ENFORCE"):
        sys.exit("Usage: toggle_policy_mode.py LOG_ONLY|ENFORCE")

    mode = sys.argv[1]

    if not GATEWAY_ID or not POLICY_ENGINE_ID:
        sys.exit(
            "\nERROR: PROCUREMENT_GATEWAY_ID or PROCUREMENT_POLICY_ENGINE_ID "
            "not set in .env.demo.\nRun 'make setup-procurement-gateway' first."
        )

    session = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
    client = session.client("bedrock-agentcore-control")

    # Fetch current Gateway state (UpdateGateway requires all fields)
    current = client.get_gateway(gatewayIdentifier=GATEWAY_ID)
    current_mode = current.get("policyEngineConfiguration", {}).get("mode", "none")

    if current_mode == mode:
        print(f"[toggle] ProcurementGateway already in {mode} mode — no change.")
        return

    print(f"[toggle] Switching ProcurementGateway Cedar mode: {current_mode} → {mode}")

    update_kwargs = {
        "gatewayIdentifier": GATEWAY_ID,
        "name": current["name"],
        "roleArn": current["roleArn"],
        "protocolType": current["protocolType"],
        "authorizerType": current["authorizerType"],
        "policyEngineConfiguration": {
            "arn": client.get_policy_engine(policyEngineId=POLICY_ENGINE_ID)["policyEngineArn"],
            "mode": mode,
        },
    }
    for field in ("description", "protocolConfiguration", "authorizerConfiguration"):
        if current.get(field):
            update_kwargs[field] = current[field]

    client.update_gateway(**update_kwargs)
    print(f"[toggle] Done — ProcurementGateway Cedar mode is now {mode}.")
    print(
        f"  Wait ~15s for propagation, then run:\n"
        f"    python scripts/invoke_phase3.py"
    )


if __name__ == "__main__":
    main()
