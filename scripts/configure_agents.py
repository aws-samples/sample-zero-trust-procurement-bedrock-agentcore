#!/usr/bin/env python3
"""
configure_agents.py — configure and deploy AgentCore Runtimes.

Run after `make deploy-foundation` + `make setup` so that execution role ARNs
are already written to .env.demo.

What this does:
  1. Reads FoundationStack outputs from .env.demo (execution role ARNs).
  2. Runs `agentcore configure` for each agent, binding the scoped IAM
     execution role created by FoundationStack.
  3. Runs `agentcore deploy` to package and upload the agent code.
  4. Discovers the newly created Runtime ARN via boto3.
  5. Appends runtime ARNs back to .env.demo so subsequent make targets
     (phase2, phase3, etc.) can invoke them.

Usage:
    python scripts/configure_agents.py

Prerequisites:
    - AWS_PROFILE set in environment.
    - `make deploy-foundation && make setup` have completed.
    - bedrock-agentcore-starter-toolkit installed  (pip install -r requirements.txt).
    - Python venv active.

Phase 2 note:
    The orchestrator role is deployed with AmazonDynamoDBFullAccess attached —
    that IS the Phase 2 "before" state. `make phase2` detaches it live to show
    least privilege enforcement.
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# ── Environment ────────────────────────────────────────────────────────────────

load_dotenv()
load_dotenv(Path(__file__).resolve().parent.parent / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE")
if not PROFILE_NAME:
    sys.exit(
        "ERROR: AWS_PROFILE is not set.\n"
        "Run:  export AWS_PROFILE=<your-aws-cli-profile>"
    )

REGION = os.environ.get("AWS_REGION", "us-east-1")
REPO_ROOT = Path(__file__).resolve().parent.parent

# ── Agent configurations ───────────────────────────────────────────────────────
# Each entry maps an agent directory to its execution role env-var.
# Step 2 deploys the orchestrator only.  Vendor and approval are added in
# Steps 5 and 7 respectively, after their stacks are deployed.

AGENTS = [
    {
        "name": "OrchestratorAgent",
        "dir": REPO_ROOT / "agents" / "orchestrator",
        "entrypoint": "main.py",
        "execution_role_env": "ORCHESTRATOR_EXECUTION_ROLE_ARN",
        "runtime_arn_key": "ORCHESTRATOR_RUNTIME_ARN",
        "python_runtime": "PYTHON_3_12",
        "description": "Procurement workflow orchestrator — reads invoices, routes validation to VendorAgent and payment approval to ApprovalAgent via A2A calls.",
    },
    {
        "name": "VendorAgent",
        "dir": REPO_ROOT / "agents" / "vendor",
        "entrypoint": "main.py",
        "execution_role_env": "VENDOR_EXECUTION_ROLE_ARN",
        "runtime_arn_key": "VENDOR_RUNTIME_ARN",
        "python_runtime": "PYTHON_3_12",
        "description": "Vendor validation sub-agent — verifies vendor identity and retrieves contract terms via ProcurementGateway MCP tools.",
    },
    {
        "name": "ApprovalAgent",
        "dir": REPO_ROOT / "agents" / "approval",
        "entrypoint": "main.py",
        "execution_role_env": "APPROVAL_EXECUTION_ROLE_ARN",
        "runtime_arn_key": "APPROVAL_RUNTIME_ARN",
        "python_runtime": "PYTHON_3_12",
        "description": "Payment approval sub-agent — evaluates payment requests against Cedar policy (amount < $500) via ProcurementGateway.",
    },
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_session() -> boto3.Session:
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)


def run(cmd: list[str], cwd: Path, description: str) -> str:
    """Run a subprocess command, print output in real time, return stdout."""
    print(f"\n  [run] {description}")
    print(f"        $ {' '.join(cmd)}")
    result = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit
        cmd,
        cwd=str(cwd),
        capture_output=False,
        text=True,
        env={**os.environ, "AWS_PROFILE": PROFILE_NAME},
    )
    if result.returncode != 0:
        sys.exit(f"\nERROR: command failed (exit {result.returncode})")
    return ""


def get_runtime_arn(session: boto3.Session, agent_name: str) -> str | None:
    """
    Find the Runtime ARN for a named agent via the AgentCore API.
    Polls until the runtime reaches READY state (up to ~5 minutes).
    Returns None if not found.
    """
    client = session.client("bedrock-agentcore-control", region_name=REGION)
    deadline = time.time() + 300  # 5-minute timeout

    while time.time() < deadline:
        try:
            # list_agent_runtimes does not support paginators — call directly
            next_token = None
            found = False
            while True:
                kwargs = {}
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = client.list_agent_runtimes(**kwargs)
                for runtime in resp.get("agentRuntimes", []):
                    if runtime.get("agentRuntimeName") == agent_name:
                        status = runtime.get("status", "")
                        arn = runtime["agentRuntimeArn"]
                        if status == "READY":
                            return arn
                        if status in ("CREATE_FAILED", "UPDATE_FAILED"):
                            sys.exit(
                                f"\nERROR: Runtime '{agent_name}' entered {status} state.\n"
                                "       Check CloudWatch logs for details."
                            )
                        print(f"  [runtime] {agent_name} status={status} — waiting ...")
                        found = True
                        break
                if found:
                    break
                next_token = resp.get("nextToken")
                if not next_token:
                    break

            if found:
                time.sleep(15)  # nosemgrep: arbitrary-sleep
            else:
                time.sleep(10)  # nosemgrep: arbitrary-sleep
        except ClientError as exc:
            if "ResourceNotFoundException" in str(exc):
                time.sleep(10)  # nosemgrep: arbitrary-sleep
            else:
                raise

    return None


def update_env_demo(updates: dict[str, str]) -> None:
    """
    Write or update key=value lines in .env.demo.
    Lines already present are uncommented and updated.
    New lines are appended.
    """
    path = REPO_ROOT / ".env.demo"
    if not path.exists():
        sys.exit(
            "\nERROR: .env.demo not found.\n"
            "Run 'make setup' first to create it."
        )

    text = path.read_text()
    for key, value in updates.items():
        # Match either a commented-out placeholder or an existing value line
        pattern = re.compile(rf"^#?\s*{re.escape(key)}=.*$", re.MULTILINE)
        replacement = f"{key}={value}"
        if pattern.search(text):
            text = pattern.sub(replacement, text)
        else:
            text += f"\n{replacement}\n"

    path.write_text(text)
    print(f"\n[configure] updated .env.demo")


# ── Main ───────────────────────────────────────────────────────────────────────

def configure_and_deploy(agent: dict, session: boto3.Session) -> str:
    """Configure, deploy, and return the Runtime ARN for one agent."""
    name = agent["name"]
    agent_dir = agent["dir"]
    execution_role_arn = os.environ.get(agent["execution_role_env"], "")

    print(f"\n[configure] === {name} ===")
    print(f"  dir           : {agent_dir}")
    print(f"  execution role: {execution_role_arn or '(not set — using AgentCore default)'}")

    if not agent_dir.exists():
        sys.exit(f"\nERROR: Agent directory not found: {agent_dir}")

    # Remove stale agentcore config so configure always creates a fresh runtime
    stale_yaml = agent_dir / ".bedrock_agentcore.yaml"
    if stale_yaml.exists():
        stale_yaml.unlink()
        print(f"  [configure] removed stale {stale_yaml.name} to force fresh runtime creation")

    # Build the configure command
    configure_cmd = [
        "agentcore", "configure",
        "--entrypoint", agent["entrypoint"],
        "--name", name,
        "--requirements-file", "requirements.txt",
        "--runtime", agent["python_runtime"],
        "--deployment-type", "direct_code_deploy",
        "--disable-memory",
        "--non-interactive",
    ]
    if execution_role_arn:
        configure_cmd += ["--execution-role", execution_role_arn]

    run(configure_cmd, cwd=agent_dir, description=f"configure {name}")
    run(["agentcore", "deploy"], cwd=agent_dir, description=f"deploy {name}")

    print(f"\n[configure] waiting for {name} to reach READY state ...")
    arn = get_runtime_arn(session, name)
    if not arn:
        sys.exit(
            f"\nERROR: Timed out waiting for {name} Runtime to become READY.\n"
            "       Check: aws bedrock-agentcore list-agent-runtimes"
        )

    print(f"  [runtime] READY  {arn}")

    # Set description on the runtime (visible in AgentCore console)
    description = agent.get("description", "")
    if description:
        ctrl = session.client("bedrock-agentcore-control", region_name=REGION)
        runtime_id = arn.split("/")[-1]
        try:
            current = ctrl.get_agent_runtime(agentRuntimeId=runtime_id)
            ctrl.update_agent_runtime(
                agentRuntimeId=runtime_id,
                agentRuntimeArtifact=current["agentRuntimeArtifact"],
                roleArn=current["roleArn"],
                networkConfiguration=current["networkConfiguration"],
                description=description,
            )
            print(f"  [runtime] description set")
        except ClientError as exc:
            print(f"  [runtime] warning: could not set description: {exc}")

    return arn


def inject_env_vars(session: boto3.Session, runtime_arns: dict[str, str]) -> None:
    """Push gateway URLs and sub-agent ARNs into runtime environment variables."""
    gateway_url = os.environ.get("PROCUREMENT_GATEWAY_URL", "")
    if not gateway_url:
        print("\n[configure] ⚠️  PROCUREMENT_GATEWAY_URL not set — skipping env vars.")
        print("  Run 'make setup-procurement-gateway' first, then re-run 'make configure-agents'.")
        return

    print("\n[configure] setting runtime environment variables ...")
    ctrl = session.client("bedrock-agentcore-control", region_name=REGION)

    phase5_gateway_url = os.environ.get("PHASE5_GATEWAY_URL", "")
    if not phase5_gateway_url:
        print("\n[configure] ⚠️  PHASE5_GATEWAY_URL not set — ApprovalAgent will use ProcurementGateway only.")
        print("  Run 'make setup-phase5-gateway' first if Phase 5 OBO demo is needed.")

    approval_env: dict = {"PROCUREMENT_GATEWAY_URL": gateway_url}
    if phase5_gateway_url:
        approval_env["PHASE5_GATEWAY_URL"] = phase5_gateway_url

    env_vars_per_agent = {
        "OrchestratorAgent": {
            "PROCUREMENT_GATEWAY_URL": gateway_url,
            "VENDOR_AGENT_RUNTIME_ARN": runtime_arns.get("VENDOR_RUNTIME_ARN", ""),
            "APPROVAL_AGENT_RUNTIME_ARN": runtime_arns.get("APPROVAL_RUNTIME_ARN", ""),
        },
        "VendorAgent": {
            "PROCUREMENT_GATEWAY_URL": gateway_url,
        },
        "ApprovalAgent": approval_env,
    }

    for agent_name, env_vars in env_vars_per_agent.items():
        arn_key = None
        for a in AGENTS:
            if a["name"] == agent_name:
                arn_key = a["runtime_arn_key"]
                break
        arn = runtime_arns.get(arn_key, "") if arn_key else ""
        if not arn:
            print(f"  [env] {agent_name}: SKIP — runtime ARN not found (key={arn_key})")
            continue
        runtime_id = arn.split("/")[-1]

        # Wait for runtime to be READY before updating env vars
        for attempt in range(12):
            try:
                current = ctrl.get_agent_runtime(agentRuntimeId=runtime_id)
                if current.get("status") == "READY":
                    break
                print(f"  [env] {agent_name}: waiting for READY (status={current.get('status')}) ...")
                time.sleep(10)  # nosemgrep: arbitrary-sleep
            except ClientError:
                time.sleep(10)  # nosemgrep: arbitrary-sleep
        else:
            print(f"  [env] {agent_name}: WARNING — runtime not READY after 2 min, skipping")
            continue

        try:
            update_kwargs = dict(
                agentRuntimeId=runtime_id,
                agentRuntimeArtifact=current["agentRuntimeArtifact"],
                roleArn=current["roleArn"],
                networkConfiguration=current["networkConfiguration"],
                environmentVariables=env_vars,
            )
            desc = current.get("description", "")
            if desc:
                update_kwargs["description"] = desc
            ctrl.update_agent_runtime(**update_kwargs)
            print(f"  [env] {agent_name}: {list(env_vars.keys())}")
        except ClientError as exc:
            print(f"  [env] {agent_name}: ERROR — {exc}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inject-only",
        action="store_true",
        help="Skip configure/deploy; only push gateway URLs to existing runtimes.",
    )
    args = parser.parse_args()

    print(f"[configure] profile={PROFILE_NAME}  region={REGION}")

    session = get_session()

    if args.inject_only:
        # Read existing Runtime ARNs from .env.demo
        runtime_arns = {
            a["runtime_arn_key"]: os.environ.get(a["runtime_arn_key"], "")
            for a in AGENTS
        }
        missing = [k for k, v in runtime_arns.items() if not v]
        if missing:
            sys.exit(
                f"\nERROR: Runtime ARNs not found in .env.demo: {missing}\n"
                "Run 'make configure-agents' (without --inject-only) first."
            )
        print("[configure] --inject-only: skipping configure/deploy, pushing env vars only.")
        inject_env_vars(session, runtime_arns)
        print("\n[configure] done (inject-only).")
        return

    runtime_arns: dict[str, str] = {}
    for agent in AGENTS:
        arn = configure_and_deploy(agent, session)
        runtime_arns[agent["runtime_arn_key"]] = arn

    update_env_demo(runtime_arns)
    inject_env_vars(session, runtime_arns)

    print("\n[configure] done.")
    print("  Runtime ARNs written to .env.demo.")
    gateway_url = os.environ.get("PROCUREMENT_GATEWAY_URL", "")
    if not gateway_url:
        print("  Next: run 'make setup-procurement-gateway' then 'make inject-gateway-urls' to push gateway URLs.")


if __name__ == "__main__":
    main()
