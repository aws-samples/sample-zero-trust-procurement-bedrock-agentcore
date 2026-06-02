#!/usr/bin/env python3
"""
teardown_agentcore.py — delete all AgentCore resources created by this demo.

CDK destroy removes the Lambda, IAM, Cognito, and DynamoDB resources but does
NOT touch AgentCore resources (runtimes, gateways, policy engines, workload
identities). This script deletes those.

Deletion order matters — dependents must go before their dependencies:
  1. Resource policies on runtimes    (no API dep, but clean)
  2. Agent runtimes                   (depend on execution roles)
  3. Gateway targets                  (belong to gateways)
  4. Gateways                         (depend on policy engines)
  5. Policies                         (belong to policy engines)
  6. Policy engines                   (independent)
  7. Workload identities              (independent)

All operations are idempotent — safe to re-run if a previous run was interrupted.

Usage:
    python scripts/teardown_agentcore.py
    make destroy   (runs this script then cdk destroy)
"""

import os
import sys
import time
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


# ── Clients ────────────────────────────────────────────────────────────────────

def _session() -> boto3.Session:
    return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)


def _control():
    return _session().client("bedrock-agentcore-control")


def _runtime():
    return _session().client("bedrock-agentcore")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _delete(label: str, fn, *args, not_found_codes=("ResourceNotFoundException",), **kwargs):
    """Call fn(*args, **kwargs), treating not-found as already-done."""
    try:
        fn(*args, **kwargs)
        print(f"  [deleted] {label}")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in not_found_codes:
            print(f"  [skip]    {label} — already gone")
        else:
            print(f"  [error]   {label} — {code}: {exc.response['Error']['Message']}")


def _poll_deleted(label: str, get_fn, interval: int = 10, timeout: int = 300):
    """Wait until get_fn raises ResourceNotFoundException."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            get_fn()
            print(f"  [wait]    {label} still deleting ...")
            time.sleep(interval)  # nosemgrep: arbitrary-sleep
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "ResourceNotFoundException", "ValidationException"
            ):
                return
            raise
    print(f"  [timeout] {label} did not finish deleting within {timeout}s")


# ── 1. Runtime resource policies ──────────────────────────────────────────────

def delete_resource_policies(ctrl) -> None:
    print("\n[step 1] removing runtime resource policies ...")
    for env_key, label in [
        ("ORCHESTRATOR_RUNTIME_ARN", "OrchestratorAgent"),
        ("VENDOR_RUNTIME_ARN",       "VendorAgent"),
        ("APPROVAL_RUNTIME_ARN",     "ApprovalAgent"),
    ]:
        arn = os.environ.get(env_key, "")
        if not arn:
            print(f"  [skip]    {label} — {env_key} not set")
            continue
        _delete(
            f"resource policy on {label}",
            ctrl.delete_resource_policy,
            resourceArn=arn,
            not_found_codes=("ResourceNotFoundException", "NoSuchResourcePolicyException"),
        )


# ── 2. Agent runtimes ─────────────────────────────────────────────────────────

def delete_runtimes(ctrl) -> None:
    print("\n[step 2] deleting agent runtimes ...")
    try:
        runtimes = ctrl.list_agent_runtimes().get("agentRuntimes", [])
    except ClientError as exc:
        print(f"  [error]   list_agent_runtimes — {exc}")
        return

    demo_names = {"OrchestratorAgent", "VendorAgent", "ApprovalAgent"}
    found = [rt for rt in runtimes if rt.get("agentRuntimeName") in demo_names]

    if not found:
        print("  [skip]    no demo runtimes found")
        return

    for rt in found:
        name = rt["agentRuntimeName"]
        rt_id = rt["agentRuntimeId"]
        _delete(
            f"runtime {name} ({rt_id})",
            ctrl.delete_agent_runtime,
            agentRuntimeId=rt_id,
        )

    # Wait for all deletions to complete before moving on
    for rt in found:
        name = rt["agentRuntimeName"]
        rt_id = rt["agentRuntimeId"]
        _poll_deleted(
            f"runtime {name}",
            lambda i=rt_id: ctrl.get_agent_runtime(agentRuntimeId=i),
        )


# ── 3 + 4. Gateway targets then gateways ─────────────────────────────────────

def _delete_gateway(ctrl, gw_id: str, gw_name: str) -> None:
    """Delete all targets under a gateway, then the gateway itself."""
    print(f"\n  [gateway] deleting targets for {gw_name} ({gw_id}) ...")
    try:
        targets = ctrl.list_gateway_targets(gatewayIdentifier=gw_id).get("items", [])
    except ClientError as exc:
        print(f"  [error]   list_gateway_targets — {exc}")
        targets = []

    for tgt in targets:
        tgt_id = tgt["targetId"]
        tgt_name = tgt.get("name", tgt_id)
        _delete(
            f"target {tgt_name}",
            ctrl.delete_gateway_target,
            gatewayIdentifier=gw_id,
            targetId=tgt_id,
        )
        _poll_deleted(
            f"target {tgt_name}",
            lambda gi=gw_id, ti=tgt_id: ctrl.get_gateway_target(
                gatewayIdentifier=gi, targetId=ti
            ),
        )

    _delete(
        f"gateway {gw_name}",
        ctrl.delete_gateway,
        gatewayIdentifier=gw_id,
    )
    _poll_deleted(
        f"gateway {gw_name}",
        lambda gi=gw_id: ctrl.get_gateway(gatewayIdentifier=gi),
    )


def delete_gateways(ctrl) -> None:
    print("\n[step 3+4] deleting gateway targets and gateways ...")
    try:
        gateways = ctrl.list_gateways().get("items", [])
    except ClientError as exc:
        print(f"  [error]   list_gateways — {exc}")
        return

    demo_gw_names = {"ProcurementGateway", "Phase5ApprovalGateway"}
    found = [gw for gw in gateways if gw.get("name") in demo_gw_names]

    if not found:
        print("  [skip]    no demo gateways found")
        return

    for gw in found:
        _delete_gateway(ctrl, gw["gatewayId"], gw["name"])


# ── 5 + 6. Policies then policy engines ───────────────────────────────────────

def _delete_policy_engine(ctrl, pe_id: str, pe_name: str) -> None:
    """Delete all policies under a policy engine, then the engine itself."""
    print(f"\n  [policy-engine] deleting policies for {pe_name} ({pe_id}) ...")
    try:
        policies = ctrl.list_policies(policyEngineId=pe_id).get("policies", [])
    except ClientError as exc:
        print(f"  [error]   list_policies — {exc}")
        policies = []

    for pol in policies:
        pol_id = pol["policyId"]
        pol_name = pol.get("name", pol_id)
        _delete(
            f"policy {pol_name}",
            ctrl.delete_policy,
            policyEngineId=pe_id,
            policyId=pol_id,
        )
        _poll_deleted(
            f"policy {pol_name}",
            lambda ei=pe_id, pi=pol_id: ctrl.get_policy(
                policyEngineId=ei, policyId=pi
            ),
        )

    _delete(
        f"policy engine {pe_name}",
        ctrl.delete_policy_engine,
        policyEngineId=pe_id,
    )
    _poll_deleted(
        f"policy engine {pe_name}",
        lambda ei=pe_id: ctrl.get_policy_engine(policyEngineId=ei),
    )


def delete_policy_engines(ctrl) -> None:
    print("\n[step 5+6] deleting policies and policy engines ...")
    try:
        engines = ctrl.list_policy_engines().get("policyEngines", [])
    except ClientError as exc:
        print(f"  [error]   list_policy_engines — {exc}")
        return

    demo_pe_names = {"ProcurementPolicyEngine", "Phase5PolicyEngine"}
    found = [pe for pe in engines if pe.get("name") in demo_pe_names]

    if not found:
        print("  [skip]    no demo policy engines found")
        return

    for pe in found:
        _delete_policy_engine(ctrl, pe["policyEngineId"], pe["name"])


# ── 7. Workload identities ─────────────────────────────────────────────────────

def delete_workload_identities(ctrl) -> None:
    print("\n[step 7] deleting workload identities ...")
    demo_wi_names = {"OrchestratorAgent", "VendorAgent", "ApprovalAgent"}
    for name in demo_wi_names:
        try:
            wi = ctrl.get_workload_identity(name=name)
            arn = wi["workloadIdentityArn"]
            _delete(
                f"workload identity {name}",
                ctrl.delete_workload_identity,
                name=name,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                print(f"  [skip]    workload identity {name} — already gone")
            else:
                print(f"  [error]   workload identity {name} — {exc}")


# ── 8. Local agentcore config files ───────────────────────────────────────────

def delete_local_agentcore_configs() -> None:
    """Remove .bedrock_agentcore.yaml files so a fresh deploy creates new runtimes."""
    print("\n[step 8] removing local agentcore config files ...")
    for agent_dir in ["orchestrator", "vendor", "approval"]:
        yaml_path = REPO_ROOT / "agents" / agent_dir / ".bedrock_agentcore.yaml"
        if yaml_path.exists():
            yaml_path.unlink()
            print(f"  [deleted] {yaml_path.relative_to(REPO_ROOT)}")
        else:
            print(f"  [skip]    agents/{agent_dir}/.bedrock_agentcore.yaml — not found")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"[teardown-agentcore] profile={PROFILE_NAME}  region={REGION}")
    print(
        "\n  Deleting AgentCore resources in dependency order:\n"
        "  resource policies → runtimes → gateway targets → gateways\n"
        "  → policies → policy engines → workload identities\n"
    )

    ctrl = _control()

    delete_resource_policies(ctrl)
    delete_runtimes(ctrl)
    delete_gateways(ctrl)
    delete_policy_engines(ctrl)
    delete_workload_identities(ctrl)
    delete_local_agentcore_configs()

    print("\n[teardown-agentcore] done.")
    print("  All AgentCore resources removed. CDK destroy will handle the rest.")


if __name__ == "__main__":
    main()
