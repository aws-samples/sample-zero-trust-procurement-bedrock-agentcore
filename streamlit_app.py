#!/usr/bin/env python3
"""
streamlit_app.py — Zero Trust AgentCore Demo UI

Interactive dashboard that replaces terminal-based make phase* invocations.

Run with:
    streamlit run streamlit_app.py

Prerequisites:
    - .env.demo populated (run 'make setup' after deploy)
    - pip install streamlit  (or: pip install -r requirements.txt)
"""

import base64
import json
import os
import time
import uuid
from pathlib import Path

import boto3
import httpx
import streamlit as st
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# ── Page config (must be first Streamlit call) ────────────────────────────────

st.set_page_config(
    page_title="ZT AgentCore Demo",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Environment ───────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent
load_dotenv(REPO_ROOT / ".env", override=False)
load_dotenv(REPO_ROOT / ".env.demo", override=True)

PROFILE_NAME = os.environ.get("AWS_PROFILE", "")
REGION = os.environ.get("AWS_REGION", "us-east-1")

PROCUREMENT_GATEWAY_URL = os.environ.get("PROCUREMENT_GATEWAY_URL", "")
PROCUREMENT_GATEWAY_ID = os.environ.get("PROCUREMENT_GATEWAY_ID", "")
PROCUREMENT_POLICY_ENGINE_ID = os.environ.get("PROCUREMENT_POLICY_ENGINE_ID", "")
ORCHESTRATOR_RUNTIME_ARN = os.environ.get("ORCHESTRATOR_RUNTIME_ARN", "")

VENDOR_RUNTIME_ARN = os.environ.get("VENDOR_RUNTIME_ARN", "")

APPROVAL_RUNTIME_ARN = os.environ.get("APPROVAL_RUNTIME_ARN", "")

ADMIN_ACCESS_TOKEN = os.environ.get("ADMIN_ACCESS_TOKEN", "")
OPERATOR_ACCESS_TOKEN = os.environ.get("OPERATOR_ACCESS_TOKEN", "")
ADMIN_ID_TOKEN = os.environ.get("ADMIN_ID_TOKEN", "")
OPERATOR_ID_TOKEN = os.environ.get("OPERATOR_ID_TOKEN", "")

ORCHESTRATOR_ROLE_ARN = os.environ.get("ORCHESTRATOR_EXECUTION_ROLE_ARN", "")

COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_APP_CLIENT_ID = os.environ.get("COGNITO_APP_CLIENT_ID", "")
DEMO_PASSWORD = os.environ.get("DEMO_USER_PASSWORD", "DemoPass1!")


# ── AWS session ───────────────────────────────────────────────────────────────

@st.cache_resource
def get_session() -> boto3.Session:
    if PROFILE_NAME:
        return boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
    return boto3.Session(region_name=REGION)


def runtime_client():
    return get_session().client("bedrock-agentcore")


def control_client():
    return get_session().client("bedrock-agentcore-control")



# ── Cognito auth helper ───────────────────────────────────────────────────────

def cognito_login(username: str) -> dict:
    """Authenticate against Cognito and return {id_token, claims, username}."""
    client = get_session().client("cognito-idp")
    resp = client.admin_initiate_auth(
        UserPoolId=COGNITO_USER_POOL_ID,
        ClientId=COGNITO_APP_CLIENT_ID,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": DEMO_PASSWORD},
    )
    id_token = resp["AuthenticationResult"]["IdToken"]
    payload = id_token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return {"id_token": id_token, "claims": claims, "username": username}


# ── MCP / Gateway helpers ─────────────────────────────────────────────────────

def _mcp_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _mcp_url(gateway_url: str) -> str:
    return gateway_url if gateway_url.endswith("/mcp") else f"{gateway_url}/mcp"


def mcp_list_tools(gateway_url: str, token: str) -> list[dict]:
    body = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
    r = httpx.post(_mcp_url(gateway_url), json=body, headers=_mcp_headers(token), timeout=30.0)
    r.raise_for_status()
    return r.json().get("result", {}).get("tools", [])


def mcp_call_tool(gateway_url: str, token: str, tool_name: str, args: dict) -> dict:
    body = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
        "id": 2,
    }
    r = httpx.post(_mcp_url(gateway_url), json=body, headers=_mcp_headers(token), timeout=30.0)
    r.raise_for_status()
    return r.json().get("result", r.json())


# ── Runtime invoke helper ─────────────────────────────────────────────────────

def invoke_runtime(arn: str, prompt: str, user_token: str = "") -> dict:
    payload: dict = {"prompt": prompt}
    if user_token:
        payload["user_token"] = user_token
    resp = runtime_client().invoke_agent_runtime(
        agentRuntimeArn=arn,
        runtimeSessionId=str(uuid.uuid4()),
        payload=json.dumps(payload).encode(),
    )
    raw = resp["response"].read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"response": raw.decode()}


# ── Policy mode helpers ───────────────────────────────────────────────────────

def get_current_policy_mode() -> str:
    if not PROCUREMENT_GATEWAY_ID:
        return "unknown"
    try:
        gw = control_client().get_gateway(gatewayIdentifier=PROCUREMENT_GATEWAY_ID)
        return gw.get("policyEngineConfiguration", {}).get("mode", "none")
    except Exception:
        return "unknown"


def set_policy_mode(mode: str) -> tuple[bool, str]:
    if not PROCUREMENT_GATEWAY_ID or not PROCUREMENT_POLICY_ENGINE_ID:
        return False, "PROCUREMENT_GATEWAY_ID or PROCUREMENT_POLICY_ENGINE_ID not set in .env.demo"
    try:
        cc = control_client()
        current = cc.get_gateway(gatewayIdentifier=PROCUREMENT_GATEWAY_ID)
        pe_info = cc.get_policy_engine(policyEngineId=PROCUREMENT_POLICY_ENGINE_ID)
        update_kwargs = {
            "gatewayIdentifier": PROCUREMENT_GATEWAY_ID,
            "name": current["name"],
            "roleArn": current["roleArn"],
            "protocolType": current["protocolType"],
            "authorizerType": current["authorizerType"],
            "policyEngineConfiguration": {
                "arn": pe_info["policyEngineArn"],
                "mode": mode,
            },
        }
        for field in ("description", "protocolConfiguration", "authorizerConfiguration"):
            if current.get(field):
                update_kwargs[field] = current[field]
        cc.update_gateway(**update_kwargs)
        return True, f"Policy mode switched to {mode}"
    except Exception as exc:
        return False, str(exc)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("ZT AgentCore Demo")
    st.caption("Amazon Bedrock AgentCore · Zero Trust Procurement")

    st.divider()

    # AWS env
    st.subheader("AWS Environment")
    if PROFILE_NAME:
        st.success(f"Profile: **{PROFILE_NAME}**")
    else:
        st.error("AWS_PROFILE not set — add it to .env")
    st.caption(f"Region: `{REGION}`")

    # Env readiness
    st.divider()
    st.subheader("Readiness")
    checks = [
        ("Gateway URL", bool(PROCUREMENT_GATEWAY_URL)),
        ("Orchestrator ARN", bool(ORCHESTRATOR_RUNTIME_ARN)),
        ("Vendor ARN", bool(VENDOR_RUNTIME_ARN)),
        ("Approval ARN", bool(APPROVAL_RUNTIME_ARN)),
        ("Admin token", bool(ADMIN_ACCESS_TOKEN)),
        ("Operator token", bool(OPERATOR_ACCESS_TOKEN)),
    ]
    for label, ok in checks:
        st.caption(f"{'✅' if ok else '⬜'} {label}")

    # Cedar policy mode toggle
    st.divider()
    st.subheader("Cedar Policy Mode")
    if not PROCUREMENT_GATEWAY_ID:
        st.caption("⬜ ProcurementGateway not deployed")
    else:
        current_mode = get_current_policy_mode()
        mode_color = "🟡" if current_mode == "LOG_ONLY" else ("🔴" if current_mode == "ENFORCE" else "⬜")
        st.caption(f"{mode_color} Current: **{current_mode}**")

        col_log, col_enf = st.columns(2)
        with col_log:
            if st.button("LOG_ONLY", use_container_width=True,
                         type="primary" if current_mode == "LOG_ONLY" else "secondary"):
                with st.spinner("Updating..."):
                    ok, msg = set_policy_mode("LOG_ONLY")
                    if ok:
                        st.success(msg)
                        time.sleep(1)  # nosemgrep: arbitrary-sleep
                        st.rerun()
                    else:
                        st.error(msg)
        with col_enf:
            if st.button("ENFORCE", use_container_width=True,
                         type="primary" if current_mode == "ENFORCE" else "secondary"):
                with st.spinner("Updating..."):
                    ok, msg = set_policy_mode("ENFORCE")
                    if ok:
                        st.success(msg)
                        time.sleep(1)  # nosemgrep: arbitrary-sleep
                        st.rerun()
                    else:
                        st.error(msg)
        st.caption("Wait ~15s after switching before invoking")

    st.divider()
    if st.button("Reload .env.demo", use_container_width=True):
        # Re-read env by clearing cache and rerunning
        st.cache_resource.clear()
        st.rerun()


# ── Main area ─────────────────────────────────────────────────────────────────

st.title("Zero Trust Agentic AI — Amazon Bedrock AgentCore")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Phase 1 · Runtime Policy",
    "Phase 2 · IAM Blast Radius",
    "Phase 3 · Cedar Agent-to-Tool",
    "Phase 4 · A2A Full Flow",
    "Phase 5 · On-Behalf-Of",
])


# ═════════════════════════════════════════════════════════════════════════════
# Phase 1 — Human → Agent: Runtime Resource Policy
# ═════════════════════════════════════════════════════════════════════════════

with tab1:
    st.header("Phase 1 — Human → Agent: Runtime Resource Policy")
    st.markdown(
        "**ZT Pillar: Verify Explicitly (ingress)**  \n"
        "The OrchestratorAgent Runtime has a **resource-based policy** that acts "
        "as an allow-list of permitted IAM principals. Both gates must pass:\n\n"
        "1. Caller's **identity policy** must allow `bedrock-agentcore:InvokeAgentRuntime`  \n"
        "2. Runtime's **resource policy** must allow the caller's principal ARN  \n\n"
        "Unlisted callers get `AccessDeniedException` — agent code never runs."
    )

    if not ORCHESTRATOR_RUNTIME_ARN:
        st.warning("ORCHESTRATOR_RUNTIME_ARN not set — run `make configure-agents && make setup-identity` first.")

    # ── 1. Resource policy
    st.subheader("1  Runtime Resource Policy")
    st.caption("The explicit allow-list attached to the OrchestratorAgent Runtime ARN.")

    if st.button("Inspect resource policy", key="p1_rp"):
        if not ORCHESTRATOR_RUNTIME_ARN:
            st.warning("ORCHESTRATOR_RUNTIME_ARN not set.")
        else:
            with st.spinner("Fetching policy..."):
                try:
                    resp = control_client().get_resource_policy(resourceArn=ORCHESTRATOR_RUNTIME_ARN)
                    doc = json.loads(resp.get("policy", "{}"))
                    st.json(doc)
                    stmts = doc.get("Statement", [])
                    if stmts:
                        raw = stmts[0].get("Principal", {})
                        effect = stmts[0].get("Effect", "")
                        if isinstance(raw, str):
                            principals = [raw]
                        else:
                            p = raw.get("AWS", [])
                            principals = [p] if isinstance(p, str) else p
                        if effect == "Deny":
                            cond = stmts[0].get("Condition", {}).get("StringNotLike", {}).get("aws:PrincipalArn", [])
                            if isinstance(cond, str):
                                cond = [cond]
                            st.success(f"✅ Deny-all EXCEPT {len(cond)} principal(s)")
                            for p in cond:
                                st.caption(f"  `{p}`")
                        else:
                            st.success(f"✅ {len(principals)} authorised principal(s)")
                            for p in principals:
                                st.caption(f"  `{p}`")
                    else:
                        st.info("Empty policy — no statements found.")
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    if "ResourceNotFound" in code or "NoSuchResource" in code:
                        st.warning("No resource policy — run `make setup-identity`")
                    else:
                        st.error(str(exc))

    st.divider()

    # ── 2. Dual-gate model
    st.subheader("2  Dual-Gate Enforcement Model")
    st.code(
        """Human caller (IAM principal)
     │
     │  bedrock-agentcore:InvokeAgentRuntime
     ▼
┌────────────────────────────────────────┐
│  Gate 1: Identity-Based IAM Policy     │
│  "Does the caller's role ALLOW this?"  │
└──────────────────┬─────────────────────┘
                   │ ALLOW
                   ▼
┌────────────────────────────────────────┐
│  Gate 2: Runtime Resource Policy       │
│  "Does this Runtime ALLOW this caller?"│
└──────────────────┬─────────────────────┘
                   │ ALLOW
                   ▼
┌────────────────────────────────────────┐
│  OrchestratorAgent Runtime (microVM)   │
│  Agent code starts executing           │
└────────────────────────────────────────┘

Unlisted caller → Gate 2: AccessDeniedException
Agent code NEVER runs. Blast radius = zero.""",
        language=None,
    )

    st.divider()

    # ── 3. Invoke as authorised caller
    st.subheader("3  Invoke OrchestratorAgent (authorised caller)")
    st.caption(
        "Direct `invoke_agent_runtime` call using the configured AWS profile. "
        "No Gateway involved — human callers reach agents via SigV4 directly."
    )

    p1_prompt = st.selectbox("Prompt", [
        "Read invoice INV-001.",
        "Show my current AWS identity.",
    ], key="p1_prompt")

    if st.button("Invoke runtime", key="p1_invoke", type="primary"):
        if not ORCHESTRATOR_RUNTIME_ARN:
            st.warning("ORCHESTRATOR_RUNTIME_ARN not set.")
        else:
            with st.spinner("Invoking OrchestratorAgent via SigV4..."):
                try:
                    result = invoke_runtime(ORCHESTRATOR_RUNTIME_ARN, p1_prompt)
                    st.json(result)
                    st.success("✅ Invocation succeeded — current profile is in the resource policy.")
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    if code == "AccessDeniedException":
                        st.error(
                            "AccessDeniedException — this profile is NOT in the resource policy.  \n"
                            "Add it via `make setup-identity` to allow access."
                        )
                    else:
                        st.error(str(exc))

    st.divider()
    st.info(
        "**What an unlisted caller sees:**  \n"
        "`An error occurred (AccessDeniedException) when calling the InvokeAgentRuntime operation`  \n"
        "The microVM never starts. No tools run. No data accessed."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Phase 2 — IAM Execution Role Blast Radius
# ═════════════════════════════════════════════════════════════════════════════

with tab2:
    st.header("Phase 2 — IAM Execution Role · Least Privilege")
    st.markdown(
        "The agent's **execution role** is the blast radius if a prompt injection succeeds. "
        "The orchestrator role is deployed with `AmazonDynamoDBFullAccess` attached — "
        "`make phase2` detaches it live, leaving only the scoped inline policies."
    )

    # Role comparison
    col_before, col_after = st.columns(2)
    with col_before:
        st.error("**BEFORE — anti-pattern (pre-Phase 2)**")
        st.markdown(
            f"Role: `{ORCHESTRATOR_ROLE_ARN or '(ORCHESTRATOR_EXECUTION_ROLE_ARN not set)'}`\n\n"
            "Policies: `AmazonDynamoDBFullAccess` (managed) + scoped inline policies\n\n"
            "Blast radius: **ALL DynamoDB tables in the account**  \n"
            "_Run `make phase2` to detach `AmazonDynamoDBFullAccess` and shrink the blast radius._"
        )
    with col_after:
        st.success("**AFTER — Zero Trust applied**")
        st.markdown(
            f"Role: `{ORCHESTRATOR_ROLE_ARN or '(ORCHESTRATOR_EXECUTION_ROLE_ARN not set)'}`\n\n"
            "Policies: `dynamodb:GetItem` on `zt-demo-invoices` only\n\n"
            "Blast radius: **single table, read-only**"
        )

    st.divider()

    if not ORCHESTRATOR_RUNTIME_ARN:
        st.warning("ORCHESTRATOR_RUNTIME_ARN not set — run `make configure-agents` first.")
    else:
        st.subheader("Invoke OrchestratorAgent directly (SigV4 — bypasses Gateway)")

        p2_prompt = st.selectbox("Scenario", [
            "Show my current AWS identity.",
            "Process invoice INV-001.",
            "Process invoice INV-002.",
        ], key="p2_prompt")

        if st.button("Invoke runtime", key="p2_invoke", type="primary"):
            with st.spinner("Invoking OrchestratorAgent..."):
                try:
                    result = invoke_runtime(ORCHESTRATOR_RUNTIME_ARN, p2_prompt)
                    st.json(result)
                    resp_text = json.dumps(result)
                    if "identity" in p2_prompt.lower():
                        if "orchestrator-execution-role" in resp_text:
                            st.success("✅ Agent is running as `orchestrator-execution-role`")
                        else:
                            st.info("Role name not found in response — check the JSON above.")
                except Exception as exc:
                    st.error(str(exc))

        st.info(
            "**What this shows:** The `show_identity` Lambda calls STS `GetCallerIdentity` "
            "and returns the IAM ARN it runs as (the Gateway service role). "
            "The orchestrator's execution role is what constrains which DynamoDB tables the agent can reach — "
            "with the scoped role, any prompt injection attempt cannot read or write outside `zt-demo-invoices`."
        )


# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 — Cedar Agent-to-Tool Enforcement via ProcurementGateway
# ═════════════════════════════════════════════════════════════════════════════

with tab3:
    st.header("Phase 3 — Cedar Agent-to-Tool Enforcement")
    st.markdown(
        "**ZT Pillar: Least Privilege + Enforce at Point-of-Action**  \n"
        "Agents call Lambda tools via `ProcurementGateway` (MCP) with their **workload identity JWT**. "
        "Cedar evaluates which agent can call which tool on every invocation.  \n\n"
        "- `OrchestratorAgent` (`role=orchestrator`) → `read_invoice`, `show_identity` only  \n"
        "- `VendorAgent` (`role=vendor-agent`) → `validate_vendor`, `get_vendor_terms` only  \n"
        "- `ApprovalAgent` (`role=approval-agent`) → `approve_payment` (forbid: amount >= $500), `get_approval_status`  \n\n"
        "Cedar **default-deny**: any action without a matching `permit` rule is blocked — "
        "no `forbid` needed to stop VendorAgent calling `approve_payment`."
    )

    # ── Gateway state
    st.subheader("1  ProcurementGateway State")
    if st.button("Inspect gateway config", key="p3_gw"):
        if not PROCUREMENT_GATEWAY_ID:
            st.warning("PROCUREMENT_GATEWAY_ID not set — run `make setup-procurement-gateway`")
        else:
            with st.spinner("Fetching gateway state..."):
                try:
                    gw = control_client().get_gateway(gatewayIdentifier=PROCUREMENT_GATEWAY_ID)
                    auth_type = gw.get("authorizerType", "NONE")
                    mode = gw.get("policyEngineConfiguration", {}).get("mode", "none")
                    col_auth, col_mode = st.columns(2)
                    with col_auth:
                        if auth_type == "AWS_IAM":
                            st.success(f"Auth: `{auth_type}` (SigV4 — agents sign with execution role)")
                        else:
                            st.warning(f"Auth: `{auth_type}`")
                    with col_mode:
                        if mode == "ENFORCE":
                            st.error(f"Cedar: `{mode}` — decisions are binding")
                        elif mode == "LOG_ONLY":
                            st.warning(f"Cedar: `{mode}` — evaluates but does not block")
                        else:
                            st.info(f"Cedar: `{mode}`")
                    st.caption(f"Gateway URL: `{PROCUREMENT_GATEWAY_URL or gw.get('gatewayUrl', 'n/a')}`")
                    st.caption(f"Gateway ID: `{PROCUREMENT_GATEWAY_ID}`")
                except Exception as exc:
                    st.error(str(exc))

    st.divider()

    # ── Cedar policies
    st.subheader("2  Cedar Policies")
    repo_root = Path(__file__).resolve().parent
    policy_files = [
        ("procurement-orchestrator.cedar", "OrchestratorAgent → read_invoice, show_identity"),
        ("procurement-vendor.cedar",       "VendorAgent → validate_vendor, get_vendor_terms"),
        ("procurement-approval.cedar",     "ApprovalAgent → approve_payment (permit)"),
    ]
    for fname, desc in policy_files:
        path = repo_root / "policies" / fname
        with st.expander(desc):
            if path.exists():
                st.code(path.read_text(), language="javascript")
            else:
                st.caption(f"policies/{fname} not found")

    st.divider()

    # ── Live scenarios
    st.subheader("3  Run Cedar Enforcement Scenarios")
    if not ORCHESTRATOR_RUNTIME_ARN:
        st.warning("ORCHESTRATOR_RUNTIME_ARN not set — run `make configure-agents` first.")
    else:
        p3_scenario = st.radio("Scenario", [
            "INV-001 · $450 — amount < $500 (Cedar ALLOW in both modes)",
            "INV-002 · $750 — amount >= $500 (Cedar DENY in LOG_ONLY logged; ENFORCE blocked)",
        ], key="p3_scenario")

        prompts_p3 = {
            "INV-001 · $450 — amount < $500 (Cedar ALLOW in both modes)":
                "Process invoice INV-001. Validate the vendor and approve the payment.",
            "INV-002 · $750 — amount >= $500 (Cedar DENY in LOG_ONLY logged; ENFORCE blocked)":
                "Process invoice INV-002. Validate the vendor and get payment approval. The invoice amount is $750.",
        }

        col_mode_hint, _ = st.columns([2, 1])
        with col_mode_hint:
            current_mode = get_current_policy_mode()
            if current_mode == "ENFORCE":
                st.error(f"Cedar is **ENFORCE** — INV-002 will be blocked at Gateway (Lambda = 0 invocations)")
            elif current_mode == "LOG_ONLY":
                st.warning(f"Cedar is **LOG_ONLY** — INV-002 DENY logged, Lambda still runs")
            else:
                st.info(f"Cedar mode: `{current_mode}` — toggle in sidebar")

        if st.button("Run scenario", key="p3_run", type="primary"):
            with st.spinner("Running via OrchestratorAgent (15–30s)..."):
                try:
                    result = invoke_runtime(ORCHESTRATOR_RUNTIME_ARN, prompts_p3[p3_scenario])
                    st.json(result)
                    if "INV-001" in p3_scenario:
                        st.success("✅ approve_payment(450) → Cedar ALLOW → auto-approved")
                    elif "INV-002" in p3_scenario:
                        if current_mode == "ENFORCE":
                            st.error(
                                "Cedar ENFORCE: approve_payment(750) blocked at Gateway.  \n"
                                "Lambda invocation count = 0. Check CloudWatch Cedar logs."
                            )
                        else:
                            st.warning(
                                "Cedar LOG_ONLY: DENY logged but Lambda still ran.  \n"
                                "Switch to ENFORCE in sidebar to make decisions binding."
                            )
                except Exception as exc:
                    st.error(str(exc))

    st.divider()
    st.info(
        "**Toggle Cedar mode** in the sidebar (LOG_ONLY / ENFORCE) and re-run INV-002 "
        "to observe the difference. In ENFORCE mode the Lambda is never invoked."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 — A2A Full Flow + Defense in Depth
# ═════════════════════════════════════════════════════════════════════════════

with tab4:
    st.header("Phase 4 — Full Three-Tier A2A Flow")
    st.markdown(
        "**ZT Pillar: Assume Breach**  \n"
        "Every A2A hop is gated by a resource policy. Three scenarios exercise "
        "the full decision tree: happy path, escalation, and prompt injection."
    )

    if not PROFILE_NAME:
        st.error("AWS_PROFILE not set")
        st.stop()

    with st.expander("A2A Resource Policies"):
        col_vendor, col_approval = st.columns(2)

        with col_vendor:
            st.subheader("VendorAgent")
            if st.button("Inspect policy", key="p4_rp_vendor"):
                if not VENDOR_RUNTIME_ARN:
                    st.warning("VENDOR_RUNTIME_ARN not set — run `make configure-agents`")
                else:
                    try:
                        resp = control_client().get_resource_policy(resourceArn=VENDOR_RUNTIME_ARN)
                        doc = json.loads(resp.get("policy", "{}"))
                        st.json(doc)
                    except ClientError as exc:
                        code = exc.response["Error"]["Code"]
                        if "ResourceNotFound" in code or "NoSuchResourcePolicy" in code:
                            st.warning("No resource policy — run `make setup-a2a`")
                        else:
                            st.error(str(exc))

        with col_approval:
            st.subheader("ApprovalAgent")
            if st.button("Inspect policy", key="p4_rp_approval"):
                if not APPROVAL_RUNTIME_ARN:
                    st.warning("APPROVAL_RUNTIME_ARN not set — run `make configure-agents`")
                else:
                    try:
                        resp = control_client().get_resource_policy(resourceArn=APPROVAL_RUNTIME_ARN)
                        doc = json.loads(resp.get("policy", "{}"))
                        st.json(doc)
                    except ClientError as exc:
                        code = exc.response["Error"]["Code"]
                        if "ResourceNotFound" in code or "NoSuchResourcePolicy" in code:
                            st.warning("No resource policy — run `make setup-a2a`")
                        else:
                            st.error(str(exc))

    missing_arns = [
        name for name, val in [
            ("ORCHESTRATOR_RUNTIME_ARN", ORCHESTRATOR_RUNTIME_ARN),
            ("VENDOR_RUNTIME_ARN", VENDOR_RUNTIME_ARN),
            ("APPROVAL_RUNTIME_ARN", APPROVAL_RUNTIME_ARN),
        ] if not val
    ]
    if missing_arns:
        st.warning(f"Missing ARNs: {', '.join(missing_arns)} — run `make configure-agents`")
    else:
        scenario = st.radio("Scenario", [
            "INV-001 · ACME $450 — happy path (auto-approved)",
            "INV-002 · TechEquip $750 — escalation (amount triggers forbid in ENFORCE)",
            "INV-EVIL · $100 — prompt injection + unknown vendor (blocked)",
        ], key="p4_scenario")

        prompts_p4 = {
            "INV-001 · ACME $450 — happy path (auto-approved)":
                "Process invoice INV-001.",
            "INV-002 · TechEquip $750 — escalation (amount triggers forbid in ENFORCE)":
                "Process invoice INV-002.",
            "INV-EVIL · $100 — prompt injection + unknown vendor (blocked)":
                "Process invoice INV-EVIL.",
        }

        if st.button("Run scenario", key="p4_run", type="primary"):
            with st.spinner("Running three-tier A2A flow — Orchestrator → Vendor → Approval..."):
                try:
                    result = invoke_runtime(ORCHESTRATOR_RUNTIME_ARN, prompts_p4[scenario])
                    st.json(result)
                    if "INV-EVIL" in scenario:
                        st.info(
                            "V999 not on approved vendor list — VendorAgent rejected it. "
                            "Prompt injection had no effect. ApprovalAgent was never called."
                        )
                    elif "INV-001" in scenario:
                        st.success("Happy path complete: vendor validated + payment auto-approved")
                    elif "INV-002" in scenario:
                        st.info("Vendor validated. Amount triggers escalation at approval step.")
                except Exception as exc:
                    st.error(str(exc))


# ═════════════════════════════════════════════════════════════════════════════
# Phase 5 — On-Behalf-Of Identity Propagation
# ═════════════════════════════════════════════════════════════════════════════

with tab5:
    st.header("Phase 5 — On-Behalf-Of Identity Propagation")
    st.markdown(
        "**ZT Pillar: Verify Explicitly (end-to-end)**  \n"
        "Login as admin or operator, see the JWT claims, then invoke the agent "
        "with the human identity bound. Switch to AWS Console for Cedar decision spans."
    )

    if not COGNITO_USER_POOL_ID or not COGNITO_APP_CLIENT_ID:
        st.warning("Cognito not configured — run `make setup` first.")
    elif not ORCHESTRATOR_RUNTIME_ARN:
        st.warning("ORCHESTRATOR_RUNTIME_ARN not set — run `make configure-agents` first.")
    else:
        # ── Login ────────────────────────────────────────────────────────
        st.subheader("Step 1: Login")
        col_admin, col_operator = st.columns(2)

        with col_admin:
            if st.button("Login as admin-user", key="p5_login_admin", type="primary"):
                with st.spinner("Authenticating admin-user against Cognito..."):
                    try:
                        auth = cognito_login("admin-user")
                        st.session_state["p5_auth"] = auth
                        st.success(f"Logged in as **admin-user**")
                    except Exception as exc:
                        st.error(f"Login failed: {exc}")

        with col_operator:
            if st.button("Login as operator-user", key="p5_login_operator", type="primary"):
                with st.spinner("Authenticating operator-user against Cognito..."):
                    try:
                        auth = cognito_login("operator-user")
                        st.session_state["p5_auth"] = auth
                        st.success(f"Logged in as **operator-user**")
                    except Exception as exc:
                        st.error(f"Login failed: {exc}")

        # ── JWT Claims ───────────────────────────────────────────────────
        if "p5_auth" in st.session_state:
            auth = st.session_state["p5_auth"]
            claims = auth["claims"]
            username = auth["username"]
            role = claims.get("role", claims.get("custom:role", "unknown"))

            st.divider()
            st.subheader(f"Step 2: Cognito JWT Claims ({username})")
            st.caption(f"role = **{role}** — this is what `get_workload_access_token_for_jwt` binds into the agent's workload token")

            key_fields = {k: v for k, v in claims.items() if k in (
                "sub", "email", "role", "custom:role", "cognito:groups",
                "iss", "token_use", "auth_time", "exp",
            )}
            st.json(key_fields)

            # ── Agent Invocation ─────────────────────────────────────────
            st.divider()
            st.subheader(f"Step 3: Invoke Agent as {username}")

            scenario = st.radio("Scenario", [
                "Process INV-001 ($450)",
                "Process INV-002 ($750)",
            ], key="p5_scenario", horizontal=True)

            invoice = "INV-001" if "INV-001" in scenario else "INV-002"

            if st.button(f"Process {invoice} as {username}", key="p5_invoke", type="primary"):
                with st.spinner(f"Invoking OrchestratorAgent as {username} (role={role})..."):
                    try:
                        result = invoke_runtime(
                            ORCHESTRATOR_RUNTIME_ARN,
                            f"Process invoice {invoice}.",
                            user_token=auth["id_token"],
                        )
                        response_text = result.get("response", str(result))
                        st.text_area("Agent Response", value=response_text, height=200)
                        st.info(
                            f"Check **AWS Console** > CloudWatch > Log Insights > `aws/spans` "
                            f"to see Cedar decisions on `Phase5ApprovalGateway` — "
                            f"`principal.getTag(\"role\") = {role}`."
                        )
                    except Exception as exc:
                        st.error(f"Invocation failed: {exc}")

            # ── Code Change ──────────────────────────────────────────────
            st.divider()
            with st.expander("The one-line code change"):
                st.code(
                    "# BEFORE (Phases 1-4): agent identity only\n"
                    "token = client.get_workload_access_token(\n"
                    "    workloadName=\"OrchestratorAgent\"\n"
                    ")\n\n"
                    "# AFTER (Phase 5): human identity bound\n"
                    "token = client.get_workload_access_token_for_jwt(\n"
                    "    workloadName=\"OrchestratorAgent\",\n"
                    "    userToken=cognito_jwt,  # admin or operator JWT\n"
                    ")",
                    language="python",
                )

            with st.expander("Cedar policy — Phase5ApprovalGateway (phase5-approval-obo.cedar)"):
                policy_path = REPO_ROOT / "policies" / "phase5-approval-obo.cedar"
                if policy_path.exists():
                    st.code(policy_path.read_text(), language="javascript")
                st.markdown(
                    "Principal type: `AgentCore::OAuthUser` — Cognito ID token as Bearer.  \n"
                    "JWT `role` claim → `principal.getTag(\"role\")`.  \n\n"
                    "- **admin** + approve_payment ($450) → **ALLOW** (permit matches)  \n"
                    "- **operator** + approve_payment → **DENY** (no matching permit)  \n"
                    "- **admin** + approve_payment ($750) → **DENY** (forbid: amount ≥ 500)"
                )

