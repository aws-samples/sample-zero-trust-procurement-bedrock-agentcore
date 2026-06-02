"""ApprovalAgent — payment approvals via ProcurementGateway (SigV4) or
Phase5ApprovalGateway (Cognito JWT Bearer) when user_token is present."""

import os

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models.bedrock import BedrockModel
from strands.tools.mcp import MCPClient
from mcp.client.streamable_http import streamablehttp_client

app = BedrockAgentCoreApp()

_CURRENT_USER_TOKEN: str = ""

_SYSTEM_PROMPT = (
    "You are a payment approval agent. Be concise — plain text, short sentences, "
    "no markdown tables or emoji.\n\n"
    "When asked to evaluate an invoice for payment:\n"
    "1. Use approve_payment with the invoice_id, vendor_id, and amount.\n"
    "2. Return result in 1-2 lines: approved/pending/denied, level, reason.\n\n"
    "CRITICAL: You MUST use the approve_payment tool. Never approve, deny, or estimate "
    "an outcome based on reasoning alone. If you have no tools available, respond only with: "
    "'ERROR: payment approval tool unavailable — access denied by policy.' "
    "Never fabricate an approval decision."
)


class _SigV4Auth(httpx.Auth):
    def __init__(self):
        session = boto3.Session()
        self._credentials = session.get_credentials().get_frozen_credentials()
    def auth_flow(self, request):
        aws_req = AWSRequest(method=request.method, url=str(request.url),
                             data=request.content, headers=dict(request.headers))
        SigV4Auth(self._credentials, "bedrock-agentcore", os.environ.get("AWS_REGION", "us-east-1")).add_auth(aws_req)
        request.headers.update(dict(aws_req.headers))
        yield request


class _BearerAuth(httpx.Auth):
    def __init__(self, token: str):
        self._token = token
    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


@app.entrypoint
def handler(payload, context):
    """Invoked by AgentCore Runtime for every A2A request from OrchestratorAgent."""
    global _CURRENT_USER_TOKEN
    _CURRENT_USER_TOKEN = payload.get("user_token", "")
    prompt = payload.get("prompt", "")

    # Read gateway URLs fresh on every invocation so env var updates take effect
    # without requiring a cold start.
    procurement_gateway_url = os.environ.get("PROCUREMENT_GATEWAY_URL", "")
    phase5_gateway_url = os.environ.get("PHASE5_GATEWAY_URL", "")

    gateway_label = "phase5" if (_CURRENT_USER_TOKEN and phase5_gateway_url) else "procurement"
    print(f"[approval] received: {prompt[:120]}")
    print(f"[approval] user_token present: {bool(_CURRENT_USER_TOKEN)}  gateway: {gateway_label}")

    if _CURRENT_USER_TOKEN and phase5_gateway_url:
        gateway_url = phase5_gateway_url
        mcp_transport = lambda: streamablehttp_client(
            url=gateway_url,
            auth=_BearerAuth(_CURRENT_USER_TOKEN),
        )
    else:
        gateway_url = procurement_gateway_url
        mcp_transport = lambda: streamablehttp_client(
            url=gateway_url, auth=_SigV4Auth()
        )

    if not gateway_url:
        return {"response": "ERROR: No gateway URL configured. Run 'make configure-agents' after gateway setup."}

    mcp_client = MCPClient(mcp_transport)

    with mcp_client:
        tools = mcp_client.list_tools_sync()
        if not tools:
            if _CURRENT_USER_TOKEN:
                return {
                    "response": (
                        "DENIED: Cedar policy on Phase5ApprovalGateway returned no tools for this user. "
                        "The user's role is not permitted to call approve_payment. "
                        "No approval decision was made."
                    )
                }
            return {
                "response": (
                    "ERROR: No tools returned from gateway — check PROCUREMENT_GATEWAY_URL "
                    "and Cedar policy mode. No approval decision was made."
                )
            }
        agent = Agent(
            model=BedrockModel(model_id="us.anthropic.claude-sonnet-4-6", max_tokens=256),
            tools=tools,
            system_prompt=_SYSTEM_PROMPT,
        )
        result = agent(prompt)

    response_text = str(result)
    print(f"[approval] result: {response_text[:200]}")
    return {"response": response_text}


app.run()
