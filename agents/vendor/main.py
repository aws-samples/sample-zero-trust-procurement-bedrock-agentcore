"""VendorAgent — validates vendors via ProcurementGateway MCP (SigV4, Cedar default-deny)."""

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

PROCUREMENT_GATEWAY_URL = os.environ.get("PROCUREMENT_GATEWAY_URL", "")

_SYSTEM_PROMPT = (
    "You are a vendor validation agent. Be concise — plain text, short sentences, "
    "no markdown tables or emoji.\n\n"
    "When asked to validate a vendor:\n"
    "1. Use validate_vendor with the vendor_id and vendor_name.\n"
    "2. If approved, use get_vendor_terms to retrieve payment terms.\n"
    "3. Return result in 2-3 lines: approved/not-approved, risk level, terms."
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


@app.entrypoint
def handler(payload, context):
    """Invoked by AgentCore Runtime for every A2A request from OrchestratorAgent."""
    prompt = payload.get("prompt", "")
    print(f"[vendor] received: {prompt[:120]}")

    if not PROCUREMENT_GATEWAY_URL:
        return {"response": "ERROR: PROCUREMENT_GATEWAY_URL not set. Run 'make configure-agents' after 'make setup-procurement-gateway'."}

    mcp_client = MCPClient(
        lambda: streamablehttp_client(url=PROCUREMENT_GATEWAY_URL, auth=_SigV4Auth())
    )

    with mcp_client:
        agent = Agent(
            model=BedrockModel(model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0", max_tokens=256),
            tools=mcp_client.list_tools_sync(),
            system_prompt=_SYSTEM_PROMPT,
        )
        result = agent(prompt)

    response_text = str(result)
    print(f"[vendor] result: {response_text[:200]}")
    return {"response": response_text}


app.run()
