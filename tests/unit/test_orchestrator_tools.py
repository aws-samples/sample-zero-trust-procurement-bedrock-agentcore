"""
Unit tests for OrchestratorAgent tools.

Tests the baked-in tools in agents/orchestrator/main.py without
deploying to AWS.  AWS API calls are mocked so the tests run offline.

Run:
    pytest tests/unit/test_orchestrator_tools.py -v
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add agent directory to sys.path so we can import main.py directly.
AGENT_DIR = Path(__file__).resolve().parent.parent.parent / "agents" / "orchestrator"
sys.path.insert(0, str(AGENT_DIR))

import main as orchestrator_main


# ── route_to_agent ─────────────────────────────────────────────────────────────

class TestRouteToAgent:
    def test_returns_error_when_no_vendor_arn(self, monkeypatch):
        monkeypatch.delenv("VENDOR_AGENT_RUNTIME_ARN", raising=False)
        monkeypatch.delenv("APPROVAL_AGENT_RUNTIME_ARN", raising=False)

        result = orchestrator_main.route_to_agent("vendor", {"prompt": "validate vendor"})
        assert "error" in result
        assert "vendor" in result["error"]

    def test_returns_error_when_no_approval_arn(self, monkeypatch):
        monkeypatch.delenv("VENDOR_AGENT_RUNTIME_ARN", raising=False)
        monkeypatch.delenv("APPROVAL_AGENT_RUNTIME_ARN", raising=False)

        result = orchestrator_main.route_to_agent("approval", {"prompt": "approve payment"})
        assert "error" in result
        assert "approval" in result["error"]

    def test_unknown_agent_type_returns_error(self, monkeypatch):
        monkeypatch.delenv("VENDOR_AGENT_RUNTIME_ARN", raising=False)
        monkeypatch.delenv("APPROVAL_AGENT_RUNTIME_ARN", raising=False)

        result = orchestrator_main.route_to_agent("unknown", {"prompt": "test"})
        assert "error" in result

    @patch("main.boto3")
    def test_invokes_runtime_when_arn_is_set(self, mock_boto3, monkeypatch):
        test_arn = "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime/test-id"
        monkeypatch.setenv("VENDOR_AGENT_RUNTIME_ARN", test_arn)

        mock_client = MagicMock()
        mock_response_body = MagicMock()
        mock_response_body.read.return_value = b'{"result": "vendor validated"}'
        mock_client.invoke_agent_runtime.return_value = {"response": mock_response_body}
        mock_boto3.client.return_value = mock_client

        result = orchestrator_main.route_to_agent("vendor", {"prompt": "check vendor V001"})

        mock_client.invoke_agent_runtime.assert_called_once()
        call_kwargs = mock_client.invoke_agent_runtime.call_args.kwargs
        assert call_kwargs["agentRuntimeArn"] == test_arn
        assert result == {"result": "vendor validated"}


# ── show_a2a_token_identity ────────────────────────────────────────────────────

class TestShowA2ATokenIdentity:
    @patch("main.boto3")
    def test_m2m_mode_returns_token_claims(self, mock_boto3):
        mock_client = MagicMock()
        # Minimal valid JWT with a simple payload: {"sub": "workload-arn", "mode": "m2m"}
        # base64url({"alg":"HS256"}).base64url({"sub":"test"}).sig
        fake_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3b3JrbG9hZC1hcm4ifQ.sig"
        mock_client.get_workload_access_token.return_value = {"workloadAccessToken": fake_token}
        mock_boto3.Session.return_value.client.return_value = mock_client
        mock_boto3.client.return_value = mock_client

        result = orchestrator_main.show_a2a_token_identity(use_user_context=False)

        assert result.get("mode") == "m2m_only — agent identity only"
        assert "token_claims" in result

    @patch("main._CURRENT_USER_TOKEN", "")
    @patch("main.boto3")
    def test_user_bound_without_token_returns_error(self, mock_boto3):
        result = orchestrator_main.show_a2a_token_identity(use_user_context=True)
        assert "error" in result


# ── handler (entrypoint) ───────────────────────────────────────────────────────

class TestHandler:
    def test_handler_returns_error_when_gateway_url_not_set(self, monkeypatch):
        monkeypatch.setattr(orchestrator_main, "PROCUREMENT_GATEWAY_URL", "")
        result = orchestrator_main.handler({"prompt": "Process invoice INV-001"}, {})
        assert "ERROR" in result["response"]
        assert "PROCUREMENT_GATEWAY_URL" in result["response"]

    @patch("main.MCPClient")
    @patch("main.Agent")
    def test_handler_passes_prompt_to_agent(self, mock_agent_cls, mock_mcp_cls, monkeypatch):
        monkeypatch.setattr(orchestrator_main, "PROCUREMENT_GATEWAY_URL", "https://gateway.example.com/mcp")

        mock_mcp_instance = MagicMock()
        mock_mcp_instance.__enter__ = MagicMock(return_value=mock_mcp_instance)
        mock_mcp_instance.__exit__ = MagicMock(return_value=False)
        mock_mcp_instance.list_tools_sync.return_value = []
        mock_mcp_cls.return_value = mock_mcp_instance

        mock_agent_instance = MagicMock()
        mock_agent_instance.return_value = "Invoice INV-001 processed."
        mock_agent_cls.return_value = mock_agent_instance

        result = orchestrator_main.handler({"prompt": "Process invoice INV-001"}, {})

        mock_agent_instance.assert_called_once_with("Process invoice INV-001")
        assert "response" in result

    @patch("main.MCPClient")
    @patch("main.Agent")
    def test_handler_captures_user_token(self, mock_agent_cls, mock_mcp_cls, monkeypatch):
        monkeypatch.setattr(orchestrator_main, "PROCUREMENT_GATEWAY_URL", "https://gateway.example.com/mcp")

        mock_mcp_instance = MagicMock()
        mock_mcp_instance.__enter__ = MagicMock(return_value=mock_mcp_instance)
        mock_mcp_instance.__exit__ = MagicMock(return_value=False)
        mock_mcp_instance.list_tools_sync.return_value = []
        mock_mcp_cls.return_value = mock_mcp_instance

        mock_agent_instance = MagicMock()
        mock_agent_instance.return_value = "done"
        mock_agent_cls.return_value = mock_agent_instance

        orchestrator_main.handler({"prompt": "test", "user_token": "tok123"}, {})

        assert orchestrator_main._CURRENT_USER_TOKEN == "tok123"
