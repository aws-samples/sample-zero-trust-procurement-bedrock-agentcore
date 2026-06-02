"""
Approval Stack — Lambda tool functions for ApprovalAgent.

Deployed after FoundationStack.  The approval tool Lambdas are registered
as MCP targets on the single ProcurementGateway (created by
`scripts/setup_procurement_gateway.py`).  There is no separate ApprovalGateway.

Zero Trust story — agent-to-tool authorization on ProcurementGateway:
  Cedar policy (procurement-approval.cedar) permits ApprovalAgent workload
  identity (role=approval-agent) to call approve_payment (Cedar enforces
  forbid: amount >= 500) and get_approval_status.  Cedar default-deny blocks every
  other agent from reaching these tools.

  ApprovalAgent Runtime has a resource policy (scripts/setup_approval_resource_policy.py)
  restricting InvokeAgentRuntime to OrchestratorAgent only — completing the
  three-tier A2A authentication chain.

Resources created:
  - approve_payment_fn        Lambda: evaluates invoice amount against thresholds
  - get_approval_status_fn    Lambda: returns approval record for an invoice

CloudFormation outputs (all exported as ZtDemo-*):
  - ApprovePaymentFnArn
  - GetApprovalStatusFnArn
"""

from aws_cdk import (
    CfnOutput,
    Stack,
    aws_lambda as lambda_,
)
from cdk_nag import NagSuppressions
from constructs import Construct

from infra.stacks.foundation_stack import FoundationStack

# ── Lambda inline source ───────────────────────────────────────────────────────

_APPROVE_PAYMENT_CODE = """\
# NOTE: _APPROVALS is ephemeral in-memory state (warm container only).
# get_approval_status may return 'not_found' after a cold start since Lambda
# does not persist this dict across invocations. Acceptable for demo purposes.
#
# Cedar (procurement-approval-limit.cedar) forbids amount >= 500 at the gateway
# before this Lambda is ever invoked. All amounts that reach here are < 500
# and are auto-approved.
_AUTO_LIMIT = 500.0

_APPROVALS = {}

def handler(event, context):
    invoice_id  = str(event.get("invoice_id", "")).strip()
    vendor_id   = str(event.get("vendor_id", "")).strip()
    vendor_name = str(event.get("vendor_name", "")).strip()
    raw_amount  = event.get("amount", "")

    if not invoice_id or raw_amount == "":
        return {"error": "invoice_id and amount are required"}

    try:
        amount = float(raw_amount)
    except (ValueError, TypeError):
        return {"approved": False, "invoice_id": invoice_id,
                "status": "invalid_amount",
                "message": f"Amount {raw_amount!r} is not a valid number."}

    result = {
        "approved": True,
        "invoice_id": invoice_id, "vendor_id": vendor_id,
        "vendor_name": vendor_name, "amount": str(amount),
        "status": "approved", "approval_level": "auto",
        "message": (f"Invoice {invoice_id} auto-approved. "
                    f"Amount ${amount:.2f} within ${_AUTO_LIMIT:.0f} limit."),
    }
    _APPROVALS[invoice_id] = result
    return result
"""

_GET_APPROVAL_STATUS_CODE = """\
_APPROVALS = {}

def handler(event, context):
    invoice_id = event.get("invoice_id", "").strip()
    if not invoice_id:
        return {"error": "invoice_id is required"}
    record = _APPROVALS.get(invoice_id)
    if not record:
        return {"invoice_id": invoice_id, "status": "not_found",
                "message": f"No approval record for invoice {invoice_id!r}. "
                           "Call approve_payment first."}
    return record
"""


class ApprovalStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        foundation: FoundationStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── approve_payment Lambda ─────────────────────────────────────────────
        approve_payment_fn = lambda_.Function(
            self,
            "ApprovePaymentFn",
            function_name="zt-demo-approve-payment",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_APPROVE_PAYMENT_CODE),
            description="ZT demo: evaluate invoice amount against approval thresholds",
        )

        # ── get_approval_status Lambda ─────────────────────────────────────────
        get_approval_status_fn = lambda_.Function(
            self,
            "GetApprovalStatusFn",
            function_name="zt-demo-get-approval-status",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_GET_APPROVAL_STATUS_CODE),
            description="ZT demo: return approval record for an invoice",
        )

        # ── cdk-nag suppressions ───────────────────────────────────────────────
        for fn in [approve_payment_fn, get_approval_status_fn]:
            NagSuppressions.add_resource_suppressions(
                fn,
                [
                    {"id": "AwsSolutions-IAM4", "reason": "AWSLambdaBasicExecutionRole is standard for Lambda logging"},
                    {"id": "AwsSolutions-L1", "reason": "Python 3.13 is the latest stable Lambda runtime; 3.14 is not yet GA"},
                ],
                apply_to_children=True,
            )

        # ── Python attributes ──────────────────────────────────────────────────
        # No separate ApprovalGateway service role — the ProcurementGatewayServiceRole
        # in OrchestratorStack covers all zt-demo-* Lambdas via wildcard ARN.
        self.approve_payment_fn = approve_payment_fn
        self.get_approval_status_fn = get_approval_status_fn

        # ── CloudFormation outputs ─────────────────────────────────────────────
        outputs = {
            "ApprovePaymentFnArn": approve_payment_fn.function_arn,
            "GetApprovalStatusFnArn": get_approval_status_fn.function_arn,
        }
        for key, value in outputs.items():
            CfnOutput(self, key, value=value, export_name=f"ZtDemo-{key}")
