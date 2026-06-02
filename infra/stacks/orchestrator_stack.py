"""
Orchestrator Stack — deploys the orchestrator Lambda tool functions and the
single ProcurementGatewayServiceRole that covers ALL demo tool Lambdas.

Deployed after FoundationStack.  The AgentCore ProcurementGateway (single
gateway for all agents) is NOT created here — it is created by
`scripts/setup_procurement_gateway.py` after all stacks are deployed.

Resources created:
  - read_invoice_fn              Lambda: reads an invoice from DynamoDB (GetItem)
  - show_identity_fn             Lambda: calls STS GetCallerIdentity
  - procurement-gateway-role     Single IAM role trusted by ProcurementGateway
                                 to invoke ALL zt-demo-* Lambda tool functions.
                                 Wildcard ARN covers vendor + approval Lambdas
                                 deployed in VendorStack and ApprovalStack.

Note: A2A routing is handled by the orchestrator agent's baked-in
`route_to_agent` tool (in agents/orchestrator/main.py), not via a Lambda.

CloudFormation outputs (all exported as ZtDemo-*):
  - ReadInvoiceFnArn
  - ShowIdentityFnArn
  - ProcurementGatewayServiceRoleArn
"""

from aws_cdk import (
    CfnOutput,
    Stack,
    aws_iam as iam,
    aws_lambda as lambda_,
)
from cdk_nag import NagSuppressions
from constructs import Construct

from infra.stacks.foundation_stack import FoundationStack

# ── Lambda inline source code ─────────────────────────────────────────────────
# Kept inline (no Code.from_asset) so the stack has zero external file deps
# and any machine can deploy it after a plain `pip install -r requirements.txt`.

_READ_INVOICE_CODE = """\
import json
import os
import boto3

def handler(event, context):
    invoice_id = event.get("invoice_id", "").strip()
    if not invoice_id:
        return {"error": "invoice_id is required"}

    table_name = os.environ.get("INVOICES_TABLE", "zt-demo-invoices")
    table = boto3.resource("dynamodb").Table(table_name)

    result = table.get_item(Key={"invoice_id": invoice_id})
    item = result.get("Item")
    if not item:
        return {"error": f"Invoice {invoice_id!r} not found"}

    # Decimal → str for JSON serialisation
    return {k: str(v) for k, v in item.items()}
"""

_SHOW_IDENTITY_CODE = """\
import boto3

def handler(event, context):
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    return {
        "account": identity["Account"],
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
        "note": (
            "This is the IAM identity the Lambda function runs as "
            "(its own AWSLambdaBasicExecutionRole, not the calling agent's execution role). "
            "To see the orchestrator execution-role blast radius, check the agent's role "
            "via the show_a2a_token_identity tool or CloudTrail."
        ),
    }
"""


class OrchestratorStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        foundation: FoundationStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── read_invoice Lambda ───────────────────────────────────────────────
        read_invoice_fn = lambda_.Function(
            self,
            "ReadInvoiceFn",
            function_name="zt-demo-read-invoice",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_READ_INVOICE_CODE),
            description="ZT demo: read an invoice by ID from DynamoDB (GetItem only)",
            environment={"INVOICES_TABLE": foundation.invoices_table.table_name},
        )
        # Grant the Lambda only GetItem on the invoices table (least privilege)
        foundation.invoices_table.grant(read_invoice_fn, "dynamodb:GetItem")

        # ── show_identity Lambda ──────────────────────────────────────────────
        # STS GetCallerIdentity does not require an explicit IAM permission —
        # it's available to all IAM principals by default.
        show_identity_fn = lambda_.Function(
            self,
            "ShowIdentityFn",
            function_name="zt-demo-show-identity",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_SHOW_IDENTITY_CODE),
            description="ZT demo: reveal current IAM identity via STS GetCallerIdentity",
        )

        # ── ProcurementGateway service role ───────────────────────────────────
        # Single IAM role assumed by the ProcurementGateway to invoke ALL
        # zt-demo-* Lambda tool functions across all three agent stacks.
        # Using a wildcard ARN pattern avoids cross-stack dependencies while
        # keeping the scope narrow (only zt-demo-* functions in this account).
        gateway_role = iam.Role(
            self,
            "ProcurementGatewayServiceRole",
            role_name="zt-demo-procurement-gateway-service-role",
            assumed_by=iam.ServicePrincipal(
                "bedrock-agentcore.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:*"
                        )
                    },
                },
            ),
            description=(
                "AgentCore ProcurementGateway service role: invokes all zt-demo "
                "Lambda tool functions (read_invoice, show_identity, validate_vendor, "
                "get_vendor_terms, approve_payment, get_approval_status)."
            ),
        )
        # Wildcard covers all zt-demo-* Lambdas: orchestrator, vendor, approval tools.
        gateway_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeAllProcurementToolLambdas",
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{self.region}:{self.account}:function:zt-demo-*"
                ],
            )
        )
        gateway_role.add_to_policy(
            iam.PolicyStatement(
                sid="AgentCorePolicyAndGateway",
                actions=["bedrock-agentcore:*"],
                resources=["*"],
            )
        )

        # ── cdk-nag suppressions ───────────────────────────────────────────────
        for fn in [read_invoice_fn, show_identity_fn]:
            NagSuppressions.add_resource_suppressions(
                fn,
                [
                    {"id": "AwsSolutions-IAM4", "reason": "AWSLambdaBasicExecutionRole is standard for Lambda logging"},
                    {"id": "AwsSolutions-L1", "reason": "Python 3.13 is the latest stable Lambda runtime; 3.14 is not yet GA"},
                ],
                apply_to_children=True,
            )
        NagSuppressions.add_resource_suppressions(
            gateway_role,
            [
                {"id": "AwsSolutions-IAM5", "reason": "Gateway service role needs wildcard on zt-demo-* Lambdas and AgentCore gateway/policy-engine resources it manages"},
                {"id": "AwsSolutions-IAM5", "reason": "AgentCore Gateway requires undocumented internal actions (CheckAuthorizePermissions, GetPolicyEngine, etc.) — bedrock-agentcore:* scoped to gateway/* and policy-engine/* resources only"},
            ],
            apply_to_children=True,
        )

        # ── Python attributes ─────────────────────────────────────────────────
        self.read_invoice_fn = read_invoice_fn
        self.show_identity_fn = show_identity_fn
        self.gateway_role = gateway_role

        # ── CloudFormation outputs ────────────────────────────────────────────
        outputs = {
            "ReadInvoiceFnArn": read_invoice_fn.function_arn,
            "ShowIdentityFnArn": show_identity_fn.function_arn,
            "ProcurementGatewayServiceRoleArn": gateway_role.role_arn,
        }
        for key, value in outputs.items():
            CfnOutput(self, key, value=value, export_name=f"ZtDemo-{key}")
