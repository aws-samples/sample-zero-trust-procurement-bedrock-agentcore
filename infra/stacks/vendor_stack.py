"""
Vendor Stack — Lambda tool functions for VendorAgent.

Deployed after FoundationStack.  The vendor tool Lambdas are registered
as MCP targets on the single ProcurementGateway (created by
`scripts/setup_procurement_gateway.py`).  There is no separate VendorGateway.

Zero Trust story — agent-to-tool authorization on ProcurementGateway:
  Cedar policy (procurement-vendor.cedar) permits VendorAgent workload
  identity (role=vendor-agent) to call validate_vendor and get_vendor_terms.
  No other agent identity can reach these tools.

Resources created:
  - validate_vendor_fn    Lambda: checks approved vendor list
  - get_vendor_terms_fn   Lambda: retrieves vendor payment terms

CloudFormation outputs (all exported as ZtDemo-*):
  - ValidateVendorFnArn
  - GetVendorTermsFnArn
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

_VALIDATE_VENDOR_CODE = """\
import json

_APPROVED = {
    "V001": {
        "vendor_name": "ACME Office Supplies",
        "status": "approved",
        "risk_level": "low",
        "payment_terms": "NET30",
        "credit_limit": "10000.00",
    },
    "V002": {
        "vendor_name": "TechEquip Inc",
        "status": "approved",
        "risk_level": "medium",
        "payment_terms": "NET15",
        "credit_limit": "5000.00",
    },
}

def handler(event, context):
    vendor_id   = event.get("vendor_id", "").strip()
    vendor_name = event.get("vendor_name", "").strip()

    if not vendor_id:
        return {"error": "vendor_id is required"}

    vendor = _APPROVED.get(vendor_id)
    if not vendor:
        return {
            "approved": False,
            "vendor_id": vendor_id,
            "status": "not_found",
            "message": f"Vendor {vendor_id!r} is not on the approved list.",
        }

    name_ok = not vendor_name or vendor["vendor_name"].lower() == vendor_name.lower()
    if not name_ok:
        return {
            "approved": False,
            "vendor_id": vendor_id,
            "status": "name_mismatch",
            "expected": vendor["vendor_name"],
            "provided": vendor_name,
            "message": "Vendor name does not match registry — routing for review.",
        }

    return {
        "approved": True,
        "vendor_id": vendor_id,
        **{k: v for k, v in vendor.items()},
        "message": f"Vendor {vendor['vendor_name']!r} is approved.",
    }
"""

_GET_VENDOR_TERMS_CODE = """\
_TERMS = {
    "V001": {"payment_terms": "NET30", "credit_limit": "10000.00", "risk_level": "low",
             "vendor_name": "ACME Office Supplies", "approved_since": "2022-01-15"},
    "V002": {"payment_terms": "NET15", "credit_limit": "5000.00",  "risk_level": "medium",
             "vendor_name": "TechEquip Inc",        "approved_since": "2023-06-01"},
}

def handler(event, context):
    vendor_id = event.get("vendor_id", "").strip()
    if not vendor_id:
        return {"error": "vendor_id is required"}
    terms = _TERMS.get(vendor_id)
    if not terms:
        return {"error": f"Vendor {vendor_id!r} not found"}
    return {"vendor_id": vendor_id, **terms}
"""


class VendorStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        foundation: FoundationStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── validate_vendor Lambda ────────────────────────────────────────────
        validate_vendor_fn = lambda_.Function(
            self,
            "ValidateVendorFn",
            function_name="zt-demo-validate-vendor",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_VALIDATE_VENDOR_CODE),
            description="ZT demo: check if a vendor ID+name is on the approved list",
        )

        # ── get_vendor_terms Lambda ───────────────────────────────────────────
        get_vendor_terms_fn = lambda_.Function(
            self,
            "GetVendorTermsFn",
            function_name="zt-demo-get-vendor-terms",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_GET_VENDOR_TERMS_CODE),
            description="ZT demo: retrieve payment terms for an approved vendor",
        )

        # ── cdk-nag suppressions ───────────────────────────────────────────────
        for fn in [validate_vendor_fn, get_vendor_terms_fn]:
            NagSuppressions.add_resource_suppressions(
                fn,
                [
                    {"id": "AwsSolutions-IAM4", "reason": "AWSLambdaBasicExecutionRole is standard for Lambda logging"},
                    {"id": "AwsSolutions-L1", "reason": "Python 3.13 is the latest stable Lambda runtime; 3.14 is not yet GA"},
                ],
                apply_to_children=True,
            )

        # ── Python attributes ─────────────────────────────────────────────────
        # No separate VendorGateway service role — the ProcurementGatewayServiceRole
        # in OrchestratorStack covers all zt-demo-* Lambdas via wildcard ARN.
        self.validate_vendor_fn = validate_vendor_fn
        self.get_vendor_terms_fn = get_vendor_terms_fn

        # ── CloudFormation outputs ────────────────────────────────────────────
        outputs = {
            "ValidateVendorFnArn": validate_vendor_fn.function_arn,
            "GetVendorTermsFnArn": get_vendor_terms_fn.function_arn,
        }
        for key, value in outputs.items():
            CfnOutput(self, key, value=value, export_name=f"ZtDemo-{key}")
