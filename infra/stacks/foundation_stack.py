"""
Foundation Stack — deployed first, no dependencies on other stacks.

Provisions:
  - Pre-token generation Lambda (V2_0) that injects a `role` claim into
    Cognito tokens based on group membership (admins → "admin",
    operators → "operator"). Cedar policies use principal.getTag("role").
  - Cognito User Pool with `admins` and `operators` groups and an App Client
    that supports ADMIN_USER_PASSWORD_AUTH (used by setup_demo.py).
  - DynamoDB `zt-demo-invoices` table (seeded by scripts/setup_demo.py).
  - Three IAM execution roles for AgentCore Runtimes:
      orchestrator-execution-role   Deployed with AmazonDynamoDBFullAccess (Phase 2
                                    "before" state). make phase2 detaches it live.
                                    Inline: dynamodb:GetItem on invoices only +
                                    Bedrock invoke + InvokeAgentRuntime on sub-agents
      vendor-execution-role     Bedrock invoke + runtime base permissions
      approval-execution-role   Bedrock invoke + runtime base permissions

  All ARNs and IDs are exported as CfnOutputs for downstream stacks and
  readable as Python attributes (self.user_pool, self.orchestrator_role, etc.).
"""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_cognito as cognito,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda as lambda_,
)
from cdk_nag import NagSuppressions
from constructs import Construct

# Inline source for the pre-token generation Lambda.
# Kept as a multi-line string (not Code.from_asset) because the function is
# <20 lines — well within the 4 KB inline limit — and avoids a separate file.
_PRE_TOKEN_GEN_CODE = """\
def handler(event, context):
    \"\"\"
    Cognito pre-token generation trigger (V2_0).
    Injects a `role` claim into both the access token and the ID token based
    on the user's Cognito group membership.  Cedar policies in AgentCore
    reference this claim via principal.getTag("role").
    \"\"\"
    groups = (
        event.get("request", {})
             .get("groupConfiguration", {})
             .get("groupsToOverride", [])
    )
    role = "admin" if "admins" in groups else "operator"

    # V2_0 response structure — modifies both access and ID tokens
    event["response"] = {
        "claimsAndScopeOverrideDetails": {
            "accessTokenGeneration": {
                "claimsToAddOrOverride": {"role": role},
            },
            "idTokenGeneration": {
                "claimsToAddOrOverride": {"role": role},
            },
        }
    }
    return event
"""


def _runtime_base_statements(region: str, account: str) -> list[iam.PolicyStatement]:
    """
    Returns the minimum IAM statements every AgentCore Runtime execution role
    requires regardless of what the agent does.  These are taken verbatim from
    the official AgentCore Runtime Permissions guide:
    https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/runtime/permissions.md

    Included:
      - CloudWatch Logs  (agent invocation logs → /aws/bedrock-agentcore/runtimes/*)
      - X-Ray            (OTEL traces via init_observability())
      - CloudWatch Metrics (bedrock-agentcore namespace only)
      - Workload Identity (GetWorkloadAccessToken for gateway JWT auth)
    """
    log_group_arn = (
        f"arn:aws:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/runtimes/*"
    )
    return [
        iam.PolicyStatement(
            sid="CloudWatchLogsCreateGroup",
            actions=["logs:DescribeLogStreams", "logs:CreateLogGroup"],
            resources=[log_group_arn],
        ),
        iam.PolicyStatement(
            sid="CloudWatchLogsDescribeAll",
            actions=["logs:DescribeLogGroups"],
            resources=[f"arn:aws:logs:{region}:{account}:log-group:*"],
        ),
        iam.PolicyStatement(
            sid="CloudWatchLogsPut",
            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
            resources=[f"{log_group_arn}:log-stream:*"],
        ),
        iam.PolicyStatement(
            sid="XRayTracing",
            actions=[
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords",
                "xray:GetSamplingRules",
                "xray:GetSamplingTargets",
            ],
            resources=["*"],
        ),
        iam.PolicyStatement(
            sid="CloudWatchMetrics",
            actions=["cloudwatch:PutMetricData"],
            resources=["*"],
            conditions={
                "StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}
            },
        ),
        iam.PolicyStatement(
            sid="WorkloadIdentityToken",
            actions=[
                "bedrock-agentcore:GetWorkloadAccessToken",
                "bedrock-agentcore:GetWorkloadAccessTokenForJwt",
            ],
            resources=["*"],
        ),
        iam.PolicyStatement(
            sid="InvokeGateway",
            actions=["bedrock-agentcore:InvokeGateway"],
            resources=["*"],
        ),
    ]


class FoundationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── Pre-token generation Lambda ───────────────────────────────────────
        pre_token_fn = lambda_.Function(
            self,
            "PreTokenGenFn",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_PRE_TOKEN_GEN_CODE),
            description=(
                "Injects role claim into Cognito access + ID tokens "
                "based on group membership (admins→admin, operators→operator)"
            ),
        )

        # ── Cognito User Pool ─────────────────────────────────────────────────
        user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name="zt-demo-user-pool",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(username=True, email=True),
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_uppercase=True,
                require_lowercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            removal_policy=RemovalPolicy.DESTROY,
            lambda_triggers=cognito.UserPoolTriggers(
                pre_token_generation=pre_token_fn,
            ),
        )

        # L1 escape hatch: set PreTokenGenerationConfig to V2_0
        # (the L2 construct only supports V1_0 via lambda_triggers)
        cfn_pool = user_pool.node.default_child
        cfn_pool.add_property_override(
            "LambdaConfig.PreTokenGenerationConfig",
            {
                "LambdaArn": pre_token_fn.function_arn,
                "LambdaVersion": "V2_0",
            },
        )

        # ── User Pool Groups ──────────────────────────────────────────────────
        cognito.CfnUserPoolGroup(
            self,
            "AdminsGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="admins",
            description="Admin users — full procurement access including payment approval",
        )
        cognito.CfnUserPoolGroup(
            self,
            "OperatorsGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name="operators",
            description="Operator users — read-only invoice access, cannot approve payments",
        )

        # ── App Client ────────────────────────────────────────────────────────
        # generate_secret=False: public client — setup_demo.py and demo scripts
        # use ADMIN_USER_PASSWORD_AUTH which does not require a client secret.
        app_client = user_pool.add_client(
            "AppClient",
            user_pool_client_name="zt-demo-client",
            auth_flows=cognito.AuthFlow(
                user_password=True,       # ALLOW_USER_PASSWORD_AUTH
                admin_user_password=True, # ALLOW_ADMIN_USER_PASSWORD_AUTH (setup script)
            ),
            generate_secret=False,
            access_token_validity=Duration.hours(1),
            id_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.days(1),
        )

        # ── Cognito Domain ────────────────────────────────────────────────────
        # Domain prefix must be globally unique — use account ID as suffix.
        # self.account resolves to the actual account ID at synth time because
        # app.py sets an explicit cdk.Environment.
        domain_prefix = f"zt-demo-{self.account}"
        user_pool.add_domain(
            "CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=domain_prefix,
            ),
        )

        # ── DynamoDB invoices table ───────────────────────────────────────────
        # Table schema is minimal — demo data seeded by scripts/setup_demo.py.
        invoices_table = dynamodb.Table(
            self,
            "InvoicesTable",
            table_name="zt-demo-invoices",
            partition_key=dynamodb.Attribute(
                name="invoice_id",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # ── IAM execution roles ───────────────────────────────────────────────
        # Trust policy follows the official AgentCore guidance:
        #   - Service principal: bedrock-agentcore.amazonaws.com
        #   - SourceAccount condition: prevents confused deputy attacks
        #   - SourceArn condition: scopes trust to this account's AgentCore resources
        agent_principal = iam.CompositePrincipal(
            iam.ServicePrincipal(
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
            # Allow account principals to assume for Phase 2 exploit simulation
            iam.AccountRootPrincipal(),
        )

        base_stmts = _runtime_base_statements(self.region, self.account)

        # ── orchestrator-execution-role ─────────────────────────────────────────
        # Deployed with AmazonDynamoDBFullAccess (Phase 2 "before" state).
        # make phase2 detaches it live to demonstrate least privilege enforcement.
        orchestrator_role = iam.Role(
            self,
            "OrchestratorExecutionRole",
            role_name="zt-demo-orchestrator-execution-role",
            assumed_by=agent_principal,
            description=(
                "OrchestratorAgent execution role. Deployed with DynamoDBFullAccess "
                "(Phase 2 'before' state). Phase 2 demo detaches it live to show "
                "least privilege enforcement."
            ),
        )
        # Phase 2 anti-pattern: broad DynamoDB access (detached live during demo)
        orchestrator_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonDynamoDBFullAccess")
        )
        orchestrator_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvoiceReadOnly",
                actions=["dynamodb:GetItem"],
                resources=[invoices_table.table_arn],
            )
        )
        orchestrator_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockInvoke",
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=["*"],
            )
        )
        orchestrator_role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeSubAgentRuntimes",
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=[
                    f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:runtime/*"
                ],
            )
        )
        for stmt in base_stmts:
            orchestrator_role.add_to_policy(stmt)

        # ── vendor-execution-role ─────────────────────────────────────────────
        vendor_role = iam.Role(
            self,
            "VendorExecutionRole",
            role_name="zt-demo-vendor-execution-role",
            assumed_by=agent_principal,
            description="Scoped role for VendorAgent: Bedrock invoke only",
        )
        vendor_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockInvoke",
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=["*"],
            )
        )
        for stmt in base_stmts:
            vendor_role.add_to_policy(stmt)

        # ── approval-execution-role ───────────────────────────────────────────
        approval_role = iam.Role(
            self,
            "ApprovalExecutionRole",
            role_name="zt-demo-approval-execution-role",
            assumed_by=agent_principal,
            description="Scoped role for ApprovalAgent: Bedrock invoke only",
        )
        approval_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockInvoke",
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=["*"],
            )
        )
        for stmt in base_stmts:
            approval_role.add_to_policy(stmt)

        # ── cdk-nag suppressions (demo-specific justifications) ────────────────
        NagSuppressions.add_resource_suppressions(
            pre_token_fn,
            [
                {"id": "AwsSolutions-IAM4", "reason": "AWSLambdaBasicExecutionRole is standard for Lambda logging"},
                {"id": "AwsSolutions-L1", "reason": "Python 3.13 is the latest stable Lambda runtime; 3.14 is not yet GA"},
            ],
            apply_to_children=True,
        )
        NagSuppressions.add_resource_suppressions(
            user_pool,
            [
                {"id": "AwsSolutions-COG2", "reason": "MFA not required — demo users are ephemeral test accounts"},
                {"id": "AwsSolutions-COG8", "reason": "Plus tier not needed — demo uses basic Cognito features only"},
            ],
        )
        NagSuppressions.add_resource_suppressions(
            invoices_table,
            [{"id": "AwsSolutions-DDB3", "reason": "PITR not needed — table is seeded fresh each demo session"}],
        )
        # Scoped roles use wildcards only where required by service (Bedrock model ARNs, X-Ray, CloudWatch)
        for role in [orchestrator_role, vendor_role, approval_role]:
            NagSuppressions.add_resource_suppressions(
                role,
                [
                    {"id": "AwsSolutions-IAM4", "reason": "AmazonDynamoDBFullAccess on orchestrator role is intentional Phase 2 'before' state — detached live during demo to show least privilege"},
                    {"id": "AwsSolutions-IAM5", "reason": "Bedrock model ARNs and CloudWatch/X-Ray require resource:* — scoped by action and condition where possible"},
                ],
                apply_to_children=True,
            )

        # ── Python attributes (used by downstream CDK stacks) ─────────────────
        self.user_pool = user_pool
        self.app_client = app_client
        self.invoices_table = invoices_table
        self.orchestrator_role = orchestrator_role
        self.vendor_role = vendor_role
        self.approval_role = approval_role
        self.domain_prefix = domain_prefix

        # ── CloudFormation outputs ────────────────────────────────────────────
        token_endpoint = (
            f"https://{domain_prefix}.auth.{self.region}.amazoncognito.com/oauth2/token"
        )
        oidc_discovery_url = (
            f"https://cognito-idp.{self.region}.amazonaws.com"
            f"/{user_pool.user_pool_id}/.well-known/openid-configuration"
        )

        outputs = {
            "UserPoolId": user_pool.user_pool_id,
            "UserPoolArn": user_pool.user_pool_arn,
            "AppClientId": app_client.user_pool_client_id,
            "CognitoTokenEndpoint": token_endpoint,
            "CognitoOidcDiscoveryUrl": oidc_discovery_url,
            "InvoicesTableName": invoices_table.table_name,
            "InvoicesTableArn": invoices_table.table_arn,
            "OrchestratorExecutionRoleArn": orchestrator_role.role_arn,
            "VendorExecutionRoleArn": vendor_role.role_arn,
            "ApprovalExecutionRoleArn": approval_role.role_arn,
        }
        for key, value in outputs.items():
            CfnOutput(self, key, value=value, export_name=f"ZtDemo-{key}")
