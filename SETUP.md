# Setup Guide

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Python | 3.11+ | [python.org](https://www.python.org) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| AWS CLI | v2 | [docs.aws.amazon.com](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| AWS CDK CLI | 2.100+ | `npm install -g aws-cdk` |

## AWS Account Requirements

- **AdministratorAccess** on the target account
- **Bedrock model access**: enable `us.anthropic.claude-sonnet-4-6` in the [Bedrock console](https://console.aws.amazon.com/bedrock/) (us-east-1)
- All resources deploy to **us-east-1** only

## AWS Profile Setup

### Create the deployer role (once per account)

Create the `zt-demo-deployer` IAM role using an admin profile. This role is assumed during all CDK deployments and demo phases.

```bash
# Create the role (trust policy allows any principal in the account to assume it)
aws iam create-role \
  --role-name zt-demo-deployer \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "AllowAccountAssumeRole",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:root"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  --description "Demo deployer role for bedrock-agentcore-zero-trust." \
  --tags Key=demo,Value=zt-agentcore Key=purpose,Value=deployer \
  --profile <admin-profile>

# Attach AdministratorAccess (required for CDK IAM role creation and Phase 2 live policy swap)
aws iam attach-role-policy \
  --role-name zt-demo-deployer \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --profile <admin-profile>
```

Replace `<ACCOUNT_ID>` with your AWS account ID and `<admin-profile>` with a profile that has IAM write permissions.

### Configure the deployer profile

Add a profile entry in `~/.aws/config` that assumes the role:

```ini
[profile zt-demo-deployer]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/zt-demo-deployer
source_profile = <admin-profile>
region = us-east-1
```

Then confirm the profile resolves correctly:

```bash
export AWS_PROFILE=zt-demo-deployer
aws sts get-caller-identity   # should show zt-demo-deployer in the ARN
```

## One-Time Setup

```bash
# 1. Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate

# 2. Install dependencies
make install

# 3. Bootstrap CDK (once per account/region)
make bootstrap

# 4. Deploy everything (~15–20 min first time)
make demo-setup
```

`make demo-setup` runs the full sequence:
1. Deploy CDK stacks (Lambda tools, IAM roles, Cognito, DynamoDB)
2. Create Cognito users + seed DynamoDB invoices + write `.env.demo`
3. Deploy agents to AgentCore Runtime (pass 1)
4. Create ProcurementGateway + Cedar policies + workload identities
5. Create Phase5ApprovalGateway
6. Deploy agents again with gateway URLs (pass 2)
7. Apply A2A resource policies

## Enable Gateway Tracing (once per deployment)

After `make demo-setup` completes, enable X-Ray tracing on both gateways from the AgentCore console:

1. Open the [AgentCore Gateways](https://console.aws.amazon.com/bedrock-agentcore/toolsAndGateways) page (us-east-1).
2. Select **ProcurementGateway** → scroll to the **Tracing** pane → **Edit** → toggle **Enable** → **Save**.
3. Repeat for **Phase5ApprovalGateway**.

Spans appear in the `aws/spans` CloudWatch Logs log group. Requires [CloudWatch Transaction Search](https://console.aws.amazon.com/cloudwatch/home#transaction-search) to be enabled first (done automatically by `make demo-setup` via `setup_demo.py`).

## Per-Session Checklist

Cognito tokens expire every hour. Run this before each session:

```bash
source .venv/bin/activate
export AWS_PROFILE=zt-demo-deployer
make setup        # refresh tokens + re-seed DynamoDB
make smoke        # verify all 9 checks pass
```

## Run the Demo Phases

```bash
make phase1                                        # Verify Explicitly: runtime resource policy
make phase2                                        # Least Privilege: scoped execution role
make phase3                                        # Cedar LOG_ONLY — observe decisions
python scripts/toggle_policy_mode.py ENFORCE       # switch Cedar to ENFORCE — block before Lambda
make phase3                                        # re-run to see ENFORCE in effect
make phase4                                        # A2A trust + prompt injection (Assume Breach)
make phase5                                        # On-behalf-of identity (Verify Explicitly end-to-end)
```

## Streamlit UI (optional)

```bash
make ui    # opens at http://localhost:8501
```

## Teardown

```bash
make destroy              # deletes AgentCore resources then CDK stacks
make teardown-agentcore   # AgentCore resources only (runtimes, gateways,
                          # policy engines, workload identities)
```
