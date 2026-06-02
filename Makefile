.PHONY: deploy setup smoke phase1 phase2 phase3 phase4 phase5 setup-a2a destroy teardown-agentcore synth diff \
        deploy-foundation deploy-orchestrator deploy-vendor deploy-approval \
        configure-agents deploy-agents inject-gateway-urls \
        setup-procurement-gateway setup-phase5-gateway setup-identity \
        setup-vendor-resource-policy setup-approval-resource-policy \
        dev-orchestrator dev-vendor dev-approval test test-unit install venv bootstrap smoke ui \
        demo-setup warm

# ─── Profile guard ────────────────────────────────────────────────────────────
# Set AWS_PROFILE in your shell before running any target:
#   export AWS_PROFILE=<your-profile>
#
# AWS CLI, CDK CLI, and boto3 all read AWS_PROFILE natively.
ifndef AWS_PROFILE
$(error AWS_PROFILE is not set. Run: export AWS_PROFILE=<your-profile>)
endif
export AWS_PROFILE

# Suppress migration warning from bedrock-agentcore-starter-toolkit pip package.
# The repo already uses the new @aws/agentcore npm CLI for configure/deploy.
export AGENTCORE_SUPPRESS_RECOMMENDATION=1

# ─── Infrastructure ───────────────────────────────────────────────────────────

deploy:
	cdk deploy --all --require-approval never

synth:
	cdk synth

diff:
	cdk diff --all

teardown-agentcore:
	python scripts/teardown_agentcore.py

destroy: teardown-agentcore
	cdk destroy --all

deploy-foundation:
	cdk deploy FoundationStack --require-approval never

deploy-orchestrator:
	cdk deploy OrchestratorStack --require-approval never

deploy-vendor:
	cdk deploy VendorStack --require-approval never

deploy-approval:
	cdk deploy ApprovalStack --require-approval never

# ─── Demo Setup ───────────────────────────────────────────────────────────────

setup:
	python scripts/setup_demo.py

# ─── Agent Runtime Deployment ─────────────────────────────────────────────────

configure-agents:
	python scripts/configure_agents.py

deploy-agents: configure-agents

# ─── ProcurementGateway Setup ────────────────────────────────────────────────

setup-procurement-gateway:
	python scripts/setup_procurement_gateway.py

# ─── Phase5ApprovalGateway Setup ──────────────────────────────────────────────

setup-phase5-gateway:
	python scripts/setup_phase5_gateway.py

# ─── Workload Identity ────────────────────────────────────────────────────────

setup-identity:
	python scripts/setup_workload_identity.py

# ─── Smoke Test ───────────────────────────────────────────────────────────────

smoke:
	python scripts/smoke_test.py

# ─── Inject gateway URLs into existing runtimes (no code re-deploy) ─────────
# Separate target so make does not deduplicate it when called after configure-agents.

inject-gateway-urls:
	python scripts/configure_agents.py --inject-only

# ─── Full Demo Setup ──────────────────────────────────────────────────────────
# Two-pass configure-agents is intentional:
#   Pass 1 (before gateways): deploys agent code, writes Runtime ARNs to .env.demo.
#   Pass 2 (after gateways):  sets gateway URLs on each runtime.
# GNU make deduplicates identical .PHONY prerequisites, so pass 2 uses the
# dedicated inject-gateway-urls target instead of a second configure-agents call.

demo-setup: deploy setup configure-agents setup-procurement-gateway setup-phase5-gateway inject-gateway-urls setup-identity setup-a2a
	python scripts/toggle_policy_mode.py ENFORCE
	@echo "\n  Full demo environment ready. Cedar is in ENFORCE mode. Run 'make smoke' to verify."

# ─── Warm-Up ──────────────────────────────────────────────────────────────────

warm:
	@echo "Warming agent runtimes (first invocation has cold start latency)..."
	python scripts/invoke_phase1.py --warm-only 2>/dev/null || true
	@echo "Warm-up complete."

# ─── Demo Phases ──────────────────────────────────────────────────────────────

phase1:
	@python scripts/setup_workload_identity.py > /dev/null 2>&1 && echo "  ✓ Resource policy applied — only zt-demo-deployer can invoke the runtime."

phase2:
	python scripts/invoke_phase2.py

phase3:
	python scripts/invoke_phase3.py

phase4:
	python scripts/invoke_phase4.py

setup-a2a:
	python scripts/setup_vendor_resource_policy.py
	python scripts/setup_approval_resource_policy.py

phase5:
	python scripts/invoke_phase5.py

# ─── A2A Resource Policies ────────────────────────────────────────────────────

setup-vendor-resource-policy:
	python scripts/setup_vendor_resource_policy.py

setup-approval-resource-policy:
	python scripts/setup_approval_resource_policy.py

# ─── Demo UI ──────────────────────────────────────────────────────────────────

ui:
	streamlit run streamlit_app.py

# ─── Development ──────────────────────────────────────────────────────────────

dev-orchestrator:
	cd agents/orchestrator && agentcore dev

dev-vendor:
	cd agents/vendor && agentcore dev

dev-approval:
	cd agents/approval && agentcore dev

# ─── Local Testing ────────────────────────────────────────────────────────────

test:
	python -m pytest tests/ -v

test-unit:
	python -m pytest tests/unit/ -v

# ─── Environment ──────────────────────────────────────────────────────────────

install:
	pip install -r requirements.txt
	npm install -g @aws/agentcore

venv:
	python3 -m venv .venv
	@echo "Run: source .venv/bin/activate"

bootstrap:
	cdk bootstrap aws://$$(aws sts get-caller-identity --query Account --output text)/us-east-1
