// procurement-orchestrator.cedar
//
// OrchestratorAgent → read_invoice, show_identity
//
// Cedar evaluates principal.id (the IAM execution role ARN) on every tool call.
// Only the orchestrator execution role can access these tools.
// Default deny: any other IAM principal is blocked (no matching permit).

permit (
    principal is AgentCore::IamEntity,
    action in [
        AgentCore::Action::"ProcurementTools-read-invoice___read_invoice",
        AgentCore::Action::"ProcurementTools-show-identity___show_identity"
    ],
    resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
) when {
    principal.id like "*zt-demo-orchestrator-execution-role*"
};
