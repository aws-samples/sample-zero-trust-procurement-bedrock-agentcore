// phase5-approval-obo.cedar
//
// Phase 5 OBO: enforce user role via JWT claim on Phase5ApprovalGateway.
// Principal is AgentCore::OAuthUser — Cognito ID token presented as Bearer.
// role claim (injected by Cognito pre-token Lambda) is mapped to principal tag.
//
// Only admin users (role == "admin") may call approve_payment or get_approval_status.
// Operators are denied (no matching permit).

permit (
    principal is AgentCore::OAuthUser,
    action in [
        AgentCore::Action::"ProcurementTools-approve-payment___approve_payment",
        AgentCore::Action::"ProcurementTools-get-approval-status___get_approval_status"
    ],
    resource == AgentCore::Gateway::"{{PHASE5_GATEWAY_ARN}}"
) when {
    principal.hasTag("role") &&
    principal.getTag("role") == "admin"
};
