// phase5-approval-limit.cedar
//
// Phase 5 OBO: forbid approve_payment when amount >= 500.
// Applies on Phase5ApprovalGateway (AgentCore::OAuthUser principal).
//
// Cedar evaluates forbid before permit — if this rule matches, the call is
// denied regardless of the permit in phase5-approval-obo.cedar.

forbid (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"ProcurementTools-approve-payment___approve_payment",
    resource == AgentCore::Gateway::"{{PHASE5_GATEWAY_ARN}}"
) when {
    context.input has amount &&
    context.input.amount >= 500
};
