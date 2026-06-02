// procurement-approval.cedar
//
// ApprovalAgent → approve_payment + get_approval_status
//
// Permits the approval agent to call both tools. The companion forbid rule
// (procurement-approval-limit.cedar) blocks approve_payment when amount >= 500.

permit (
    principal is AgentCore::IamEntity,
    action in [
        AgentCore::Action::"ProcurementTools-approve-payment___approve_payment",
        AgentCore::Action::"ProcurementTools-get-approval-status___get_approval_status"
    ],
    resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
) when {
    principal.id like "*zt-demo-approval-execution-role*"
};
