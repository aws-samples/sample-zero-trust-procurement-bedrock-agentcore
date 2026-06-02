// procurement-approval-limit.cedar
//
// Forbid approve_payment when amount >= 500.
//
// Cedar evaluates forbid before permit — if this rule matches, the call is
// denied regardless of the permit in procurement-approval.cedar. This generates
// a visible DENY decision span in CloudWatch (aws/spans) with the determining
// policy name. Lambda invocation count = 0 for denied calls.

forbid (
    principal is AgentCore::IamEntity,
    action == AgentCore::Action::"ProcurementTools-approve-payment___approve_payment",
    resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
) when {
    context.input has amount &&
    context.input.amount >= 500
};
