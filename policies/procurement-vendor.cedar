// procurement-vendor.cedar
//
// VendorAgent → validate_vendor, get_vendor_terms
//
// Only the vendor execution role can access vendor tools.
// The VendorAgent cannot call approve_payment or read_invoice —
// Cedar default-deny blocks any action without a matching permit.

permit (
    principal is AgentCore::IamEntity,
    action in [
        AgentCore::Action::"ProcurementTools-validate-vendor___validate_vendor",
        AgentCore::Action::"ProcurementTools-get-vendor-terms___get_vendor_terms"
    ],
    resource == AgentCore::Gateway::"{{GATEWAY_ARN}}"
) when {
    principal.id like "*zt-demo-vendor-execution-role*"
};
