"""
Securix – Azure Security Checks
CIS Azure Foundations Benchmark 4.0 / ISO 27001
"""

from app.audit.engine.base import CheckResult, Status, check


def _meta(data: dict) -> dict:
    meta = data.get("collection_meta")
    if meta is not None:
        return meta

    collection_ok = data.get("collection_ok", False)
    errors = data.get("errors", [])
    return {
        "identity_ok": collection_ok,
        "resource_ok": collection_ok,
        "identity_errors": errors,
        "resource_errors": errors,
    }


@check(
    check_id="azure_iam_mfa_enabled",
    name="MFA Enabled for All Users",
    description="Ensure multi-factor authentication is enabled for all Azure AD users.",
    provider="azure",
    category="identity",
    severity="critical",
    frameworks={"CIS": "1.1.1", "ISO27001": "A.9.4.2", "NIST": "IA-2"},
    remediation=(
        "Navigate to Azure AD > Users > Per-user MFA and enable MFA for all users. "
        "Or configure Conditional Access policies to require MFA."
    ),
)
def check_mfa_enabled(data: dict) -> CheckResult:
    meta = _meta(data)
    users = data.get("aad_users", [])

    if not meta.get("identity_ok", False):
        return CheckResult(
            check_id="azure_iam_mfa_enabled",
            status=Status.SKIPPED,
            details="Identity data unavailable; MFA could not be evaluated.",
            raw_data={"collection_errors": meta.get("identity_errors", [])},
        )

    unresolved = [u for u in users if u.get("mfa_enabled") is None]
    users_without_mfa = [u for u in users if u.get("mfa_enabled") is False]

    if unresolved:
        return CheckResult(
            check_id="azure_iam_mfa_enabled",
            status=Status.WARNING,
            details=f"MFA status could not be resolved for {len(unresolved)} user(s).",
            raw_data={
                "unresolved_users": [u.get("userPrincipalName") for u in unresolved[:10]],
                "collection_errors": meta.get("identity_errors", []),
            },
        )

    if not users:
        return CheckResult(
            check_id="azure_iam_mfa_enabled",
            status=Status.SKIPPED,
            details="No users returned by Microsoft Graph.",
            raw_data={"collection_errors": meta.get("identity_errors", [])},
        )

    if users_without_mfa:
        names = ", ".join(u.get("userPrincipalName", "?") for u in users_without_mfa[:5])
        return CheckResult(
            check_id="azure_iam_mfa_enabled",
            status=Status.FAIL,
            details=f"{len(users_without_mfa)} user(s) without MFA: {names}",
            raw_data={"users_without_mfa": users_without_mfa},
        )

    return CheckResult(
        check_id="azure_iam_mfa_enabled",
        status=Status.PASS,
        details=f"All {len(users)} users have MFA enabled.",
    )


@check(
    check_id="azure_iam_no_guest_users",
    name="No Unauthorized Guest Users",
    description="Ensure guest user count is minimized and reviewed.",
    provider="azure",
    category="identity",
    severity="medium",
    frameworks={"CIS": "1.3", "ISO27001": "A.9.2.6"},
    remediation="Review and remove guest users that are no longer needed via Azure AD > Users > Guest users.",
)
def check_no_guest_users(data: dict) -> CheckResult:
    meta = _meta(data)
    users = data.get("aad_users", [])

    if not meta.get("identity_ok", False):
        return CheckResult(
            check_id="azure_iam_no_guest_users",
            status=Status.SKIPPED,
            details="Identity data unavailable; guest user review could not be evaluated.",
            raw_data={"collection_errors": meta.get("identity_errors", [])},
        )

    guests = [u for u in users if u.get("userType") == "Guest"]

    if len(guests) == 0:
        return CheckResult(
            check_id="azure_iam_no_guest_users",
            status=Status.PASS,
            details="No guest users found.",
        )
    if len(guests) <= 5:
        return CheckResult(
            check_id="azure_iam_no_guest_users",
            status=Status.WARNING,
            details=f"{len(guests)} guest user(s) found. Review if still needed.",
            raw_data={"guests": guests},
        )
    return CheckResult(
        check_id="azure_iam_no_guest_users",
        status=Status.FAIL,
        details=f"{len(guests)} guest users found — excessive number.",
        raw_data={"guests": guests},
    )


@check(
    check_id="azure_iam_privileged_roles_reviewed",
    name="Privileged Role Assignments Reviewed",
    description="Global Administrator role should be assigned to fewer than 5 users.",
    provider="azure",
    category="identity",
    severity="high",
    frameworks={"CIS": "1.21", "ISO27001": "A.9.2.3"},
    remediation="Use Azure PIM (Privileged Identity Management) for just-in-time privileged access.",
)
def check_privileged_roles(data: dict) -> CheckResult:
    meta = _meta(data)
    role_assignments = data.get("role_assignments", [])

    if not meta.get("resource_ok", False):
        return CheckResult(
            check_id="azure_iam_privileged_roles_reviewed",
            status=Status.SKIPPED,
            details="Role assignment data unavailable; privileged role review could not be evaluated.",
            raw_data={"collection_errors": meta.get("resource_errors", [])},
        )

    global_admins = [
        r for r in role_assignments
        if r.get("roleDefinitionName") == "Global Administrator"
    ]

    count = len(global_admins)
    if count == 0:
        return CheckResult(
            check_id="azure_iam_privileged_roles_reviewed",
            status=Status.WARNING,
            details="No Global Administrators found — verify role assignment collection and tenant scope.",
        )
    if count <= 4:
        return CheckResult(
            check_id="azure_iam_privileged_roles_reviewed",
            status=Status.PASS,
            details=f"{count} Global Administrator(s) assigned (within limit).",
        )
    return CheckResult(
        check_id="azure_iam_privileged_roles_reviewed",
        status=Status.FAIL,
        details=f"{count} Global Administrators — exceeds recommended maximum of 4.",
        raw_data={"admins": global_admins},
    )


@check(
    check_id="azure_storage_no_public_blobs",
    name="No Publicly Accessible Storage Blobs",
    description="Ensure that blob containers do not have public access enabled.",
    provider="azure",
    category="storage",
    severity="critical",
    frameworks={"CIS": "3.5", "ISO27001": "A.8.2.3"},
    remediation="Set 'Public access level' to 'Private' on all blob containers.",
)
def check_no_public_blobs(data: dict) -> CheckResult:
    meta = _meta(data)
    storage_accounts = data.get("storage_accounts", [])

    if not meta.get("resource_ok", False):
        return CheckResult(
            check_id="azure_storage_no_public_blobs",
            status=Status.SKIPPED,
            details="Storage data unavailable; public blob exposure could not be evaluated.",
            raw_data={"collection_errors": meta.get("resource_errors", [])},
        )

    public_containers = []
    for account in storage_accounts:
        for container in account.get("containers", []):
            props = container.get("properties", container)
            access = props.get("publicAccess") or container.get("publicAccess")
            if access in ("Blob", "Container"):
                public_containers.append(
                    {
                        "account": account.get("name"),
                        "container": container.get("name"),
                        "access_level": access,
                    }
                )

    if not public_containers:
        return CheckResult(
            check_id="azure_storage_no_public_blobs",
            status=Status.PASS,
            details="No publicly accessible blob containers found.",
        )

    return CheckResult(
        check_id="azure_storage_no_public_blobs",
        status=Status.FAIL,
        details=f"{len(public_containers)} publicly accessible container(s) found.",
        raw_data={"public_containers": public_containers},
    )


@check(
    check_id="azure_storage_encryption_at_rest",
    name="Storage Encryption at Rest Enabled",
    description="Ensure Azure Storage accounts have encryption at rest enabled.",
    provider="azure",
    category="storage",
    severity="high",
    frameworks={"CIS": "3.2", "ISO27001": "A.10.1.1"},
    remediation="Enable Storage Service Encryption (SSE) in Azure Storage > Encryption settings.",
)
def check_storage_encryption(data: dict) -> CheckResult:
    meta = _meta(data)
    accounts = data.get("storage_accounts", [])

    if not meta.get("resource_ok", False):
        return CheckResult(
            check_id="azure_storage_encryption_at_rest",
            status=Status.SKIPPED,
            details="Storage data unavailable; encryption-at-rest could not be evaluated.",
            raw_data={"collection_errors": meta.get("resource_errors", [])},
        )

    unencrypted = []
    for account in accounts:
        props = account.get("properties", account)
        encryption = props.get("encryption", account.get("encryption", {}))
        blob_service = encryption.get("services", {}).get("blob", {})
        if not blob_service.get("enabled", False):
            unencrypted.append(account)

    if not unencrypted:
        return CheckResult(
            check_id="azure_storage_encryption_at_rest",
            status=Status.PASS,
            details=f"All {len(accounts)} storage account(s) have encryption enabled.",
        )

    return CheckResult(
        check_id="azure_storage_encryption_at_rest",
        status=Status.FAIL,
        details=f"{len(unencrypted)} storage account(s) without encryption.",
        raw_data={"unencrypted": unencrypted},
    )


@check(
    check_id="azure_network_no_rdp_open",
    name="No Unrestricted RDP Access (Port 3389)",
    description="Ensure no Network Security Group allows unrestricted inbound RDP.",
    provider="azure",
    category="network",
    severity="critical",
    frameworks={"CIS": "6.1", "ISO27001": "A.13.1.1"},
    remediation="Remove or restrict NSG rules allowing inbound 3389 from 0.0.0.0/0.",
)
def check_no_open_rdp(data: dict) -> CheckResult:
    meta = _meta(data)
    nsgs = data.get("network_security_groups", [])

    if not meta.get("resource_ok", False):
        return CheckResult(
            check_id="azure_network_no_rdp_open",
            status=Status.SKIPPED,
            details="NSG data unavailable; RDP exposure could not be evaluated.",
            raw_data={"collection_errors": meta.get("resource_errors", [])},
        )

    risky_rules = []
    for nsg in nsgs:
        rules = nsg.get("properties", {}).get("securityRules", nsg.get("securityRules", []))
        for rule in rules:
            props = rule.get("properties", rule)
            if (
                props.get("direction") == "Inbound"
                and props.get("access") == "Allow"
                and props.get("destinationPortRange") in ("3389", "*")
                and props.get("sourceAddressPrefix") in ("*", "Internet", "0.0.0.0/0")
            ):
                risky_rules.append({"nsg": nsg.get("name"), "rule": rule.get("name")})

    if not risky_rules:
        return CheckResult(
            check_id="azure_network_no_rdp_open",
            status=Status.PASS,
            details="No unrestricted RDP inbound rules found.",
        )

    return CheckResult(
        check_id="azure_network_no_rdp_open",
        status=Status.FAIL,
        details=f"{len(risky_rules)} NSG rule(s) expose RDP to the internet.",
        raw_data={"risky_rules": risky_rules},
    )


@check(
    check_id="azure_network_no_ssh_open",
    name="No Unrestricted SSH Access (Port 22)",
    description="Ensure no NSG allows unrestricted inbound SSH from the internet.",
    provider="azure",
    category="network",
    severity="critical",
    frameworks={"CIS": "6.2", "ISO27001": "A.13.1.1"},
    remediation="Restrict SSH access to known IP ranges or use Azure Bastion.",
)
def check_no_open_ssh(data: dict) -> CheckResult:
    meta = _meta(data)
    nsgs = data.get("network_security_groups", [])

    if not meta.get("resource_ok", False):
        return CheckResult(
            check_id="azure_network_no_ssh_open",
            status=Status.SKIPPED,
            details="NSG data unavailable; SSH exposure could not be evaluated.",
            raw_data={"collection_errors": meta.get("resource_errors", [])},
        )

    risky_rules = []
    for nsg in nsgs:
        rules = nsg.get("properties", {}).get("securityRules", nsg.get("securityRules", []))
        for rule in rules:
            props = rule.get("properties", rule)
            if (
                props.get("direction") == "Inbound"
                and props.get("access") == "Allow"
                and props.get("destinationPortRange") in ("22", "*")
                and props.get("sourceAddressPrefix") in ("*", "Internet", "0.0.0.0/0")
            ):
                risky_rules.append({"nsg": nsg.get("name"), "rule": rule.get("name")})

    if not risky_rules:
        return CheckResult(
            check_id="azure_network_no_ssh_open",
            status=Status.PASS,
            details="No unrestricted SSH inbound rules found.",
        )

    return CheckResult(
        check_id="azure_network_no_ssh_open",
        status=Status.FAIL,
        details=f"{len(risky_rules)} NSG rule(s) expose SSH to the internet.",
        raw_data={"risky_rules": risky_rules},
    )


@check(
    check_id="azure_monitor_diagnostic_settings",
    name="Diagnostic Settings Enabled on Subscriptions",
    description="Ensure activity logs are collected via diagnostic settings.",
    provider="azure",
    category="monitoring",
    severity="high",
    frameworks={"CIS": "5.1.1", "ISO27001": "A.12.4.1"},
    remediation="Enable diagnostic settings on your subscription and route logs to a Log Analytics workspace or storage account.",
)
def check_diagnostic_settings(data: dict) -> CheckResult:
    meta = _meta(data)
    settings = data.get("diagnostic_settings", [])

    if not meta.get("resource_ok", False):
        return CheckResult(
            check_id="azure_monitor_diagnostic_settings",
            status=Status.SKIPPED,
            details="Diagnostic settings data unavailable; logging coverage could not be evaluated.",
            raw_data={"collection_errors": meta.get("resource_errors", [])},
        )

    if settings:
        return CheckResult(
            check_id="azure_monitor_diagnostic_settings",
            status=Status.PASS,
            details=f"{len(settings)} diagnostic setting(s) configured.",
        )

    return CheckResult(
        check_id="azure_monitor_diagnostic_settings",
        status=Status.FAIL,
        details="No diagnostic settings configured for this subscription.",
    )


def evaluate_azure_checks(inventory: dict) -> list[dict]:
    checks = [
        check_mfa_enabled,
        check_no_guest_users,
        check_privileged_roles,
        check_no_public_blobs,
        check_storage_encryption,
        check_no_open_rdp,
        check_no_open_ssh,
        check_diagnostic_settings,
    ]

    results = []
    for func in checks:
        metadata = getattr(func, "_check_meta", {})
        result = func(inventory).to_dict()
        result.update(
            {
                "title": metadata.get("name", result["check_id"]),
                "severity": metadata.get("severity", "medium"),
                "remediation": metadata.get("remediation", ""),
                "category": metadata.get("category"),
                "provider": metadata.get("provider"),
                "frameworks": metadata.get("frameworks", {}),
                "description": metadata.get("description", ""),
            }
        )
        results.append(result)

    return results
