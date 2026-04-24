def evaluate_aws_checks(inventory: dict) -> list[dict]:
    resources = inventory.get("resources", {})
    collection_ok = inventory.get("collection_ok", False)

    root_keys_present = resources.get("root_keys_present")
    return [
        {
            "check_id": "AWS-CIS-1.4",
            "title": "Root account access keys are absent",
            "severity": "critical",
            "status": (
                "pass"
                if collection_ok and root_keys_present is False
                else "fail"
                if collection_ok and root_keys_present is True
                else "unknown"
            ),
            "evidence": {
                "account_id": resources.get("account_id"),
                "root_keys_present": root_keys_present,
                "collection_errors": inventory.get("errors", []),
            },
            "remediation": "Delete root keys and enforce IAM user access.",
        },
        {
            "check_id": "AWS-CIS-1.5",
            "title": "IAM footprint is discoverable",
            "severity": "low",
            "status": "pass" if collection_ok else "unknown",
            "evidence": {
                "iam_users_count": resources.get("iam_users_count"),
                "collection_errors": inventory.get("errors", []),
            },
            "remediation": "Ensure least-privilege access reviews are scheduled.",
        },
    ]
