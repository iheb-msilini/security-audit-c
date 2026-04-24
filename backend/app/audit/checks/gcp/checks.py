def evaluate_gcp_checks(inventory: dict) -> list[dict]:
    resources = inventory.get("resources", {})
    collection_ok = inventory.get("collection_ok", False)
    primitive_bindings = resources.get("primitive_role_bindings")

    return [
        {
            "check_id": "GCP-CIS-1.1",
            "title": "No primitive roles used",
            "severity": "high",
            "status": (
                "pass"
                if collection_ok and primitive_bindings == 0
                else "fail"
                if collection_ok and isinstance(primitive_bindings, int) and primitive_bindings > 0
                else "unknown"
            ),
            "evidence": {
                "primitive_role_bindings": primitive_bindings,
                "collection_errors": inventory.get("errors", []),
            },
            "remediation": "Replace primitive roles with least-privilege custom roles.",
        },
        {
            "check_id": "GCP-CIS-3.1",
            "title": "Project and bucket inventory is discoverable",
            "severity": "low",
            "status": "pass" if collection_ok else "unknown",
            "evidence": {
                "projects_count": resources.get("projects_count"),
                "buckets_count": resources.get("buckets_count"),
                "collection_errors": inventory.get("errors", []),
            },
            "remediation": "Ensure continuous inventory collection is configured.",
        },
    ]
