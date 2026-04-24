from typing import Any


async def collect_gcp_inventory() -> dict[str, Any]:
    """
    Collect GCP inventory from Application Default Credentials.
    """
    inventory: dict[str, Any] = {
        "provider": "gcp",
        "collection_ok": False,
        "resources": {},
        "errors": [],
    }
    try:
        import google.auth
        from google.cloud import resourcemanager_v3, storage
    except Exception as exc:
        inventory["errors"].append(f"sdk_unavailable: {exc}")
        return inventory

    try:
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        projects_client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        storage_client = storage.Client(credentials=credentials)

        projects = [p for p in projects_client.search_projects()]
        project_ids = [p.project_id for p in projects if p.project_id]
        buckets_count = 0
        for pid in project_ids:
            buckets_count += sum(1 for _ in storage_client.list_buckets(project=pid))

        inventory["collection_ok"] = True
        inventory["resources"] = {
            "projects_count": len(project_ids),
            "buckets_count": buckets_count,
            "primitive_role_bindings": None,  # Requires Cloud Asset/IAM policy traversal.
        }
    except Exception as exc:
        inventory["errors"].append(f"gcp_api_error: {exc}")

    return inventory
