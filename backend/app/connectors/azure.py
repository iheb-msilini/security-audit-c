from typing import Any


async def collect_azure_inventory() -> dict[str, Any]:
    """
    Collect Azure inventory using DefaultAzureCredential.
    """
    inventory: dict[str, Any] = {
        "provider": "azure",
        "collection_ok": False,
        "resources": {},
        "errors": [],
    }
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except Exception as exc:
        inventory["errors"].append(f"sdk_unavailable: {exc}")
        return inventory

    try:
        credential = DefaultAzureCredential()
        sub_client = SubscriptionClient(credential)
        subs = list(sub_client.subscriptions.list())
        subscription_ids = [s.subscription_id for s in subs if s.subscription_id]
        storage_count = 0
        for sid in subscription_ids:
            st_client = StorageManagementClient(credential, sid)
            storage_count += sum(1 for _ in st_client.storage_accounts.list())
        inventory["collection_ok"] = True
        inventory["resources"] = {
            "subscriptions_count": len(subscription_ids),
            "storage_accounts_count": storage_count,
            "privileged_without_mfa": None,  # Requires Entra/Graph permissions and extra API path.
        }
    except Exception as exc:
        inventory["errors"].append(f"azure_api_error: {exc}")

    return inventory
