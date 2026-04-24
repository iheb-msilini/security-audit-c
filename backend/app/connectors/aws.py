from typing import Any


async def collect_aws_inventory() -> dict[str, Any]:
    """
    Collect AWS inventory via boto3 with current environment credentials.
    Returns structured data plus collection metadata.
    """
    inventory: dict[str, Any] = {
        "provider": "aws",
        "collection_ok": False,
        "resources": {},
        "errors": [],
    }
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except Exception as exc:
        inventory["errors"].append(f"sdk_unavailable: {exc}")
        return inventory

    try:
        session = boto3.session.Session()
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account")
        iam = session.client("iam")
        users = iam.list_users(MaxItems=100).get("Users", [])

        inventory["collection_ok"] = True
        inventory["resources"] = {
            "account_id": account_id,
            "iam_users_count": len(users),
            "root_keys_present": False,  # Not inferable directly without credential report parsing.
        }
    except (NoCredentialsError, BotoCoreError, ClientError) as exc:
        inventory["errors"].append(f"aws_api_error: {exc}")
    except Exception as exc:
        inventory["errors"].append(f"unexpected_error: {exc}")

    return inventory
