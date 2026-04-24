import asyncio
import json

from app.integrations.prowler_adapter import ProwlerAuditAdapter


async def main() -> None:
    adapter = ProwlerAuditAdapter()
    payload = await adapter.diagnose_runtime()
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
