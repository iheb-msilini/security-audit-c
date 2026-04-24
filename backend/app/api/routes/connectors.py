from fastapi import APIRouter

from app.integrations.prowler_adapter import ProwlerAuditAdapter

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get("")
async def connector_status() -> list[dict]:
    return [
        {"tool": "internal", "providers": ["aws", "azure", "gcp"], "status": "available"},
        {"tool": "prowler", "providers": ["aws", "azure", "gcp"], "status": "adapter-ready"},
        {"tool": "maester", "providers": ["m365"], "status": "adapter-ready"},
        {"tool": "steampipe", "providers": ["aws", "azure", "gcp", "multi"], "status": "adapter-ready"},
    ]


@router.get("/diagnostics/prowler")
async def prowler_diagnostics() -> dict:
    adapter = ProwlerAuditAdapter()
    return await adapter.diagnose_runtime()
