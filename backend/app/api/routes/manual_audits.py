from fastapi import APIRouter

router = APIRouter(prefix="/manual-audits", tags=["manual-audits"])


@router.get("")
async def list_manual_items() -> list[dict]:
    return [
        {"id": "MAN-001", "title": "Verify incident response contacts", "status": "todo"},
        {"id": "MAN-002", "title": "Review break-glass account policy", "status": "todo"},
    ]
