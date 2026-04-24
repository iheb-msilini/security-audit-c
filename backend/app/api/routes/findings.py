from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.models import Finding

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/{audit_id}")
async def list_findings(audit_id: int, db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = await db.execute(select(Finding).where(Finding.audit_id == audit_id))
    findings = rows.scalars().all()
    return [
        {
            "id": f.id,
            "tool": f.tool,
            "provider": f.provider,
            "check_id": f.check_id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status,
            "resource_id": f.resource_id,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "compliance": f.compliance,
        }
        for f in findings
    ]
