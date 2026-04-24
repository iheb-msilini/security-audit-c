from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.models import Audit

router = APIRouter(prefix="/scoring", tags=["scoring"])


@router.get("/{audit_id}")
async def score_breakdown(audit_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    row = await db.execute(select(Audit).where(Audit.id == audit_id))
    audit = row.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    summary = audit.collection_summary or {}
    return {
        "audit_id": audit.id,
        "tool": audit.tool,
        "provider": audit.provider,
        "framework": audit.framework,
        "score": audit.score,
        "coverage_percent": audit.coverage_percent,
        "maturity": summary.get("maturity"),
        "counts_by_status": summary.get("counts_by_status", {}),
        "severity_breakdown": summary.get("severity_breakdown", {}),
    }
