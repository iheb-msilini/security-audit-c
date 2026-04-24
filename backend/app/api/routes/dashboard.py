from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.models import Audit, AuditStatus

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db)) -> dict:
    total = await db.scalar(select(func.count(Audit.id)))
    avg_score = await db.scalar(select(func.coalesce(func.avg(Audit.score), 0)))
    avg_coverage = await db.scalar(select(func.coalesce(func.avg(Audit.coverage_percent), 0)))
    completed = await db.scalar(
        select(func.count(Audit.id)).where(Audit.status == AuditStatus.completed)
    )
    return {
        "total_audits": total or 0,
        "completed_audits": completed or 0,
        "average_score": round(float(avg_score), 2),
        "average_coverage": round(float(avg_coverage), 2),
    }
