from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.orchestrator import execute_audit_job
from app.db.session import get_db
from app.models.models import Audit, AuditStatus
from app.tasks.audit_tasks import dispatch_audit_job

router = APIRouter(prefix="/audits", tags=["audits"])
INLINE_SAFE_TOOLS = {"internal"}


def _diagnostics_excerpt(summary: dict | None, run_error: str | None) -> str | None:
    if not summary:
        return run_error

    diagnostics = summary.get("diagnostics") or {}
    resolved_command = summary.get("resolved_command") or diagnostics.get("resolved_command")
    path_candidates = diagnostics.get("path_binary_candidates") or []
    scripts = diagnostics.get("scripts_matching_prowler") or []
    modules = diagnostics.get("module_candidates") or []

    parts = []
    if run_error:
        parts.append(run_error)
    if resolved_command:
        parts.append(f"resolved_command={resolved_command}")
    if path_candidates:
        parts.append(f"path_candidates={path_candidates[:2]}")
    if scripts:
        parts.append(f"scripts={scripts[:3]}")
    if modules:
        parts.append(f"modules={modules[:4]}")

    return " | ".join(parts) if parts else None


class AuditCreate(BaseModel):
    name: str
    provider: str
    framework: str = "CIS"
    tool: str = "internal"


@router.get("")
async def list_audits(db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = await db.execute(select(Audit).order_by(Audit.created_at.desc()))
    audits = rows.scalars().all()

    return [
        {
            "id": a.id,
            "name": a.name,
            "provider": a.provider,
            "framework": a.framework,
            "tool": a.tool,
            "status": a.status.value,
            "score": a.score,
            "coverage_percent": a.coverage_percent,
            "collection_summary": a.collection_summary,
            "run_error": a.run_error,
            "diagnostics_excerpt": _diagnostics_excerpt(a.collection_summary, a.run_error)
            if a.status == AuditStatus.failed
            else None,
            "created_at": a.created_at.isoformat(),
        }
        for a in audits
    ]


@router.post("")
async def create_audit(payload: AuditCreate, db: AsyncSession = Depends(get_db)) -> dict:
    audit = Audit(
        name=payload.name,
        provider=payload.provider.lower(),
        framework=payload.framework.upper(),
        tool=payload.tool.lower(),
        status=AuditStatus.pending,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(audit)

    return {"id": audit.id, "status": audit.status.value, "tool": audit.tool}


@router.post("/{audit_id}/trigger")
async def trigger_audit(audit_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    row = await db.execute(select(Audit).where(Audit.id == audit_id))
    audit = row.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    if audit.status == AuditStatus.running:
        raise HTTPException(status_code=409, detail="Audit is already running")

    audit.status = AuditStatus.running
    audit.run_error = None
    audit.finished_at = None
    await db.commit()

    try:
        task = dispatch_audit_job(audit.id, audit.tool)
        return {
            "audit_id": audit.id,
            "status": audit.status.value,
            "tool": audit.tool,
            "execution_mode": "celery",
            "task_id": task.id,
        }
    except Exception as exc:
        if audit.tool not in INLINE_SAFE_TOOLS:
            audit.status = AuditStatus.pending
            await db.commit()
            raise HTTPException(
                status_code=503,
                detail=f"Audit queue unavailable for tool '{audit.tool}': {exc}",
            ) from exc

        result = await execute_audit_job(audit.id)
        return {
            "audit_id": result.audit_id,
            "status": result.status,
            "tool": result.tool,
            "score": result.score,
            "coverage_percent": result.coverage_percent,
            "run_error": result.run_error,
            "diagnostics_excerpt": _diagnostics_excerpt(result.summary, result.run_error),
            "execution_mode": "inline",
        }
