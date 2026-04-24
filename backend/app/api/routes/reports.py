from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.models import Audit, Finding
from app.reporting.generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{audit_id}")
async def generate_report(
    audit_id: int,
    format: str = Query("json", pattern="^(json|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    audit_row = await db.execute(select(Audit).where(Audit.id == audit_id))
    audit = audit_row.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    findings_row = await db.execute(select(Finding).where(Finding.audit_id == audit_id))
    findings = findings_row.scalars().all()

    payload = {
        "audit": {
            "id": audit.id,
            "name": audit.name,
            "provider": audit.provider,
            "tool": audit.tool,
            "score": audit.score,
            "coverage_percent": audit.coverage_percent,
            "status": audit.status.value,
            "collection_summary": audit.collection_summary,
            "run_error": audit.run_error,
        },
        "findings": [
            {
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
        ],
    }
    if format == "pdf":
        return Response(
            content=ReportGenerator.as_pdf(payload),
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="audit-{audit_id}.pdf"'},
        )
    return Response(content=ReportGenerator.as_json(payload), media_type="application/json")
