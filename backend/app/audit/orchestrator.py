from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, select

from app.db.session import AsyncSessionLocal
from app.integrations import (
    InternalAuditAdapter,
    MaesterAuditAdapter,
    ProwlerAuditAdapter,
    SteampipeAuditAdapter,
)
from app.models.models import Audit, AuditStatus, Finding, Severity
from app.normalization import normalize_findings
from app.scoring import ScoringEngine


@dataclass
class AuditExecutionResult:
    audit_id: int
    status: str
    tool: str
    score: int
    coverage_percent: int
    run_error: str | None
    summary: dict
    findings: list[dict]


class AuditOrchestrator:
    adapters = {
        "internal": InternalAuditAdapter(),
        "prowler": ProwlerAuditAdapter(),
        "maester": MaesterAuditAdapter(),
        "steampipe": SteampipeAuditAdapter(),
    }

    @classmethod
    async def run_adapter(cls, audit: Audit):
        tool = audit.tool.lower()
        adapter = cls.adapters.get(tool)
        if not adapter:
            raise ValueError(f"Unsupported audit tool: {tool}")
        if audit.provider.lower() not in adapter.supported_providers:
            raise ValueError(f"Tool '{tool}' does not support provider '{audit.provider}'")
        return await adapter.run(audit)


def _severity_from_string(value: str) -> Severity:
    normalized = (value or "medium").lower()
    mapping = {
        "critical": Severity.critical,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
        "info": Severity.low,
    }
    return mapping.get(normalized, Severity.medium)


async def execute_audit_job(audit_id: int) -> AuditExecutionResult:
    async with AsyncSessionLocal() as db:
        row = await db.execute(select(Audit).where(Audit.id == audit_id))
        audit = row.scalar_one_or_none()
        if not audit:
            raise ValueError(f"Audit {audit_id} not found")

        audit.status = AuditStatus.running
        audit.run_error = None
        audit.finished_at = None
        await db.commit()
        await db.refresh(audit)

        try:
            adapter_result = await AuditOrchestrator.run_adapter(audit)
            normalized = normalize_findings(adapter_result)
            scorecard = ScoringEngine.calculate(normalized)

            await db.execute(delete(Finding).where(Finding.audit_id == audit.id))
            for item in normalized:
                finding = Finding(
                    audit_id=audit.id,
                    tool=item.tool,
                    provider=item.provider,
                    check_id=item.check_id,
                    title=item.title,
                    severity=_severity_from_string(item.severity),
                    status=item.status,
                    resource_id=item.resource_id,
                    evidence=item.evidence,
                    remediation=item.remediation,
                    compliance=item.compliance,
                )
                db.add(finding)

            summary = {
                "provider": audit.provider,
                "tool": audit.tool,
                **adapter_result.summary,
                **scorecard.to_dict(),
                "raw_artifact_path": adapter_result.raw_artifact_path,
            }

            audit.score = scorecard.score
            audit.coverage_percent = scorecard.coverage_percent
            audit.collection_summary = summary
            audit.run_error = adapter_result.run_error
            audit.status = AuditStatus.failed if adapter_result.run_error and not normalized else AuditStatus.completed
            audit.finished_at = datetime.utcnow()
            await db.commit()

            return AuditExecutionResult(
                audit_id=audit.id,
                status=audit.status.value,
                tool=audit.tool,
                score=audit.score,
                coverage_percent=audit.coverage_percent,
                run_error=audit.run_error,
                summary=summary,
                findings=[item.to_dict() for item in normalized],
            )
        except Exception as exc:
            audit.status = AuditStatus.failed
            audit.score = 0
            audit.coverage_percent = 0
            audit.run_error = str(exc)
            audit.collection_summary = {"provider": audit.provider, "tool": audit.tool}
            audit.finished_at = datetime.utcnow()
            await db.commit()

            return AuditExecutionResult(
                audit_id=audit.id,
                status=audit.status.value,
                tool=audit.tool,
                score=audit.score,
                coverage_percent=audit.coverage_percent,
                run_error=audit.run_error,
                summary=audit.collection_summary,
                findings=[],
            )
