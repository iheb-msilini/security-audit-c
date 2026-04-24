from app.audit.engine.runner import AuditEngine
from app.integrations.base import AdapterRunResult


class InternalAuditAdapter:
    tool_name = "internal"
    supported_providers = {"aws", "azure", "gcp"}

    async def run(self, audit: object) -> AdapterRunResult:
        provider = str(getattr(audit, "provider", "")).lower()
        report = await AuditEngine.run(provider)
        return AdapterRunResult(
            tool=self.tool_name,
            provider=provider,
            raw_findings=report.get("findings", []),
            summary=report.get("collection_summary", {}),
            run_error=report.get("run_error"),
        )
