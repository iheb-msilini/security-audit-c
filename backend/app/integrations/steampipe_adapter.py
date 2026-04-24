import asyncio
import json
import os
import shutil

from app.integrations.base import AdapterRunResult


class SteampipeAuditAdapter:
    tool_name = "steampipe"
    supported_providers = {"aws", "azure", "gcp", "multi"}

    async def run(self, audit: object) -> AdapterRunResult:
        provider = str(getattr(audit, "provider", "")).lower()
        steampipe_bin = shutil.which(os.getenv("STEAMPIPE_BIN", "steampipe"))
        if not steampipe_bin:
            return AdapterRunResult(
                tool=self.tool_name,
                provider=provider,
                run_error="Steampipe binary not found in PATH",
            )

        query = os.getenv(
            "STEAMPIPE_DEFAULT_QUERY",
            "select 'inventory' as control, 'pass' as status, 'sample-resource' as resource;",
        )
        process = await asyncio.create_subprocess_exec(
            steampipe_bin,
            "query",
            query,
            "--output",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            message = stderr.decode().strip() or "Steampipe execution failed"
            return AdapterRunResult(tool=self.tool_name, provider=provider, run_error=message)

        raw_data = json.loads(stdout.decode() or "[]")
        raw_findings = raw_data if isinstance(raw_data, list) else []
        return AdapterRunResult(
            tool=self.tool_name,
            provider=provider,
            raw_findings=raw_findings,
            summary={"provider": provider, "rows": len(raw_findings)},
        )
