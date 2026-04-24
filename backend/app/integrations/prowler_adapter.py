import asyncio
import json
import os
import shutil
from pathlib import Path

from app.integrations.base import AdapterRunResult


class ProwlerAuditAdapter:
    tool_name = "prowler"
    supported_providers = {"aws", "azure", "gcp"}

    async def run(self, audit: object) -> AdapterRunResult:
        provider = str(getattr(audit, "provider", "")).lower()
        prowler_bin = shutil.which(os.getenv("PROWLER_BIN", "prowler"))
        if not prowler_bin:
            return AdapterRunResult(
                tool=self.tool_name,
                provider=provider,
                run_error="Prowler binary not found in PATH",
            )

        output_dir = Path("/tmp/securite-audit/prowler") / str(getattr(audit, "id", "adhoc"))
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "results.json"

        cmd = [
            prowler_bin,
            provider,
            "--output-formats",
            "json",
            "--output-filename",
            "results",
            "--output-directory",
            str(output_dir),
        ]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            message = stderr.decode().strip() or "Prowler execution failed"
            return AdapterRunResult(tool=self.tool_name, provider=provider, run_error=message)

        raw_findings: list[dict] = []
        if output_file.exists():
            raw_findings = json.loads(output_file.read_text())

        return AdapterRunResult(
            tool=self.tool_name,
            provider=provider,
            raw_findings=raw_findings if isinstance(raw_findings, list) else [],
            summary={"provider": provider, "raw_artifact_path": str(output_file)},
            raw_artifact_path=str(output_file),
        )
