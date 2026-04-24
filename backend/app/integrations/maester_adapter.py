import asyncio
import json
import os
import shutil
from pathlib import Path

from app.integrations.base import AdapterRunResult


class MaesterAuditAdapter:
    tool_name = "maester"
    supported_providers = {"m365"}

    async def run(self, audit: object) -> AdapterRunResult:
        pwsh_bin = shutil.which(os.getenv("POWERSHELL_BIN", "pwsh"))
        if not pwsh_bin:
            return AdapterRunResult(
                tool=self.tool_name,
                provider="m365",
                run_error="PowerShell (pwsh) not found in PATH for Maester execution",
            )

        output_dir = Path("/tmp/securite-audit/maester") / str(getattr(audit, "id", "adhoc"))
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "results.json"
        script = (
            "Import-Module Maester -ErrorAction Stop; "
            f"Invoke-Maester -Format Json -OutputPath '{output_file}'"
        )
        process = await asyncio.create_subprocess_exec(
            pwsh_bin,
            "-NoProfile",
            "-Command",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            message = stderr.decode().strip() or "Maester execution failed"
            return AdapterRunResult(tool=self.tool_name, provider="m365", run_error=message)

        raw_findings: list[dict] = []
        if output_file.exists():
            raw_data = json.loads(output_file.read_text())
            raw_findings = raw_data if isinstance(raw_data, list) else raw_data.get("results", [])

        return AdapterRunResult(
            tool=self.tool_name,
            provider="m365",
            raw_findings=raw_findings,
            summary={"provider": "m365", "raw_artifact_path": str(output_file)},
            raw_artifact_path=str(output_file),
        )
