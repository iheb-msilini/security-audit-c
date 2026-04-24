import asyncio
import importlib.metadata
import json
import os
import shutil
import sys
import sysconfig
from pathlib import Path

from app.integrations.base import AdapterRunResult


class ProwlerAuditAdapter:
    tool_name = "prowler"
    supported_providers = {"aws", "azure", "gcp"}

    def _binary_candidates(self) -> list[str]:
        env_binary = os.getenv("PROWLER_BIN")
        candidates = [env_binary] if env_binary else []
        candidates.extend(["prowler", "prowler-cli"])
        return [candidate for candidate in candidates if candidate]

    def _distribution_diagnostics(self) -> tuple[list[dict], list[str], list[list[str]]]:
        scripts_dir = Path(sysconfig.get_path("scripts"))
        module_candidates = [os.getenv("PROWLER_PYTHON_MODULE", "").strip(), "prowler"]
        distributions_info: list[dict] = []
        command_candidates: list[list[str]] = []

        for distribution in importlib.metadata.distributions():
            name = (distribution.metadata.get("Name") or "").strip()
            if "prowler" not in name.lower():
                continue

            entry_points = []
            normalized_module = name.replace("-", "_").replace(".", "_")
            if normalized_module:
                module_candidates.append(normalized_module)

            for entry_point in distribution.entry_points:
                if entry_point.group != "console_scripts":
                    continue
                if "prowler" not in entry_point.name.lower():
                    continue

                script_path = scripts_dir / entry_point.name
                command_candidates.append(
                    [str(script_path)] if script_path.exists() else [entry_point.name]
                )
                module_name = entry_point.value.split(":", 1)[0].strip()
                if module_name:
                    module_candidates.append(module_name)
                entry_points.append(
                    {
                        "name": entry_point.name,
                        "value": entry_point.value,
                        "script_path": str(script_path),
                        "script_exists": script_path.exists(),
                    }
                )

            distributions_info.append(
                {
                    "name": name,
                    "version": distribution.version,
                    "entry_points": entry_points,
                }
            )

        filtered_modules: list[str] = []
        for module_name in module_candidates:
            if module_name and module_name not in filtered_modules:
                filtered_modules.append(module_name)

        return distributions_info, filtered_modules, command_candidates

    async def _probe_prefix(self, prefix: list[str]) -> bool:
        process = await asyncio.create_subprocess_exec(
            *prefix,
            "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        return process.returncode == 0

    async def diagnose_runtime(self) -> dict:
        scripts_dir = Path(sysconfig.get_path("scripts"))
        distributions_info, module_candidates, discovered_commands = self._distribution_diagnostics()
        binary_candidates = self._binary_candidates()

        path_binaries = [
            {
                "candidate": candidate,
                "resolved_path": shutil.which(candidate),
            }
            for candidate in binary_candidates
        ]

        script_matches = []
        if scripts_dir.exists():
            for path in sorted(scripts_dir.iterdir()):
                if "prowler" in path.name.lower():
                    script_matches.append(str(path))

        resolved_command = await self._discover_command_prefix()

        return {
            "tool": self.tool_name,
            "container_hostname": os.getenv("HOSTNAME"),
            "python_executable": sys.executable,
            "python_version": sys.version,
            "path": os.getenv("PATH", ""),
            "scripts_dir": str(scripts_dir),
            "path_binary_candidates": path_binaries,
            "scripts_matching_prowler": script_matches,
            "distributions_matching_prowler": distributions_info,
            "module_candidates": module_candidates,
            "discovered_command_candidates": discovered_commands,
            "resolved_command": resolved_command,
        }

    async def _discover_command_prefix(self) -> list[str] | None:
        binary_candidates = self._binary_candidates()

        seen: set[tuple[str, ...]] = set()

        for candidate in binary_candidates:
            resolved = shutil.which(candidate) or candidate
            prefix = [resolved]
            key = tuple(prefix)
            if key in seen:
                continue
            seen.add(key)
            if await self._probe_prefix(prefix):
                return prefix

        _, filtered_modules, command_candidates = self._distribution_diagnostics()

        for prefix in command_candidates:
            key = tuple(prefix)
            if key in seen:
                continue
            seen.add(key)
            if await self._probe_prefix(prefix):
                return prefix

        for module_name in filtered_modules:
            prefix = [sys.executable, "-m", module_name]
            key = tuple(prefix)
            if key in seen:
                continue
            seen.add(key)
            if await self._probe_prefix(prefix):
                return prefix

        return None

    async def run(self, audit: object) -> AdapterRunResult:
        provider = str(getattr(audit, "provider", "")).lower()
        diagnostics = await self.diagnose_runtime()
        command_prefix = diagnostics.get("resolved_command")
        if not command_prefix:
            return AdapterRunResult(
                tool=self.tool_name,
                provider=provider,
                summary={
                    "provider": provider,
                    "diagnostics": diagnostics,
                },
                run_error=(
                    "Unable to find a working Prowler CLI entry point. "
                    "Checked PATH binaries, console_scripts, and Python modules. "
                    f"PATH candidates={diagnostics.get('path_binary_candidates')}; "
                    f"scripts={diagnostics.get('scripts_matching_prowler')}; "
                    f"modules={diagnostics.get('module_candidates')}"
                ),
            )

        output_dir = Path("/tmp/securite-audit/prowler") / str(getattr(audit, "id", "adhoc"))
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "results.json"

        cmd = [
            *command_prefix,
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
            return AdapterRunResult(
                tool=self.tool_name,
                provider=provider,
                summary={
                    "provider": provider,
                    "resolved_command": command_prefix,
                    "diagnostics": diagnostics,
                },
                run_error=(
                    f"{message}. "
                    f"Resolved command={command_prefix}; "
                    f"PATH candidates={diagnostics.get('path_binary_candidates')}"
                ),
            )

        raw_findings: list[dict] = []
        if output_file.exists():
            raw_findings = json.loads(output_file.read_text())

        return AdapterRunResult(
            tool=self.tool_name,
            provider=provider,
            raw_findings=raw_findings if isinstance(raw_findings, list) else [],
            summary={
                "provider": provider,
                "raw_artifact_path": str(output_file),
                "resolved_command": command_prefix,
                "diagnostics": diagnostics,
            },
            raw_artifact_path=str(output_file),
        )
