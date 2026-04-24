from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class AdapterRunResult:
    tool: str
    provider: str
    raw_findings: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    run_error: str | None = None
    raw_artifact_path: str | None = None


class AuditAdapter(Protocol):
    tool_name: str
    supported_providers: set[str]

    async def run(self, audit: object) -> AdapterRunResult:
        ...
