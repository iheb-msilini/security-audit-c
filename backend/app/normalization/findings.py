from dataclasses import asdict, dataclass, field

from app.integrations.base import AdapterRunResult


@dataclass
class NormalizedFinding:
    tool: str
    provider: str
    check_id: str
    title: str
    severity: str
    status: str
    resource_id: str | None = None
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    compliance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _normalize_internal(provider: str, raw_findings: list[dict]) -> list[NormalizedFinding]:
    findings = []
    for finding in raw_findings:
        findings.append(
            NormalizedFinding(
                tool="internal",
                provider=provider,
                check_id=finding.get("check_id", "unknown"),
                title=finding.get("title") or finding.get("check_id", "unknown"),
                severity=str(finding.get("severity", "medium")).lower(),
                status=str(finding.get("status", "unknown")).lower(),
                resource_id=finding.get("resource_id"),
                evidence=finding.get("raw_data", {}),
                remediation=finding.get("remediation", ""),
                compliance=finding.get("frameworks", {}),
            )
        )
    return findings


def _normalize_prowler(provider: str, raw_findings: list[dict]) -> list[NormalizedFinding]:
    findings = []
    for finding in raw_findings:
        compliance = {}
        framework = finding.get("Compliance") or finding.get("compliance")
        if framework:
            compliance["framework"] = framework
        findings.append(
            NormalizedFinding(
                tool="prowler",
                provider=provider,
                check_id=finding.get("CheckID") or finding.get("check_id") or "unknown",
                title=finding.get("CheckTitle") or finding.get("title") or "Untitled check",
                severity=str(finding.get("Severity") or finding.get("severity") or "medium").lower(),
                status=str(finding.get("Status") or finding.get("status") or "unknown").lower(),
                resource_id=finding.get("ResourceId") or finding.get("resource_id"),
                evidence=finding,
                remediation=finding.get("Remediation") or finding.get("remediation") or "",
                compliance=compliance,
            )
        )
    return findings


def _normalize_maester(raw_findings: list[dict]) -> list[NormalizedFinding]:
    findings = []
    for finding in raw_findings:
        status = str(finding.get("status") or finding.get("result") or "unknown").lower()
        if status == "passed":
            status = "pass"
        elif status == "failed":
            status = "fail"
        findings.append(
            NormalizedFinding(
                tool="maester",
                provider="m365",
                check_id=finding.get("id") or finding.get("check_id") or "unknown",
                title=finding.get("title") or finding.get("name") or "Untitled test",
                severity=str(finding.get("severity") or "medium").lower(),
                status=status,
                resource_id=finding.get("resource_id"),
                evidence=finding,
                remediation=finding.get("remediation") or "",
                compliance=finding.get("compliance") or {},
            )
        )
    return findings


def _normalize_steampipe(provider: str, raw_findings: list[dict]) -> list[NormalizedFinding]:
    findings = []
    for index, finding in enumerate(raw_findings, start=1):
        findings.append(
            NormalizedFinding(
                tool="steampipe",
                provider=provider,
                check_id=str(finding.get("control") or finding.get("check_id") or f"steampipe-{index}"),
                title=str(finding.get("title") or finding.get("control") or f"Steampipe Result {index}"),
                severity=str(finding.get("severity") or "medium").lower(),
                status=str(finding.get("status") or "unknown").lower(),
                resource_id=finding.get("resource") or finding.get("resource_id"),
                evidence=finding,
                remediation=str(finding.get("remediation") or ""),
                compliance=finding.get("compliance") or {},
            )
        )
    return findings


def normalize_findings(result: AdapterRunResult) -> list[NormalizedFinding]:
    if result.tool == "internal":
        return _normalize_internal(result.provider, result.raw_findings)
    if result.tool == "prowler":
        return _normalize_prowler(result.provider, result.raw_findings)
    if result.tool == "maester":
        return _normalize_maester(result.raw_findings)
    if result.tool == "steampipe":
        return _normalize_steampipe(result.provider, result.raw_findings)
    return []
