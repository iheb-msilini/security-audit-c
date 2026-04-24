from dataclasses import asdict, dataclass, field

from app.normalization.findings import NormalizedFinding


@dataclass
class Scorecard:
    score: int
    coverage_percent: int
    maturity: str
    total_checks: int
    evaluable_checks: int
    counts_by_status: dict = field(default_factory=dict)
    severity_breakdown: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class ScoringEngine:
    @staticmethod
    def calculate(findings: list[NormalizedFinding]) -> Scorecard:
        total = len(findings)
        counts_by_status = {key: 0 for key in ["pass", "fail", "warning", "skipped", "unknown"]}
        severity_breakdown = {key: 0 for key in ["critical", "high", "medium", "low"]}

        for finding in findings:
            counts_by_status[finding.status] = counts_by_status.get(finding.status, 0) + 1
            severity_breakdown[finding.severity] = severity_breakdown.get(finding.severity, 0) + 1

        evaluable = counts_by_status.get("pass", 0) + counts_by_status.get("fail", 0) + counts_by_status.get("warning", 0)
        score = int((counts_by_status.get("pass", 0) / evaluable) * 100) if evaluable else 0
        coverage = int((evaluable / total) * 100) if total else 0

        if score >= 85:
            maturity = "optimized"
        elif score >= 70:
            maturity = "managed"
        elif score >= 50:
            maturity = "defined"
        else:
            maturity = "initial"

        return Scorecard(
            score=score,
            coverage_percent=coverage,
            maturity=maturity,
            total_checks=total,
            evaluable_checks=evaluable,
            counts_by_status=counts_by_status,
            severity_breakdown=severity_breakdown,
        )
