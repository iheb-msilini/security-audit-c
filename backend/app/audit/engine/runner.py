from app.connectors.aws import collect_aws_inventory
from app.connectors.azure import collect_azure_inventory
from app.connectors.gcp import collect_gcp_inventory


class CheckRegistry:
    @staticmethod
    def get_evaluator(provider: str):
        provider = provider.lower()

        if provider == "azure":
            from app.audit.checks.azure.checks import evaluate_azure_checks

            return evaluate_azure_checks
        if provider == "aws":
            from app.audit.checks.aws.checks import evaluate_aws_checks

            return evaluate_aws_checks
        if provider == "gcp":
            from app.audit.checks.gcp.checks import evaluate_gcp_checks

            return evaluate_gcp_checks

        return None

    collector_by_provider = {
        "azure": collect_azure_inventory,
        "aws": collect_aws_inventory,
        "gcp": collect_gcp_inventory,
    }

    @classmethod
    def get_collector(cls, provider: str):
        return cls.collector_by_provider.get(provider.lower())


class AuditEngine:
    @staticmethod
    async def run(provider: str) -> dict:
        collector = CheckRegistry.get_collector(provider)
        evaluator = CheckRegistry.get_evaluator(provider)

        if not collector or not evaluator:
            return {
                "score": 0,
                "findings": [],
                "collection_summary": {"provider": provider, "collection_ok": False},
                "run_error": f"Unsupported provider: {provider}",
            }

        inventory = await collector()
        findings = evaluator(inventory)

        normalized_findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
        known = [f for f in normalized_findings if f.get("status") in {"pass", "fail"}]
        passed = sum(1 for f in known if f["status"] == "pass")
        score = int((passed / len(known)) * 100) if known else 0
        run_error = None if inventory.get("collection_ok") else "; ".join(inventory.get("errors", []))

        return {
            "score": score,
            "findings": normalized_findings,
            "collection_summary": inventory,
            "run_error": run_error,
        }
