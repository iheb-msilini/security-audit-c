import asyncio

from celery import Celery

from app.audit.orchestrator import execute_audit_job
from app.core.config import get_settings

settings = get_settings()
celery_app = Celery(
    "audit_tasks",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)


@celery_app.task(name="run_audit_job")
def run_audit_job(audit_id: int) -> dict:
    result = asyncio.run(execute_audit_job(audit_id))
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "tool": result.tool,
        "score": result.score,
        "coverage_percent": result.coverage_percent,
        "run_error": result.run_error,
    }

def dispatch_audit_job(audit_id: int, tool: str):
    queue_name = "prowler" if tool == "prowler" else "default"
    return run_audit_job.apply_async(args=[audit_id], queue=queue_name)
