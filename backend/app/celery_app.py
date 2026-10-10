from celery import Celery
from app.config import settings

celery_app = Celery(
    "sentinelai",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks"],
)
celery_app.conf.update(
    task_default_queue="scans",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=settings.scan_timeout_seconds,
    task_time_limit=settings.scan_timeout_seconds + 45,
    broker_connection_retry_on_startup=True,
    result_expires=3600,
)
