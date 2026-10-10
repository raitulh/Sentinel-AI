from sqlalchemy.orm import Session
from app.models import AuditEvent


def record_event(db: Session, organization_id: str, actor_user_id: str | None, action: str,
                 resource_type: str, resource_id: str, metadata: dict | None = None) -> None:
    db.add(AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        event_metadata=metadata or {},
    ))
