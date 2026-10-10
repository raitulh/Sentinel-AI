import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import Membership, User
from app.security import decode_access_token

bearer = HTTPBearer(auto_error=False)


def get_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session") from exc
    user = db.query(User).options(joinedload(User.memberships)).filter(User.id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account unavailable")
    membership = next((m for m in user.memberships if m.organization_id == payload["org"]), None)
    if not membership:
        raise HTTPException(status_code=403, detail="Organization membership required")
    return {"user": user, "organization_id": membership.organization_id, "role": membership.role}


def require_roles(*roles: str):
    def dependency(ctx=Depends(get_context)):
        if ctx["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return ctx
    return dependency
