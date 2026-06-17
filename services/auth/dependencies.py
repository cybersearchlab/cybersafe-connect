import random
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from config import OTP_EXPIRE_MINUTES
from database import SessionLocal
from enums import AccountStatus, TokenType
from models import User
from security import decode_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_otp() -> tuple[str, datetime]:
    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
    return code, expires_at


def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "fullname": user.fullname,
        "email": user.email,
        "role": user.role.value,
        "is_verified": user.is_verified,
        "account_status": user.account_status.value,
    }


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"X-Error-Code": "AUTH_REQUIRED"},
        )

    try:
        payload = decode_token(credentials.credentials, TokenType.access)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"X-Error-Code": "INVALID_TOKEN"},
        )

    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found",
            headers={"X-Error-Code": "USER_NOT_FOUND"},
        )

    if user.account_status in (AccountStatus.suspended, AccountStatus.deleted):
        raise HTTPException(
            status_code=403,
            detail="Account is not active",
            headers={"X-Error-Code": "ACCOUNT_BLOCKED"},
        )

    return user
