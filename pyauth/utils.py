from datetime import datetime, timedelta
from typing import Optional, Dict

import bcrypt
from jose import jwt
from pydantic import BaseModel

from pyauth.context import Context


def hash_password(passord: bytes) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(passord, salt)


def verify_password(password: bytes, known_hash: bytes) -> bool:
    return bcrypt.checkpw(password, known_hash)


class TokenPayload(BaseModel):
    sub: str
    exp: int


def create_access_token(
    ctx: Context, data: Dict, expires_delta: Optional[timedelta] = None
) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ctx.access_token_expire_minutes)
    return jwt.encode(
        claims={**data, "exp": expire},
        key=ctx.jwt_secret_key,
        algorithm=ctx.hash_algorithm,
    )


def create_refresh_token(
    ctx: Context, data: Dict, expires_delta: Optional[timedelta] = None
) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ctx.refresh_token_expire_minutes)
    return jwt.encode(
        claims={**data, "exp": expire},
        key=ctx.jwt_refresh_secret_key,
        algorithm=ctx.hash_algorithm,
    )
