import logging
from contextlib import asynccontextmanager
from typing import Annotated

import asyncpg
from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import FastAPI, HTTPException, status, Depends, Response
from fastapi.security import OAuth2PasswordRequestForm


from pyauth.context import ctx
from pyauth.models import User
from pyauth.deps import get_current_user
from pyauth.utils import (
    TokenSchema,
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await ctx.init_db()
    yield
    await ctx.dispose_db()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CorrelationIdMiddleware)
logger = logging.getLogger("app")


@app.get("/", summary="Say hi.")
async def hi() -> str:
    return "hi."


@app.post(
    "/registrate", summary="Registrate new user", status_code=status.HTTP_201_CREATED
)
async def registrate(user: User):
    try:
        user.password = hash_password(user.password)
        await ctx.user_repo.add(user)
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(
            status_code=400, detail="User with this email already exists"
        )


@app.post(
    "/auth",
    summary="Create access and refresh tokens for user",
    response_model=TokenSchema,
)
async def auth(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], response: Response
) -> TokenSchema:
    err = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    found_entity = await ctx.user_repo.get_one(field="email", value=form_data.username)
    if found_entity is None:
        raise err
    user = User.model_validate(found_entity)
    if not verify_password(
        password=str.encode(form_data.password), known_hash=user.password
    ):
        raise err

    access_token = create_access_token(ctx, data={"sub": user.email})
    refresh_token = create_refresh_token(ctx, data={"sub": user.email})

    return TokenSchema(access_token=access_token, refresh_token=refresh_token)


@app.get("/me", summary="Get secret that only register people know")
async def get_me(user: Annotated[User, Depends(get_current_user)]) -> str:
    return f"You are logged in as {user.email}"


# TODO: delete me
@app.get("/registrate", status_code=status.HTTP_200_OK)
async def get_users():
    return await ctx.user_repo.get_many()
