import logging
from contextlib import asynccontextmanager

import asyncpg
from asgi_correlation_id import CorrelationIdMiddleware
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status

from pyauth.context import Context
from pyauth.models import User
from pyauth.utils import hash_password

load_dotenv()
ctx = Context()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await ctx.init_db()
    yield
    await ctx.dispose_db()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CorrelationIdMiddleware)
logger = logging.getLogger("app")


@app.get("/")
async def hello():
    return "hello"


@app.post("/registrate", status_code=status.HTTP_201_CREATED)
async def registrate(user: User):
    try:
        user.password = hash_password(user.password)
        await ctx.user_repo.add(user)
        return user
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(
            status_code=400, detail="User with this email already exists"
        )


# TODO: delete me
@app.get("/registrate", status_code=status.HTTP_200_OK)
async def get_users():
    return await ctx.user_repo.get()
