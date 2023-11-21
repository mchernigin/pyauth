from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from asgi_correlation_id import CorrelationIdMiddleware
from dotenv import load_dotenv
import logging

from pyauth.context import Context


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
    return await ctx.user_repo.get()


@app.get("/registrate", status_code=status.HTTP_201_CREATED)
async def registrate():
    return "registrate"
