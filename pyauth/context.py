from os import getenv

from databases import Database
from dotenv import load_dotenv

from pyauth.db import PgRepository
from pyauth.models import User


class Context:
    def __init__(self):
        db_url = getenv("DATABASE_URL")
        if not db_url:
            raise AssertionError("$DATABASE_URL is not set")
        self.pg = Database(db_url)
        self.user_repo = PgRepository(self.pg, User)
        self.access_token_expire_minutes = int(
            getenv("ACCESS_TOKEN_EXPIRE_MINUTES") or 5
        )
        self.refresh_token_expire_minutes = int(
            getenv("REFRESH_TOKEN_EXPIRE_MINUTES") or 60
        )
        self.jwt_secret_key = getenv("JWT_SECRET_KEY") or "secret"
        self.jwt_refresh_secret_key = getenv("JWT_SECRET_KEY") or "secret"
        self.hash_algorithm = getenv("ALGORITHM") or "HS256"

    async def init_db(self) -> None:
        await self.pg.connect()

    async def dispose_db(self) -> None:
        await self.pg.disconnect()


load_dotenv()
ctx = Context()
