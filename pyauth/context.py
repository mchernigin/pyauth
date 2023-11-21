from databases import Database
from os import getenv

from pyauth.db import PgRepository
from pyauth.models import User


class Context:
    def __init__(self):
        db_url = getenv("DATABASE_URL")
        if not db_url:
            raise AssertionError("$DATABASE_URL is not set")
        self.pg = Database(db_url)
        self.user_repo = PgRepository(self.pg, User)

    async def init_db(self) -> None:
        print(self.pg.url)
        await self.pg.connect()

    async def dispose_db(self) -> None:
        await self.pg.disconnect()
