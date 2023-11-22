from typing import ClassVar

from pyauth.db import Entity


class User(Entity):
    email: str
    password: bytes

    _table_name: ClassVar[str] = "users"
    _pk: ClassVar[str] = "id"
