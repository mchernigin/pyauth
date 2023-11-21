from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel


class User(BaseModel):
    id: UUID | None
    email: str
    password: bytes

    _table_name: ClassVar[str] = "users"
    _pk: ClassVar[str] = "id"
