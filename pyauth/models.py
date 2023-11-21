from typing import ClassVar
from pydantic import BaseModel


class User(BaseModel):
    user_id: int
    chat_id: int

    _table_name: ClassVar[str] = "users"
