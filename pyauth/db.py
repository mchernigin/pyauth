import logging
from typing import List, Type, Optional, ClassVar

from asyncpg.exceptions import UniqueViolationError
from databases import Database
from pydantic import BaseModel, TypeAdapter

logger = logging.getLogger("app")


class Entity(BaseModel):
    _table_name: ClassVar[str]
    _pk: ClassVar[str]


class DatabaseCredentials(BaseModel):
    driver: str
    username: str
    password: str
    url: str
    port: int
    db_name: str


class AbstractRepository:
    def __init__(self, db: Database, entity: Type[Entity]):
        self._db = db
        self._entity = entity
        self._table_name = entity._table_name

    def _get_query_parameters(self, dump):
        keys = list(dump.keys())
        columns = ",".join(keys)
        placeholders = ",".join(map(lambda x: f":{x}", keys))
        return columns, placeholders

    async def add(self, entities: BaseModel | List[BaseModel], ignore_conflict=False):
        if not isinstance(entities, list):
            entities = [entities]

        if not entities:
            return

        dumps = list(map(lambda x: x.model_dump(), entities))

        columns, placeholders = self._get_query_parameters(dumps[0])

        query = f"INSERT INTO {self._table_name}({columns}) VALUES ({placeholders})"
        logger.debug(f"Sending query: {query}")

        if ignore_conflict:
            query += " ON CONFLICT DO NOTHING"

        await self._db.execute_many(query=query, values=dumps)

    async def update(self, entity: Entity, fields: List[str]):
        dump = entity.model_dump()

        pk = entity._pk
        query_set = [f"{field} = :{field}" for field in fields]
        query = (
            f"UPDATE {self._table_name} SET {','.join(query_set)} WHERE {pk} = :{pk}"
        )
        logger.debug(f"Sending query: {query}")
        await self._db.execute(
            query=query, values={k: dump[k] for k in fields} | {pk: dump[pk]}
        )

    async def get_many(self, field=None, value=None) -> List[Entity]:
        query = f"SELECT * FROM {self._table_name}"
        if field is not None:
            query += f" WHERE {field} = :{field}"
            rows = await self._db.fetch_all(query=query, values={field: value})
        else:
            rows = await self._db.fetch_all(query=query)

        mapped = map(
            lambda row: TypeAdapter(self._entity).validate_python(dict(row._mapping)),
            rows,
        )

        return list(mapped)

    async def get_one(self, field, value) -> Optional[Entity]:
        query = f"SELECT * FROM {self._table_name}"
        query += f" WHERE {field} = :{field}"
        row = await self._db.fetch_one(query=query, values={field: value})

        if not row:
            return None

        return TypeAdapter(self._entity).validate_python(dict(row._mapping))


class PgRepository(AbstractRepository):
    async def add_or_update(self, entity: Entity, fields: List[str]):
        try:
            await self.add(entity)
        except UniqueViolationError:
            await self.update(entity, fields)


def create_db_string(creds: DatabaseCredentials):
    return f"{creds.driver}://{creds.username}:{creds.password}@{creds.url}:{creds.port}/{creds.db_name}"
