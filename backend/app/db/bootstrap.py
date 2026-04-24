from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from app.models.models import Base


def _column_exists(connection: Connection, table_name: str, column_name: str) -> bool:
    inspector = inspect(connection)
    columns = inspector.get_columns(table_name)
    return any(column["name"] == column_name for column in columns)


def _add_column(connection: Connection, table_name: str, column_name: str, definition: str) -> None:
    if _column_exists(connection, table_name, column_name):
        return
    connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"))


def ensure_schema(connection: Connection) -> None:
    Base.metadata.create_all(connection)

    dialect = connection.dialect.name
    json_type = "JSON" if dialect == "postgresql" else "TEXT"

    _add_column(connection, "audits", "tool", "VARCHAR(30) DEFAULT 'internal'")
    _add_column(connection, "audits", "coverage_percent", "INTEGER DEFAULT 0")

    _add_column(connection, "findings", "tool", "VARCHAR(30) DEFAULT 'internal'")
    _add_column(connection, "findings", "provider", "VARCHAR(30) DEFAULT 'unknown'")
    _add_column(connection, "findings", "resource_id", "VARCHAR(255)")
    _add_column(connection, "findings", "compliance", f"{json_type}")
