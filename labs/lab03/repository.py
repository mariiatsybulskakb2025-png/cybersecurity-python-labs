"""Параметризовані SQL-запити до таблиць categories і records.

Модуль не залежить від FastAPI: помилки повертаються власними винятками,
які перетворює на HTTP-відповіді шар маршрутів.
"""

import logging
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from typing import Any

from .database import get_connection

logger = logging.getLogger(__name__)

Record = dict[str, Any]


class RepositoryError(Exception):
    """Базова помилка шару доступу до даних."""


class NotFoundError(RepositoryError):
    """Запис або категорія не існує."""


class ConflictError(RepositoryError):
    """Порушено унікальність або зв’язки між таблицями."""


class StorageError(RepositoryError):
    """Технічна помилка роботи з базою даних."""


RECORD_SELECT = (
    "SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, "
    "r.value, r.status "
    "FROM records AS r JOIN categories AS c ON c.id = r.category_id"
)
INSERT_RECORD = (
    "INSERT INTO records (code, title, category_id, value, status) "
    "VALUES (?, ?, ?, ?, ?)"
)


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Відкрити з’єднання на одну операцію й гарантовано закрити його."""
    try:
        with closing(get_connection()) as connection:
            connection.row_factory = sqlite3.Row
            yield connection
    except sqlite3.Error as exc:
        # Технічні подробиці — лише в журнал, клієнту — загальне повідомлення.
        logger.error("Помилка SQLite: %s", exc)
        raise StorageError("Тимчасова помилка роботи з базою даних.") from exc


def _conflict(exc: sqlite3.IntegrityError, unique_message: str) -> ConflictError:
    """Перетворити IntegrityError на зрозумілий ConflictError."""
    if "UNIQUE" in str(exc):
        return ConflictError(unique_message)
    return ConflictError("Дані порушують обмеження цілісності бази.")


def _values(data: Record) -> tuple[Any, ...]:
    """Повернути значення полів запису в порядку параметрів SQL."""
    return (
        data["code"],
        data["title"],
        data["category_id"],
        data["value"],
        data["status"],
    )


def _require_category(connection: sqlite3.Connection, category_id: int) -> None:
    """Перервати операцію з NotFoundError, якщо категорії немає."""
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("Категорію не знайдено.")


def _fetch_record(connection: sqlite3.Connection, record_id: int | None) -> Record:
    """Прочитати запис разом із назвою категорії (JOIN)."""
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    if row is None:
        raise NotFoundError("Запис не знайдено.")
    return dict(row)


# --------------------------------------------------------------- категорії


def create_category(name: str) -> Record:
    """Створити категорію й повернути її."""
    with _connect() as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
        except sqlite3.IntegrityError as exc:
            raise _conflict(exc, "Категорія з такою назвою вже існує.") from exc
        return {"id": cursor.lastrowid, "name": name}


def list_categories() -> list[Record]:
    """Повернути всі категорії за зростанням id."""
    with _connect() as connection:
        rows = connection.execute("SELECT id, name FROM categories ORDER BY id")
        return [dict(row) for row in rows.fetchall()]


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with _connect() as connection:
        try:
            with connection:
                _require_category(connection, category_id)
                used = connection.execute(
                    "SELECT COUNT(*) FROM records WHERE category_id = ?",
                    (category_id,),
                ).fetchone()[0]
                if used:
                    raise ConflictError(
                        "Категорія містить записи, тому її не можна видалити."
                    )
                cursor = connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
                if cursor.rowcount == 0:
                    raise NotFoundError("Категорію не знайдено.")
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Категорія містить записи, тому її не можна видалити."
            ) from exc


# ------------------------------------------------------------------ записи


def create_record(data: Record) -> Record:
    """Додати запис і повернути його разом із category_name."""
    with _connect() as connection:
        try:
            with connection:
                _require_category(connection, data["category_id"])
                cursor = connection.execute(INSERT_RECORD, _values(data))
                return _fetch_record(connection, cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise _conflict(exc, "Запис із таким code вже існує.") from exc


def get_record(record_id: int) -> Record:
    """Повернути один запис за id."""
    with _connect() as connection:
        return _fetch_record(connection, record_id)


def list_records(
    *,
    category_id: int | None,
    status: str | None,
    min_value: float | None,
    q: str | None,
    limit: int,
    offset: int,
) -> list[Record]:
    """Повернути записи за фільтрами; порядок завжди за id."""
    # SQL-фрагменти — лише з рядків нижче, усі значення — окремим списком.
    conditions: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    query = RECORD_SELECT
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _connect() as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def replace_record(record_id: int, data: Record) -> Record:
    """Повністю замінити змінювані поля запису; id не змінюється."""
    with _connect() as connection:
        try:
            with connection:
                _fetch_record(connection, record_id)
                _require_category(connection, data["category_id"])
                cursor = connection.execute(
                    "UPDATE records "
                    "SET code = ?, title = ?, category_id = ?, value = ?, status = ? "
                    "WHERE id = ?",
                    (*_values(data), record_id),
                )
                if cursor.rowcount == 0:
                    raise NotFoundError("Запис не знайдено.")
                return _fetch_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            raise _conflict(exc, "Запис із таким code вже існує.") from exc


def delete_record(record_id: int) -> None:
    """Видалити запис за id."""
    with _connect() as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено.")


def create_records_bulk(items: Sequence[Record]) -> list[Record]:
    """Атомарно додати пакет записів в одній транзакції.

    Якщо будь-який елемент має дублікат code, неіснуючу категорію або
    порушує обмеження, не зберігається жоден елемент пакета.
    """
    with _connect() as connection:
        try:
            with connection:  # один commit на весь пакет або rollback
                for category_id in sorted({item["category_id"] for item in items}):
                    _require_category(connection, category_id)
                codes = [item["code"] for item in items]
                if len(set(codes)) != len(codes):
                    raise ConflictError("У пакеті є записи з однаковим code.")
                new_ids = [
                    connection.execute(INSERT_RECORD, _values(item)).lastrowid
                    for item in items
                ]
                return [_fetch_record(connection, new_id) for new_id in new_ids]
        except sqlite3.IntegrityError as exc:
            raise _conflict(exc, "Один із записів має code, який уже існує.") from exc
