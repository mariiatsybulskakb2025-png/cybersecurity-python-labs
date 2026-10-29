"""Початкове заповнення бази навчальними даними з data/seed.json.

Запуск із кореня репозиторію: ``python -m labs.lab03.seed``.
"""

import json
import logging
import math
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

from .config import STATUSES, VALUE_MAX, VALUE_MIN
from .database import get_connection, initialize_database

logger = logging.getLogger(__name__)

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"

EXPECTED_CATEGORIES = 3
EXPECTED_RECORDS = 8
CATEGORY_FIELDS = {"id", "name"}
RECORD_FIELDS = {"code", "title", "category_id", "value", "status"}

CategoryRow = tuple[int, str]
RecordRow = tuple[str, str, int, float, str]


class SeedError(Exception):
    """Початкові дані некоректні або їх не вдалося записати."""


def _require(condition: bool, message: str) -> None:
    """Перервати заповнення зрозумілим повідомленням, якщо умова хибна."""
    if not condition:
        raise SeedError(message)


def _is_int(value: Any) -> bool:
    """Перевірити, що значення — ціле число (bool не вважається числом)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    """Перевірити, що значення — скінченне число (bool не вважається числом)."""
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def load_seed(path: Path = SEED_PATH) -> Any:
    """Прочитати JSON-файл із початковими даними."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        logger.error("Не вдалося прочитати %s: %s", path, exc)
        raise SeedError("Не вдалося прочитати файл початкових даних.") from exc
    except json.JSONDecodeError as exc:
        raise SeedError(
            f"Файл початкових даних не є коректним JSON "
            f"(рядок {exc.lineno}, позиція {exc.colno})."
        ) from exc


def _validate_categories(raw: Any) -> list[CategoryRow]:
    """Перевірити масив категорій і повернути рядки для вставки."""
    _require(isinstance(raw, list), "Поле categories має бути масивом.")
    _require(
        len(raw) == EXPECTED_CATEGORIES,
        f"Очікується {EXPECTED_CATEGORIES} категорії, знайдено {len(raw)}.",
    )
    rows: list[CategoryRow] = []
    for number, item in enumerate(raw, start=1):
        label = f"Категорія №{number}"
        _require(
            isinstance(item, dict) and set(item) == CATEGORY_FIELDS,
            f"{label}: потрібні рівно поля id та name.",
        )
        _require(
            _is_int(item["id"]) and item["id"] > 0,
            f"{label}: id має бути додатним цілим числом.",
        )
        name = item["name"]
        _require(
            isinstance(name, str) and 2 <= len(name.strip()) <= 40,
            f"{label}: name має містити від 2 до 40 символів.",
        )
        rows.append((item["id"], name.strip()))
    _require(
        len({row[0] for row in rows}) == len(rows),
        "Ідентифікатори категорій мають бути унікальними.",
    )
    _require(
        len({row[1] for row in rows}) == len(rows),
        "Назви категорій мають бути унікальними.",
    )
    return rows


def _validate_records(raw: Any, category_ids: set[int]) -> list[RecordRow]:
    """Перевірити масив записів і повернути рядки для вставки."""
    _require(isinstance(raw, list), "Поле records має бути масивом.")
    _require(
        len(raw) == EXPECTED_RECORDS,
        f"Очікується {EXPECTED_RECORDS} записів, знайдено {len(raw)}.",
    )
    rows: list[RecordRow] = []
    for number, item in enumerate(raw, start=1):
        label = f"Запис №{number}"
        _require(
            isinstance(item, dict) and set(item) == RECORD_FIELDS,
            f"{label}: потрібні рівно поля {', '.join(sorted(RECORD_FIELDS))}.",
        )
        code, title = item["code"], item["title"]
        _require(
            isinstance(code, str) and 3 <= len(code.strip()) <= 40,
            f"{label}: code має містити від 3 до 40 символів.",
        )
        _require(
            isinstance(title, str) and 3 <= len(title.strip()) <= 120,
            f"{label}: title має містити від 3 до 120 символів.",
        )
        _require(
            item["category_id"] in category_ids and _is_int(item["category_id"]),
            f"{label}: category_id посилається на неіснуючу категорію.",
        )
        _require(
            _is_number(item["value"]) and VALUE_MIN <= item["value"] <= VALUE_MAX,
            f"{label}: value має бути числом від {VALUE_MIN:g} до {VALUE_MAX:g}.",
        )
        _require(
            item["status"] in STATUSES,
            f"{label}: status має бути одним із {', '.join(STATUSES)}.",
        )
        rows.append(
            (
                code.strip(),
                title.strip(),
                item["category_id"],
                float(item["value"]),
                item["status"],
            )
        )
    _require(
        len({row[0] for row in rows}) == len(rows),
        "Значення code у початкових даних мають бути унікальними.",
    )
    return rows


def validate_seed(data: Any) -> tuple[list[CategoryRow], list[RecordRow]]:
    """Перевірити весь JSON і повернути підготовлені рядки."""
    _require(
        isinstance(data, dict) and set(data) == {"categories", "records"},
        "Файл має містити рівно два масиви: categories і records.",
    )
    categories = _validate_categories(data["categories"])
    records = _validate_records(data["records"], {row[0] for row in categories})
    return categories, records


def _has_data(connection: sqlite3.Connection) -> bool:
    """Повернути True, якщо в базі вже є категорії або записи."""
    row = connection.execute(
        "SELECT EXISTS (SELECT 1 FROM categories) OR EXISTS (SELECT 1 FROM records)"
    ).fetchone()
    return bool(row[0])


def seed_database() -> str:
    """Заповнити порожню базу; повернути повідомлення про результат."""
    categories, records = validate_seed(load_seed())
    try:
        initialize_database()
        # Одна транзакція: перевірка порожнечі та всі вставки разом.
        with closing(get_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if _has_data(connection):
                return (
                    "База вже містить дані: початкове заповнення "
                    "пропущено, дублікати не створюються."
                )
            connection.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)", categories
            )
            connection.executemany(
                "INSERT INTO records (code, title, category_id, value, status) "
                "VALUES (?, ?, ?, ?, ?)",
                records,
            )
    except sqlite3.Error as exc:
        logger.error("Помилка SQLite під час заповнення: %s", exc)
        raise SeedError(
            f"Початкові дані не збережено, зміни скасовано ({exc})."
        ) from exc
    return (
        f"Додано категорій: {len(categories)}, записів: {len(records)}. "
        "Початкове заповнення завершено."
    )


def main() -> int:
    """Точка входу командного рядка; повернути код завершення."""
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(message)s")
    try:
        print(seed_database())
    except SeedError as exc:
        print(f"Помилка: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
