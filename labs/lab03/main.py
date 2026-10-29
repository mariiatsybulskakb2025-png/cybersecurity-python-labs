"""FastAPI-застосунок: облік завантаження каналів зв’язку (варіант 11).

Запуск із кореня репозиторію:
``uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000``.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from shared import student as student_info

from .config import APP_DESCRIPTION, APP_TITLE, VARIANT_NUMBER
from .database import initialize_database
from .routers import categories, records


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Під час запуску створити відсутні таблиці, не змінюючи наявні дані."""
    initialize_database()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


class StudentInfo(BaseModel):
    """Дані студента з shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int


class PingResponse(BaseModel):
    """Відповідь перевірки доступності."""

    status: str


def _student_value(names: tuple[str, ...], default: Any) -> Any:
    """Взяти перше наявне значення з shared/student.py за списком імен."""
    for name in names:
        value = getattr(student_info, name, None)
        if value is not None and not callable(value):
            return value
    return default


@app.get(
    "/ping",
    response_model=PingResponse,
    tags=["service"],
    summary="Перевірка доступності API",
    operation_id="ping",
)
def ping() -> dict[str, str]:
    """Повернути `{"status": "ok"}`, якщо API працює."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentInfo,
    tags=["service"],
    summary="Дані студента",
    operation_id="get_student",
)
def get_student() -> StudentInfo:
    """Повернути ПІБ, групу та номер варіанта з `shared/student.py`."""
    return StudentInfo(
        student_name=str(
            _student_value(
                ("STUDENT_NAME", "FULL_NAME", "NAME", "student_name"),
                "Цибульська Марія Юріївна",
            )
        ),
        group_name=str(_student_value(("GROUP_NAME", "GROUP", "group_name"), "КБ-202")),
        variant_number=int(
            _student_value(
                ("VARIANT_NUMBER", "VARIANT", "variant_number"), VARIANT_NUMBER
            )
        ),
    )
