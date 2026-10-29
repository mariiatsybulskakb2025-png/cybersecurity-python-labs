"""Pydantic-моделі запитів і відповідей."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import BULK_MAX_ITEMS, BULK_MIN_ITEMS, VALUE_MAX, VALUE_MIN

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Дані для створення категорії (каналу зв’язку)."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
        json_schema_extra={"examples": [{"name": "internet"}]},
    )

    name: str = Field(
        min_length=2,
        max_length=40,
        description="Унікальна назва каналу, 2–40 символів.",
    )


class CategoryRead(BaseModel):
    """Категорія у відповіді API."""

    id: int = Field(description="Ідентифікатор категорії.")
    name: str = Field(description="Назва каналу.")


class RecordCreate(BaseModel):
    """Дані для створення запису; id задає база даних."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "code": "V11-TEST",
                    "title": "Вимірювання каналу тест",
                    "category_id": 1,
                    "value": 75.5,
                    "status": "new",
                }
            ]
        },
    )

    code: str = Field(
        min_length=3,
        max_length=40,
        description="Унікальний код запису, 3–40 символів.",
    )
    title: str = Field(
        min_length=3,
        max_length=120,
        description="Назва вимірювання, 3–120 символів.",
    )
    category_id: int = Field(gt=0, description="Ідентифікатор існуючої категорії.")
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        description="Завантаження каналу у відсотках, від 0 до 100 включно.",
    )
    status: Status = Field(description="Стан перевірки: new, in_progress або done.")

    @field_validator("value", mode="before")
    @classmethod
    def value_must_be_number(cls, value: Any) -> Any:
        """Відхилити рядки та логічні значення замість числа."""
        if not isinstance(value, bool | str):
            return value
        raise ValueError("value має бути числом")


class RecordReplace(RecordCreate):
    """Повна заміна запису: усі змінювані поля обов’язкові."""


class RecordRead(RecordCreate):
    """Запис у відповіді API: id та назва категорії додаються сервером."""

    id: int = Field(description="Ідентифікатор запису.")
    category_name: str = Field(description="Назва категорії (каналу).")


RecordBulkCreate = Annotated[
    list[RecordCreate],
    Field(
        min_length=BULK_MIN_ITEMS,
        max_length=BULK_MAX_ITEMS,
        description="Пакет записів: від 1 до 100 елементів.",
    ),
]
