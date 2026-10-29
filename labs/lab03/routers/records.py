"""Маршрути для записів (вимірювань завантаження каналів)."""

from typing import Annotated, Any

from fastapi import APIRouter, Path, Query

from .. import repository
from ..config import DEFAULT_LIMIT, MAX_LIMIT, VALUE_MAX, VALUE_MIN
from ..repository import RepositoryError
from ..schemas import (
    RecordBulkCreate,
    RecordCreate,
    RecordRead,
    RecordReplace,
    Status,
)
from . import http_error

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[int, Path(gt=0, description="Додатний ідентифікатор запису.")]

NOT_FOUND = {404: {"description": "Запис або категорію не знайдено."}}
CONFLICT = {409: {"description": "Запис із таким code вже існує."}}


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами",
    operation_id="list_records",
)
def list_records(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Лише записи цієї категорії."),
    ] = None,
    status: Annotated[
        Status | None,
        Query(description="Лише записи з цим статусом."),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            description="Лише записи, де value >= min_value (0–100).",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у title з урахуванням регістру.",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_LIMIT, description="Максимальна кількість записів."),
    ] = DEFAULT_LIMIT,
    offset: Annotated[
        int,
        Query(ge=0, description="Кількість пропущених записів."),
    ] = 0,
) -> list[dict[str, Any]]:
    """Повернути записи за фільтрами (поєднуються через AND), порядок — за `id`."""
    try:
        return repository.list_records(
            category_id=category_id,
            status=status,
            min_value=min_value,
            q=q,
            limit=limit,
            offset=offset,
        )
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    operation_id="create_records_bulk",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(records: RecordBulkCreate) -> list[dict[str, Any]]:
    """Створити від 1 до 100 записів в одній транзакції (все або нічого)."""
    try:
        return repository.create_records_bulk([r.model_dump() for r in records])
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    operation_id="get_record",
    responses={404: {"description": "Запис не знайдено."}},
)
def get_record(record_id: RecordId) -> dict[str, Any]:
    """Повернути один запис разом із назвою категорії."""
    try:
        return repository.get_record(record_id)
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    operation_id="create_record",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(record: RecordCreate) -> dict[str, Any]:
    """Створити запис; `id` присвоює база даних."""
    try:
        return repository.create_record(record.model_dump())
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити запис",
    operation_id="replace_record",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, record: RecordReplace) -> dict[str, Any]:
    """Замінити всі змінювані поля запису; `id` залишається незмінним."""
    try:
        return repository.replace_record(record_id, record.model_dump())
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.delete(
    "/{record_id}",
    status_code=204,
    summary="Видалити запис",
    operation_id="delete_record",
    responses={404: {"description": "Запис не знайдено."}},
)
def delete_record(record_id: RecordId) -> None:
    """Видалити запис за `id`."""
    try:
        repository.delete_record(record_id)
    except RepositoryError as exc:
        raise http_error(exc) from exc
