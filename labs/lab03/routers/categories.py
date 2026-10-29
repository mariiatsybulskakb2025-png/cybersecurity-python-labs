"""Маршрути для категорій (каналів зв’язку)."""

from typing import Annotated, Any

from fastapi import APIRouter, Path

from .. import repository
from ..repository import RepositoryError
from ..schemas import CategoryCreate, CategoryRead
from . import http_error

router = APIRouter(prefix="/categories", tags=["categories"])

CategoryId = Annotated[int, Path(gt=0, description="Додатний ідентифікатор категорії.")]


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій",
    operation_id="list_categories",
)
def list_categories() -> list[dict[str, Any]]:
    """Повернути всі категорії за зростанням `id`."""
    try:
        return repository.list_categories()
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    operation_id="create_category",
    responses={409: {"description": "Категорія з такою назвою вже існує."}},
)
def create_category(category: CategoryCreate) -> dict[str, Any]:
    """Створити категорію; назва має бути унікальною."""
    try:
        return repository.create_category(category.name)
    except RepositoryError as exc:
        raise http_error(exc) from exc


@router.delete(
    "/{category_id}",
    status_code=204,
    summary="Видалити порожню категорію",
    operation_id="delete_category",
    responses={
        404: {"description": "Категорію не знайдено."},
        409: {"description": "Категорія містить записи."},
    },
)
def delete_category(category_id: CategoryId) -> None:
    """Видалити категорію, яка не містить жодного запису."""
    try:
        repository.delete_category(category_id)
    except RepositoryError as exc:
        raise http_error(exc) from exc
