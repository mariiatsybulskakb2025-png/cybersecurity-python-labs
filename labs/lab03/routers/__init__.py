"""Маршрути FastAPI-застосунку."""

from fastapi import HTTPException

from ..repository import ConflictError, NotFoundError, RepositoryError


def http_error(exc: RepositoryError) -> HTTPException:
    """Перетворити помилку шару даних на HTTP-помилку без технічних деталей."""
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ConflictError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(
        status_code=500, detail="Внутрішня помилка сервера. Спробуйте пізніше."
    )
