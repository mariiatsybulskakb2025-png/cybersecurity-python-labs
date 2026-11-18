"""Консольна утиліта перегляду запису про вразливість у NVD."""

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


class RetrievalError(Exception):
    """Не вдалося отримати відповідь (мережа або файл)."""


def cve_identifier(value: str) -> str:
    """Перевіряє повний збіг ідентифікатора з шаблоном CVE."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "очікується ідентифікатор у форматі CVE-РРРР-NNNN (великими літерами)"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Перегляд запису про вразливість у NVD (CVSS v3.1)."
    )
    parser.add_argument("--cve", required=True, type=cve_identifier)
    parser.add_argument(
        "--input", help="локальний JSON-файл з відповіддю NVD (без мережевих запитів)"
    )
    return parser


def load_response(path: str | Path) -> Any:
    """Читає UTF-8 JSON-файл з локальною відповіддю NVD."""
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _load_local(path: str) -> Any:
    try:
        return load_response(path)
    except FileNotFoundError:
        raise RetrievalError(f"файл не знайдено: {path}") from None
    except OSError:
        raise RetrievalError(f"не вдалося прочитати файл: {path}") from None
    except UnicodeDecodeError:
        raise RetrievalError("файл не є коректним UTF-8") from None
    except json.JSONDecodeError:
        raise RetrievalError("файл не містить коректного JSON") from None


def _status_of(exc: requests.RequestException) -> str:
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return str(status) if status is not None else "невідомий"


def _fetch_remote(cve_id: str) -> Any:
    try:
        return api_client.fetch_response(cve_id)
    except requests.Timeout:
        raise RetrievalError("перевищено час очікування відповіді NVD") from None
    except requests.ConnectionError:
        raise RetrievalError("не вдалося встановити з'єднання з NVD") from None
    except requests.HTTPError as exc:
        raise RetrievalError(
            f"NVD повернув HTTP-помилку {_status_of(exc)}; це не означає, "
            "що пошук CVE дав порожній результат"
        ) from None
    except api_client.UnexpectedStatusError as exc:
        raise RetrievalError(
            f"неочікуваний HTTP-статус {exc.status_code} (очікувався 200)"
        ) from None
    except (requests.exceptions.JSONDecodeError, json.JSONDecodeError):
        raise RetrievalError("відповідь NVD не є коректним JSON") from None
    except requests.RequestException:
        raise RetrievalError("запит до NVD не вдався") from None


def _is_valid_variant(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 15


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входу CLI; повертає код завершення (0, 1 або 2)."""
    args = build_parser().parse_args(argv)
    if not _is_valid_variant(VARIANT_NUMBER):
        print(
            "Помилка: VARIANT_NUMBER має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    try:
        if args.input is not None:
            payload = _load_local(args.input)
        else:
            payload = _fetch_remote(args.cve)
    except RetrievalError as exc:
        print(f"Помилка отримання даних: {exc}.", file=sys.stderr)
        return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Помилка перевірки даних: {exc}.", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
