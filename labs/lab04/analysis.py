"""Перевірка відповіді NVD і правило аналізу за варіантом.

Внутрішній запис (результат ``extract_record``) — словник із ключами:

* ``description`` — перший непорожній англійський опис або ``None``;
* ``vuln_status`` — статус NVD (непорожній рядок) або ``None``;
* ``cvss`` — ``None`` (оцінки немає або її не аналізували) або словник
  ``{"version", "score", "source", "vector", "data"}``, де ``data`` — це
  ``cvssData`` вибраної оцінки CVSS v3.1.
"""

import math
from typing import Any

CVSS_VERSION = "3.1"
STATUS_REJECTED = "Rejected"


class DataError(ValueError):
    """Відповідь має неправильну структуру або недопустиме значення."""


ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

# номер варіанта -> (поріг T, поле field, значення expected)
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


def _is_non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _read_status(cve: dict[str, Any]) -> str | None:
    if "vulnStatus" not in cve:
        return None
    status = cve["vulnStatus"]
    if not _is_non_empty_str(status):
        raise DataError("vulnStatus має бути непорожнім рядком")
    return status


def _select_description(cve: dict[str, Any]) -> str | None:
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise DataError("descriptions має бути списком")
    chosen = None
    for item in descriptions:
        if not isinstance(item, dict):
            raise DataError("елемент descriptions має бути об'єктом")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise DataError("lang і value в descriptions мають бути рядками")
        if chosen is None and lang == "en" and value.strip():
            chosen = value
    return chosen


def _check_base_score(score: Any) -> None:
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise DataError("baseScore має бути числом")
    if not math.isfinite(score) or not 0 <= score <= 10:
        raise DataError("baseScore має бути скінченним числом від 0 до 10")


def _optional_text(data: dict[str, Any], key: str) -> str | None:
    if key not in data:
        return None
    if not _is_non_empty_str(data[key]):
        raise DataError(f"{key} має бути непорожнім рядком")
    return data[key]


def _select_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise DataError("metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    items = metrics["cvssMetricV31"]
    if not isinstance(items, list):
        raise DataError("cvssMetricV31 має бути списком")
    if not items:
        return None
    if not all(isinstance(item, dict) for item in items):
        raise DataError("елементи cvssMetricV31 мають бути об'єктами")

    chosen = next((item for item in items if item.get("type") == "Primary"), items[0])
    data = chosen.get("cvssData")
    if not isinstance(data, dict):
        raise DataError("cvssData має бути об'єктом")
    _check_base_score(data.get("baseScore"))

    version = None
    if "version" in data:
        if data["version"] != CVSS_VERSION:
            raise DataError(f"version має дорівнювати {CVSS_VERSION!r}")
        version = CVSS_VERSION
    return {
        "version": version,
        "score": data["baseScore"],
        "source": _optional_text(chosen, "source"),
        "vector": _optional_text(data, "vectorString"),
        "data": data,
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None."""
    if not isinstance(payload, dict):
        raise DataError("відповідь NVD має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise DataError("vulnerabilities відсутнє або не є списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise DataError("для точного ідентифікатора очікується не більше одного запису")

    item = vulnerabilities[0]
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        raise DataError("елемент vulnerabilities не містить об'єкта cve")
    if cve.get("id") != cve_id:
        raise DataError("cve.id не збігається із запитаним ідентифікатором")

    status = _read_status(cve)
    record: dict[str, Any] = {
        "description": _select_description(cve),
        "vuln_status": status,
        "cvss": None,
    }
    if status is None or status == STATUS_REJECTED:
        return record
    record["cvss"] = _select_cvss(cve)
    return record


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта до запису й повертає словник звіту."""
    if (
        not isinstance(variant, int)
        or isinstance(variant, bool)
        or variant not in VARIANT_RULES
    ):
        raise DataError("номер варіанта має бути цілим числом від 1 до 15")
    threshold, field, expected = VARIANT_RULES[variant]
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == STATUS_REJECTED:
        report["decision"] = "rejected"
        return report

    report["decision"] = "insufficient_data"
    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]
    if field not in cvss["data"]:
        return report

    observed = cvss["data"][field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise DataError(f"недопустиме значення поля {field}")
    report["observed"] = observed
    is_review = cvss["score"] >= threshold and observed == expected
    report["decision"] = "review" if is_review else "other"
    return report
