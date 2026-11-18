"""Клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

import os
from typing import Any

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервіс повернув успішний, але не очікуваний HTTP-статус (не 200)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"неочікуваний HTTP-статус {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту; ключ береться зі змінної NVD_API_KEY."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD і повертає декодований JSON."""
    response = requests.get(
        NVD_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
