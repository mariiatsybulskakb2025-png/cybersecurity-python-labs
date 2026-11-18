import copy
import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
CVE_ID = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def cve_id():
    return CVE_ID


@pytest.fixture
def sample_payload():
    """Нова копія синтетичної відповіді для кожного тесту."""
    with SAMPLE_PATH.open(encoding="utf-8") as file:
        return json.load(file)


@pytest.fixture
def make_payload(sample_payload):
    """Фабрика відповідей: змінює лише потрібні поля копії зразка."""

    def factory(
        *,
        score=None,
        status="Analyzed",
        **cvss_fields,
    ):
        payload = copy.deepcopy(sample_payload)
        cve = payload["vulnerabilities"][0]["cve"]
        data = cve["metrics"]["cvssMetricV31"][0]["cvssData"]
        if score is not None:
            data["baseScore"] = score
        data.update(cvss_fields)
        if status is None:
            del cve["vulnStatus"]
        else:
            cve["vulnStatus"] = status
        return payload

    return factory


@pytest.fixture
def local_file(tmp_path, sample_payload):
    path = tmp_path / "response.json"
    path.write_text(json.dumps(sample_payload), encoding="utf-8")
    return path
