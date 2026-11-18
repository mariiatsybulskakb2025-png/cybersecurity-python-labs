from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def make_response(payload=None, status=200):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def patch_get(monkeypatch, response=None, side_effect=None):
    fake_get = Mock(return_value=response, side_effect=side_effect)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


# ---------- build_headers ----------


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")

    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_headers_strip_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123  ")

    assert api_client.build_headers()["apiKey"] == "fake-key-123"


@pytest.mark.parametrize("value", ["", "   "])
def test_headers_blank_key_means_no_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)

    assert "apiKey" not in api_client.build_headers()


def test_key_is_read_at_call_time(monkeypatch):
    assert "apiKey" not in api_client.build_headers()

    monkeypatch.setenv("NVD_API_KEY", "late-key")

    assert api_client.build_headers()["apiKey"] == "late-key"


# ---------- fetch_response ----------


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload)
    fake_get = patch_get(monkeypatch, response)

    assert api_client.fetch_response("CVE-2099-10001") == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_in_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    fake_get = patch_get(monkeypatch, make_response({}))

    api_client.fetch_response("CVE-2099-10001")

    kwargs = fake_get.call_args.kwargs
    assert kwargs["headers"]["apiKey"] == "fake-key-123"
    assert "fake-key-123" not in str(kwargs["params"])
    assert "fake-key-123" not in fake_get.call_args.args[0]


def test_fetch_makes_exactly_one_request(monkeypatch):
    fake_get = patch_get(monkeypatch, make_response({}))

    api_client.fetch_response("CVE-2099-10001")

    assert fake_get.call_count == 1


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("connect"),
        requests.exceptions.ReadTimeout("read"),
        requests.exceptions.ConnectionError("down"),
        requests.exceptions.SSLError("tls"),
    ],
)
def test_fetch_passes_network_errors_up(monkeypatch, error):
    patch_get(monkeypatch, side_effect=error)

    with pytest.raises(type(error)):
        api_client.fetch_response("CVE-2099-10001")


@pytest.mark.parametrize("status", [404, 403, 500, 503])
def test_fetch_raises_http_error(monkeypatch, status):
    response = make_response(status=status)
    response.raise_for_status.side_effect = requests.HTTPError(response=response)
    patch_get(monkeypatch, response)

    with pytest.raises(requests.HTTPError) as info:
        api_client.fetch_response("CVE-2099-10001")

    assert info.value.response.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [201, 204, 301, 302])
def test_fetch_rejects_unexpected_success_status(monkeypatch, status):
    response = make_response({"vulnerabilities": []}, status=status)
    patch_get(monkeypatch, response)

    with pytest.raises(api_client.UnexpectedStatusError) as info:
        api_client.fetch_response("CVE-2099-10001")

    assert info.value.status_code == status
    response.json.assert_not_called()


def test_fetch_passes_invalid_json_up(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, response)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_real_network_is_blocked_by_fixture():
    with pytest.raises(AttributeError):
        requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
