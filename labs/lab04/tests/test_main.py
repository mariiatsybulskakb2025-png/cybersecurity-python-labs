import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main

SAMPLE_REPORT_V11 = {
    "cve_id": "CVE-2099-10001",
    "variant": 11,
    "description": "Synthetic vulnerability for offline API testing.",
    "vuln_status": "Analyzed",
    "cvss_version": "3.1",
    "score": 9.8,
    "score_source": "nvd@nist.gov",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rule": {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    "observed": "NONE",
    "decision": "other",
}


@pytest.fixture
def forbid_network(monkeypatch):
    fake = Mock(side_effect=AssertionError("мережевий запит у локальному режимі"))
    monkeypatch.setattr(api_client, "fetch_response", fake)
    return fake


@pytest.fixture
def fake_fetch(monkeypatch, sample_payload):
    fake = Mock(return_value=sample_payload)
    monkeypatch.setattr(api_client, "fetch_response", fake)
    return fake


def run(capsys, *argv):
    code = main.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---------- успішні запуски ----------


def test_local_mode_prints_one_json_report(capsys, local_file, forbid_network):
    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(local_file))

    assert code == 0
    assert err == ""
    assert json.loads(out) == SAMPLE_REPORT_V11
    forbid_network.assert_not_called()


def test_network_mode_uses_client(capsys, fake_fetch):
    code, out, err = run(capsys, "--cve", "CVE-2099-10001")

    assert code == 0
    assert err == ""
    assert json.loads(out) == SAMPLE_REPORT_V11
    fake_fetch.assert_called_once_with("CVE-2099-10001")


def test_output_is_not_ascii_escaped(capsys, tmp_path, sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = (
        "Опис українською"
    )
    path = tmp_path / "ua.json"
    path.write_text(json.dumps(sample_payload, ensure_ascii=False), encoding="utf-8")

    code, out, _ = run(capsys, "--cve", "CVE-2099-10001", "--input", str(path))

    assert code == 0
    assert "Опис українською" in out
    assert "\\u" not in out


@pytest.mark.parametrize("variant", range(1, 16))
def test_variant_from_student_module(capsys, monkeypatch, local_file, variant):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)

    code, out, _ = run(capsys, "--cve", "CVE-2099-10001", "--input", str(local_file))

    report = json.loads(out)
    assert code == 0
    assert report["variant"] == variant
    assert report["decision"] == ("review" if variant <= 7 else "other")


@pytest.mark.parametrize(
    ("payload", "decision"),
    [
        ({"vulnerabilities": []}, "not_found"),
        (
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2099-10001", "vulnStatus": "Rejected"}}
                ]
            },
            "rejected",
        ),
        ({"vulnerabilities": [{"cve": {"id": "CVE-2099-10001"}}]}, "insufficient_data"),
    ],
)
def test_non_error_states_exit_with_zero(capsys, tmp_path, payload, decision):
    path = tmp_path / "state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(path))

    assert code == 0
    assert err == ""
    assert json.loads(out)["decision"] == decision


# ---------- аргументи та номер варіанта: код 2 ----------


@pytest.mark.parametrize(
    "bad_id",
    [
        "cve-2099-10001",
        "CVE-2099-123",
        "CVE-209-10001",
        "CVE-20991-10001",
        "CVE-2099-10001\n",
        "CVE-2099-10001 ",
        "XCVE-2099-10001",
        "CVE-٢٠٩٩-١٠٠٠١",
        "",
    ],
)
def test_invalid_cve_is_argparse_error(capsys, bad_id):
    with pytest.raises(SystemExit) as info:
        main.main(["--cve", bad_id])

    assert info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--cve" in captured.err


@pytest.mark.parametrize(
    "good_id", ["CVE-2099-10001", "CVE-2021-44228", "CVE-2099-1234567"]
)
def test_valid_cve_formats_pass(capsys, tmp_path, good_id):
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")

    code, _, _ = run(capsys, "--cve", good_id, "--input", str(path))

    assert code == 0


def test_missing_cve_is_argparse_error(capsys):
    with pytest.raises(SystemExit) as info:
        main.main([])

    assert info.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("bad_variant", [0, 16, -3, True, "11", 11.0, None])
def test_invalid_variant_exits_with_two(capsys, monkeypatch, local_file, bad_variant):
    monkeypatch.setattr(main, "VARIANT_NUMBER", bad_variant)

    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(local_file))

    assert code == 2
    assert out == ""
    assert "VARIANT_NUMBER" in err
    assert "Traceback" not in err


# ---------- помилки отримання і перевірки даних: код 1 ----------


def test_missing_file(capsys, tmp_path, forbid_network):
    code, out, err = run(
        capsys, "--cve", "CVE-2099-10001", "--input", str(tmp_path / "none.json")
    )

    assert (code, out) == (1, "")
    assert "не знайдено" in err
    assert "Traceback" not in err


def test_directory_instead_of_file(capsys, tmp_path, forbid_network):
    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(tmp_path))

    assert (code, out) == (1, "")
    assert "не вдалося прочитати" in err


def test_invalid_json_file(capsys, tmp_path, forbid_network):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")

    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(path))

    assert (code, out) == (1, "")
    assert "JSON" in err
    assert "Traceback" not in err


def test_invalid_utf8_file(capsys, tmp_path, forbid_network):
    path = tmp_path / "latin.json"
    path.write_bytes(b'{"a": "\xff\xfe"}')

    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(path))

    assert (code, out) == (1, "")
    assert "UTF-8" in err


def test_data_error_exits_with_one(capsys, tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text('{"vulnerabilities": "nope"}', encoding="utf-8")

    code, out, err = run(capsys, "--cve", "CVE-2099-10001", "--input", str(path))

    assert (code, out) == (1, "")
    assert "Помилка перевірки даних" in err
    assert "Traceback" not in err


def test_id_mismatch_exits_with_one(capsys, local_file):
    code, out, err = run(capsys, "--cve", "CVE-2099-10002", "--input", str(local_file))

    assert (code, out) == (1, "")
    assert "Помилка перевірки даних" in err


def make_http_error(status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.HTTPError(response=response)


@pytest.mark.parametrize(
    ("error", "fragment"),
    [
        (requests.exceptions.ConnectTimeout("t"), "очікування"),
        (requests.exceptions.ReadTimeout("t"), "очікування"),
        (requests.exceptions.ConnectionError("c"), "з'єднання"),
        (requests.exceptions.SSLError("tls"), "з'єднання"),
        (make_http_error(404), "404"),
        (make_http_error(503), "503"),
        (api_client.UnexpectedStatusError(302), "302"),
        (requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1), "JSON"),
        (requests.exceptions.TooManyRedirects("r"), "не вдався"),
    ],
)
def test_network_errors_exit_with_one(capsys, monkeypatch, error, fragment):
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=error))

    code, out, err = run(capsys, "--cve", "CVE-2099-10001")

    assert (code, out) == (1, "")
    assert fragment in err
    assert "Traceback" not in err


def test_http_404_is_not_reported_as_empty_result(capsys, monkeypatch):
    monkeypatch.setattr(
        api_client, "fetch_response", Mock(side_effect=make_http_error(404))
    )

    code, out, err = run(capsys, "--cve", "CVE-2099-10001")

    assert code == 1
    assert "not_found" not in out + err
    assert "не означає" in err


def test_secrets_and_error_text_are_not_printed(capsys, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "super-secret-key")
    error = requests.exceptions.ConnectionError("apiKey=super-secret-key leaked body")
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=error))

    code, out, err = run(capsys, "--cve", "CVE-2099-10001")

    assert code == 1
    assert "super-secret-key" not in out + err
    assert "leaked body" not in out + err


# ---------- load_response ----------


def test_load_response_reads_utf8(tmp_path):
    path = tmp_path / "ua.json"
    path.write_text('{"text": "Привіт"}', encoding="utf-8")

    assert main.load_response(path) == {"text": "Привіт"}


def test_load_response_errors(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[1,", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        main.load_response(bad)
    with pytest.raises(FileNotFoundError):
        main.load_response(tmp_path / "none.json")
