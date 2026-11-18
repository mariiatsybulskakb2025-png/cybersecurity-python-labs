import copy

import pytest

from labs.lab04 import analysis

REPORT_KEYS = {
    "cve_id",
    "variant",
    "description",
    "vuln_status",
    "cvss_version",
    "score",
    "score_source",
    "vector",
    "rule",
    "observed",
    "decision",
}


def cve_of(payload):
    return payload["vulnerabilities"][0]["cve"]


def metric_of(payload, index=0):
    return cve_of(payload)["metrics"]["cvssMetricV31"][index]


def record_for(payload, cve_id="CVE-2099-10001"):
    return analysis.extract_record(payload, cve_id)


# ---------- extract_record: структура відповіді ----------


def test_extract_returns_record_for_sample(sample_payload, cve_id):
    record = analysis.extract_record(sample_payload, cve_id)

    assert record["description"] == "Synthetic vulnerability for offline API testing."
    assert record["vuln_status"] == "Analyzed"
    assert record["cvss"]["version"] == "3.1"
    assert record["cvss"]["score"] == 9.8
    assert record["cvss"]["source"] == "nvd@nist.gov"
    assert record["cvss"]["vector"].startswith("CVSS:3.1/")


def test_extract_empty_list_means_not_found(cve_id):
    assert analysis.extract_record({"vulnerabilities": []}, cve_id) is None


def test_extract_does_not_change_payload(sample_payload, cve_id):
    original = copy.deepcopy(sample_payload)

    analysis.extract_record(sample_payload, cve_id)

    assert sample_payload == original


@pytest.mark.parametrize("payload", [[], "text", None, 5])
def test_extract_rejects_non_object_payload(payload, cve_id):
    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


@pytest.mark.parametrize("value", [None, {}, "x", 1])
def test_extract_rejects_bad_vulnerabilities(value, cve_id):
    with pytest.raises(ValueError):
        analysis.extract_record({"vulnerabilities": value}, cve_id)


def test_extract_rejects_missing_vulnerabilities(cve_id):
    with pytest.raises(ValueError):
        analysis.extract_record({}, cve_id)


def test_extract_rejects_two_items(sample_payload, cve_id):
    sample_payload["vulnerabilities"].append(
        copy.deepcopy(sample_payload["vulnerabilities"][0])
    )

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, cve_id)


@pytest.mark.parametrize("item", [None, "x", {}, {"cve": None}, {"cve": []}])
def test_extract_rejects_bad_item(item, cve_id):
    with pytest.raises(ValueError):
        analysis.extract_record({"vulnerabilities": [item]}, cve_id)


@pytest.mark.parametrize("other_id", ["CVE-2099-10002", "cve-2099-10001", None])
def test_extract_rejects_id_mismatch(sample_payload, other_id):
    cve_of(sample_payload)["id"] = other_id

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, "CVE-2099-10001")


# ---------- extract_record: статус і опис ----------


def test_extract_rejects_null_status(sample_payload, cve_id):
    cve_of(sample_payload)["vulnStatus"] = None

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, cve_id)


def test_extract_missing_status_gives_none(make_payload, cve_id):
    record = analysis.extract_record(make_payload(status=None), cve_id)

    assert record["vuln_status"] is None
    assert record["cvss"] is None


@pytest.mark.parametrize("status", ["", "   ", 5, ["Analyzed"]])
def test_extract_rejects_bad_status(make_payload, cve_id, status):
    with pytest.raises(ValueError):
        analysis.extract_record(make_payload(status=status), cve_id)


def test_extract_description_skips_empty_and_other_languages(sample_payload, cve_id):
    cve_of(sample_payload)["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "First English"},
        {"lang": "en", "value": "Second English"},
    ]

    record = analysis.extract_record(sample_payload, cve_id)

    assert record["description"] == "First English"


def test_extract_description_none_without_english(sample_payload, cve_id):
    cve_of(sample_payload)["descriptions"] = [{"lang": "es", "value": "Hola"}]

    assert analysis.extract_record(sample_payload, cve_id)["description"] is None


def test_extract_description_missing_field_gives_none(sample_payload, cve_id):
    del cve_of(sample_payload)["descriptions"]

    assert analysis.extract_record(sample_payload, cve_id)["description"] is None


@pytest.mark.parametrize(
    "descriptions",
    [
        None,
        "text",
        {},
        ["text"],
        [{"lang": "en"}],
        [{"lang": 1, "value": "x"}],
        [{"lang": "en", "value": 5}],
    ],
)
def test_extract_rejects_bad_descriptions(sample_payload, cve_id, descriptions):
    cve_of(sample_payload)["descriptions"] = descriptions

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, cve_id)


# ---------- extract_record: вибір оцінки ----------


def test_extract_rejected_does_not_analyse_metrics(make_payload, cve_id):
    payload = make_payload(status="Rejected")
    cve_of(payload)["metrics"] = None

    record = analysis.extract_record(payload, cve_id)

    assert record["vuln_status"] == "Rejected"
    assert record["description"] is not None
    assert record["cvss"] is None


def test_extract_missing_status_does_not_analyse_metrics(make_payload, cve_id):
    payload = make_payload(status=None)
    cve_of(payload)["metrics"] = "broken"

    assert analysis.extract_record(payload, cve_id)["cvss"] is None


def test_extract_missing_metrics_means_no_score(make_payload, cve_id):
    payload = make_payload()
    del cve_of(payload)["metrics"]

    assert analysis.extract_record(payload, cve_id)["cvss"] is None


def test_extract_missing_v31_means_no_score(make_payload, cve_id):
    payload = make_payload()
    cve_of(payload)["metrics"] = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}

    assert analysis.extract_record(payload, cve_id)["cvss"] is None


def test_extract_empty_v31_list_means_no_score(make_payload, cve_id):
    payload = make_payload()
    cve_of(payload)["metrics"]["cvssMetricV31"] = []

    assert analysis.extract_record(payload, cve_id)["cvss"] is None


@pytest.mark.parametrize("metrics", [None, [], "x", 5])
def test_extract_rejects_bad_metrics(make_payload, cve_id, metrics):
    payload = make_payload()
    cve_of(payload)["metrics"] = metrics

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


@pytest.mark.parametrize("value", [None, {}, "x", 5])
def test_extract_rejects_bad_v31_container(make_payload, cve_id, value):
    payload = make_payload()
    cve_of(payload)["metrics"]["cvssMetricV31"] = value

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


def test_extract_rejects_non_dict_metric_item(make_payload, cve_id):
    payload = make_payload()
    cve_of(payload)["metrics"]["cvssMetricV31"].append("x")

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


def test_extract_primary_beats_previous_secondary(make_payload, cve_id):
    payload = make_payload()
    primary = metric_of(payload)
    secondary = copy.deepcopy(primary)
    secondary["type"] = "Secondary"
    secondary["source"] = "other@example.invalid"
    secondary["cvssData"]["baseScore"] = 5.0
    cve_of(payload)["metrics"]["cvssMetricV31"] = [secondary, primary]

    record = analysis.extract_record(payload, cve_id)

    assert record["cvss"]["score"] == 9.8
    assert record["cvss"]["source"] == "nvd@nist.gov"


def test_extract_first_item_used_without_primary(make_payload, cve_id):
    payload = make_payload()
    first = metric_of(payload)
    first["type"] = "Secondary"
    first["cvssData"]["baseScore"] = 4.0
    second = copy.deepcopy(first)
    second["cvssData"]["baseScore"] = 8.0
    cve_of(payload)["metrics"]["cvssMetricV31"] = [first, second]

    assert analysis.extract_record(payload, cve_id)["cvss"]["score"] == 4.0


@pytest.mark.parametrize("data", [None, [], "x", 5])
def test_extract_rejects_bad_cvss_data(make_payload, cve_id, data):
    payload = make_payload()
    metric_of(payload)["cvssData"] = data

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


def test_extract_rejects_missing_cvss_data(make_payload, cve_id):
    payload = make_payload()
    del metric_of(payload)["cvssData"]

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


@pytest.mark.parametrize("score", [0, 0.0, 5.5, 10, 10.0])
def test_extract_accepts_scores_in_range(make_payload, cve_id, score):
    record = analysis.extract_record(make_payload(score=score), cve_id)

    assert record["cvss"]["score"] == score


@pytest.mark.parametrize(
    "score",
    [
        "9.8",
        True,
        False,
        None,
        [],
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.1,
        10.1,
    ],
)
def test_extract_rejects_bad_scores(make_payload, cve_id, score):
    payload = make_payload()
    metric_of(payload)["cvssData"]["baseScore"] = score

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


def test_extract_rejects_missing_score(make_payload, cve_id):
    payload = make_payload()
    del metric_of(payload)["cvssData"]["baseScore"]

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


# ---------- extract_record: version, vector, source ----------


def test_extract_optional_report_fields_may_be_absent(make_payload, cve_id):
    payload = make_payload()
    metric = metric_of(payload)
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]

    cvss = analysis.extract_record(payload, cve_id)["cvss"]

    assert cvss["version"] is None
    assert cvss["source"] is None
    assert cvss["vector"] is None
    assert cvss["score"] == 9.8


@pytest.mark.parametrize("version", ["3.0", "3", 3.1, None, ""])
def test_extract_rejects_wrong_version(make_payload, cve_id, version):
    payload = make_payload()
    metric_of(payload)["cvssData"]["version"] = version

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


@pytest.mark.parametrize("value", ["", "  ", None, 5])
def test_extract_rejects_bad_vector(make_payload, cve_id, value):
    payload = make_payload()
    metric_of(payload)["cvssData"]["vectorString"] = value

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


@pytest.mark.parametrize("value", ["", "  ", None, 5])
def test_extract_rejects_bad_source(make_payload, cve_id, value):
    payload = make_payload()
    metric_of(payload)["source"] = value

    with pytest.raises(ValueError):
        analysis.extract_record(payload, cve_id)


# ---------- build_report: варіант 11 (поріг 6.0, userInteraction == REQUIRED) ----------


@pytest.mark.parametrize(
    ("score", "interaction", "expected"),
    [
        (5.9, "REQUIRED", "other"),  # нижче порога
        (6.0, "REQUIRED", "review"),  # рівно на порозі
        (6.1, "REQUIRED", "review"),  # вище порога
        (9.8, "REQUIRED", "review"),
        (10, "REQUIRED", "review"),
        (6.0, "NONE", "other"),  # поріг є, але ознаки немає
        (9.8, "NONE", "other"),  # висока оцінка без ознаки
        (0, "REQUIRED", "other"),
    ],
)
def test_variant_11_decision(make_payload, cve_id, score, interaction, expected):
    payload = make_payload(score=score, userInteraction=interaction)

    report = analysis.build_report(record_for(payload), cve_id, 11)

    assert report["decision"] == expected
    assert report["observed"] == interaction
    assert report["score"] == score


def test_build_report_full_report_for_sample(sample_payload, cve_id):
    report = analysis.build_report(record_for(sample_payload), cve_id, 11)

    assert report == {
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


def test_build_report_does_not_change_record(sample_payload, cve_id):
    record = record_for(sample_payload)
    original = copy.deepcopy(record)

    analysis.build_report(record, cve_id, 11)

    assert record == original


# ---------- build_report: стани ----------


def test_build_report_not_found(cve_id):
    report = analysis.build_report(None, cve_id, 11)

    assert set(report) == REPORT_KEYS
    assert report["decision"] == "not_found"
    assert report["cve_id"] == cve_id
    assert report["variant"] == 11
    assert report["rule"] == {
        "threshold": 6.0,
        "field": "userInteraction",
        "expected": "REQUIRED",
    }
    for key in REPORT_KEYS - {"cve_id", "variant", "rule", "decision"}:
        assert report[key] is None


def test_build_report_rejected_even_with_high_score(make_payload, cve_id):
    payload = make_payload(status="Rejected", score=10, userInteraction="REQUIRED")

    report = analysis.build_report(record_for(payload), cve_id, 11)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    for key in ("cvss_version", "score", "score_source", "vector", "observed"):
        assert report[key] is None


def test_build_report_missing_status_is_insufficient(make_payload, cve_id):
    report = analysis.build_report(record_for(make_payload(status=None)), cve_id, 11)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] is not None
    assert report["score"] is None
    assert report["observed"] is None


def test_build_report_no_v31_score_is_insufficient(make_payload, cve_id):
    payload = make_payload()
    cve_of(payload)["metrics"]["cvssMetricV31"] = []

    report = analysis.build_report(record_for(payload), cve_id, 11)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_build_report_missing_variant_field_is_insufficient(make_payload, cve_id):
    payload = make_payload()
    del metric_of(payload)["cvssData"]["userInteraction"]

    report = analysis.build_report(record_for(payload), cve_id, 11)

    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("value", [None, "MAYBE", "none", 5, ["NONE"]])
def test_build_report_invalid_field_value_is_error(make_payload, cve_id, value):
    payload = make_payload()
    metric_of(payload)["cvssData"]["userInteraction"] = value

    with pytest.raises(ValueError):
        analysis.build_report(record_for(payload), cve_id, 11)


@pytest.mark.parametrize("variant", [0, 16, -1, True, "11", 11.0, None, [11]])
def test_build_report_invalid_variant(sample_payload, cve_id, variant):
    with pytest.raises(ValueError):
        analysis.build_report(record_for(sample_payload), cve_id, variant)


# ---------- build_report: усі 15 варіантів за таблицею методички ----------

RULES = [
    (1, 7.0, "attackVector", "NETWORK"),
    (2, 8.0, "attackComplexity", "LOW"),
    (3, 7.0, "privilegesRequired", "NONE"),
    (4, 8.0, "userInteraction", "NONE"),
    (5, 7.0, "confidentialityImpact", "HIGH"),
    (6, 7.0, "integrityImpact", "HIGH"),
    (7, 7.0, "availabilityImpact", "HIGH"),
    (8, 9.0, "scope", "CHANGED"),
    (9, 5.0, "attackVector", "LOCAL"),
    (10, 6.0, "privilegesRequired", "LOW"),
    (11, 6.0, "userInteraction", "REQUIRED"),
    (12, 6.0, "confidentialityImpact", "LOW"),
    (13, 6.0, "integrityImpact", "LOW"),
    (14, 6.0, "availabilityImpact", "LOW"),
    (15, 8.0, "attackComplexity", "HIGH"),
]


@pytest.mark.parametrize(("variant", "threshold", "field", "expected"), RULES)
def test_every_variant_rule_and_threshold(
    make_payload, cve_id, variant, threshold, field, expected
):
    def decide(score, value):
        payload = make_payload(score=score, **{field: value})
        return analysis.build_report(record_for(payload), cve_id, variant)

    at_threshold = decide(threshold, expected)
    assert at_threshold["rule"] == {
        "threshold": threshold,
        "field": field,
        "expected": expected,
    }
    assert at_threshold["decision"] == "review"
    assert decide(threshold - 0.1, expected)["decision"] == "other"
    assert decide(10, expected)["decision"] == "review"

    wrong = next(v for v in analysis.ALLOWED_VALUES[field] if v != expected)
    assert decide(10, wrong)["decision"] == "other"


@pytest.mark.parametrize(
    ("variant", "decision"),
    [(v, "review" if v <= 7 else "other") for v in range(1, 16)],
)
def test_sample_file_decision_for_every_variant(
    sample_payload, cve_id, variant, decision
):
    report = analysis.build_report(record_for(sample_payload), cve_id, variant)

    assert report["decision"] == decision
