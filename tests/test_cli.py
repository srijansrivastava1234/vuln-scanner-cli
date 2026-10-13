import json
from unittest.mock import patch
from cli import determine_exit_code, main


def test_determine_exit_code_pass():
    results = {"assessment": {"status": "AUDITED", "grade": "A", "score": 85}}
    assert determine_exit_code(results, fail_grade="F") == 0
    assert determine_exit_code(results, fail_grade="B") == 0


def test_determine_exit_code_failure_threshold():
    results = {"assessment": {"status": "AUDITED", "grade": "F", "score": 40}}
    assert determine_exit_code(results, fail_grade="F") == 1

    results_c = {"assessment": {"status": "AUDITED", "grade": "C", "score": 60}}
    assert determine_exit_code(results_c, fail_grade="B") == 1
    assert determine_exit_code(results_c, fail_grade="F") == 0


def test_determine_exit_code_unreachable():
    results = {"assessment": {"status": "UNREACHABLE", "grade": "N/A"}}
    assert determine_exit_code(results, fail_grade="F") == 2

    results_fail = {"assessment": {"status": "HTTP_FAILED", "grade": "N/A"}}
    assert determine_exit_code(results_fail, fail_grade="F") == 2


@patch("cli.scan_target")
def test_cli_main_json_export(mock_scan, tmp_path):
    mock_scan.return_value = {
        "target": "https://example.com",
        "http_status": 200,
        "ssl": {"status": "VALID"},
        "headers": {"findings": []},
        "cookies": [],
        "assessment": {"status": "AUDITED", "score": 100, "grade": "A+"},
    }

    out_file = tmp_path / "test_report.json"
    exit_code = main(["example.com", "--json", str(out_file)])

    assert exit_code == 0
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["target"] == "https://example.com"
    assert data["assessment"]["grade"] == "A+"


@patch("cli.scan_target")
def test_cli_main_fail_grade_exit_code(mock_scan):
    mock_scan.return_value = {
        "target": "https://example.com",
        "http_status": 200,
        "ssl": {"status": "EXPIRED"},
        "headers": {"findings": []},
        "cookies": [],
        "assessment": {"status": "AUDITED", "score": 30, "grade": "F"},
    }

    # Should exit with 1 when grade F triggers --fail-grade F
    assert main(["example.com", "--fail-grade", "F"]) == 1

    # Should exit with 0 when --fail-grade is not set
    assert main(["example.com"]) == 0
