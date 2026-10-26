import gzip
import json
from pathlib import Path

from logsentry.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
AUTH = str(SAMPLES / "auth.log")
WEB = str(SAMPLES / "access.log")


def scan(*extra, capsys):
    code = main(["scan", "--auth", AUTH, "--web", WEB, "--year", "2026", *extra])
    return code, capsys.readouterr().out


def test_sample_scenario_detects_every_rule(capsys):
    code, out = scan("--format", "json", capsys=capsys)
    assert code == 0
    report = json.loads(out)
    found = {(f["rule_id"], f["src_ip"]) for f in report["findings"]}
    assert {
        ("WEB-001", "203.0.113.45"), ("WEB-002", "203.0.113.45"), ("WEB-003", "203.0.113.45"),
        ("WEB-004", "203.0.113.45"), ("WEB-005", "203.0.113.45"), ("WEB-006", "203.0.113.45"),
        ("WEB-007", "203.0.113.45"), ("SSH-001", "198.51.100.23"), ("SSH-003", "198.51.100.23"),
        ("AUTH-004", "198.51.100.23"), ("SSH-002", "192.0.2.77"),
    } <= found


def test_no_false_positives_on_sample_background_traffic(capsys):
    _, out = scan("--format", "json", capsys=capsys)
    attackers = {"203.0.113.45", "198.51.100.23", "192.0.2.77", "local:web01"}
    assert {f["src_ip"] for f in json.loads(out)["findings"]} <= attackers


def test_ip_ranking_puts_web_attacker_first(capsys):
    _, out = scan("--format", "json", capsys=capsys)
    assert json.loads(out)["ip_ranking"][0]["ip"] == "203.0.113.45"


def test_min_severity_filters(capsys):
    _, out = scan("--format", "json", "--min-severity", "critical", capsys=capsys)
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"CRITICAL"}


def test_fail_on_returns_exit_code_2(capsys):
    code, _ = scan("--fail-on", "critical", "--no-color", capsys=capsys)
    assert code == 2


def test_markdown_report_to_file(tmp_path, capsys):
    target = tmp_path / "reports" / "report.md"
    code, _ = scan("--format", "markdown", "-o", str(target), capsys=capsys)
    assert code == 0
    text = target.read_text(encoding="utf-8")
    assert text.startswith("# LogSentry incident report")
    assert "[T1505.003 Server Software Component: Web Shell]" in text


def test_gzip_input(tmp_path, capsys):
    gz = tmp_path / "auth.log.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write(Path(AUTH).read_text(encoding="utf-8"))
    main(["scan", "--auth", str(gz), "--year", "2026", "--format", "json"])
    ids = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "SSH-003" in ids


def test_missing_file_is_an_error(capsys):
    assert main(["scan", "--auth", "does-not-exist.log"]) == 1
    assert "error" in capsys.readouterr().err


def test_no_inputs_is_an_error(capsys):
    assert main(["scan"]) == 1


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "T1110.001" in out and "WEB-007" in out
