import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "check_pr_body.py"
_spec = importlib.util.spec_from_file_location("check_pr_body", _SCRIPT)
check_pr_body = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_pr_body)

_TEMPLATE = _SCRIPT.parents[1] / "pull_request_template.md"

VALID = """\
## Planned stage
PR 02 — CI workflows

## Summary
Adds CI.

## Requirements addressed
None (infrastructure)

## Tests executed
pytest: 20 passed
"""


def test_valid_body_passes():
    assert check_pr_body.check(VALID) == []


def test_untouched_template_fails():
    problems = check_pr_body.check(_TEMPLATE.read_text())
    assert len(problems) == len(check_pr_body.REQUIRED_SECTIONS)


@pytest.mark.parametrize("body", [None, "", "   \n"])
def test_empty_body_fails(body):
    assert check_pr_body.check(body) == [
        "The PR description is empty. Fill in .github/pull_request_template.md."
    ]


def test_missing_section_is_named():
    body = VALID.replace("## Tests executed\npytest: 20 passed\n", "")
    assert check_pr_body.check(body) == ["Missing section: '## Tests executed'."]


def test_comment_only_section_is_empty():
    body = VALID.replace("Adds CI.", "<!-- describe -->")
    problems = check_pr_body.check(body)
    assert len(problems) == 1 and "Summary" in problems[0]


def test_headings_are_case_insensitive_and_crlf_tolerant():
    body = VALID.lower().replace("\n", "\r\n")
    assert check_pr_body.check(body) == []


def test_heading_with_trailing_qualifier_accepted():
    body = VALID.replace("## Tests executed", "## Tests executed (local, not in CI)")
    assert check_pr_body.check(body) == []


def test_longer_word_is_not_a_prefix_match():
    body = VALID.replace("## Summary", "## Summaryx")
    assert check_pr_body.check(body) == ["Missing section: '## Summary'."]


def test_h3_headings_accepted():
    assert check_pr_body.check(VALID.replace("## ", "### ")) == []


def test_main_exit_codes(monkeypatch, capsys):
    monkeypatch.setenv("PR_BODY", VALID)
    assert check_pr_body.main() == 0
    monkeypatch.setenv("PR_BODY", "nothing useful")
    assert check_pr_body.main() == 1
    assert "::error" in capsys.readouterr().out
