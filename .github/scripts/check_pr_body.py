"""Check that a PR description follows .github/pull_request_template.md.

Every required section must be present with real content. HTML comments
(the template's instructions) do not count as content, so an untouched
template fails.
"""

from __future__ import annotations

import os
import re
import sys

REQUIRED_SECTIONS = (
    "Planned stage",
    "Summary",
    "Requirements addressed",
    "Tests executed",
)

_HEADING = re.compile(r"^#{2,3}[ \t]+(.+?)[ \t]*#*[ \t]*$", re.MULTILINE)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def parse_sections(body: str) -> dict[str, str]:
    """Map each heading (case-insensitive) to its text with comments removed."""
    body = _COMMENT.sub("", body.replace("\r\n", "\n"))
    matches = list(_HEADING.finditer(body))
    sections: dict[str, str] = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections[match.group(1).strip().lower()] = body[match.end() : end].strip()
    return sections


def _find_section(sections: dict[str, str], name: str) -> str | None:
    """Find a section by name; a trailing qualifier like '(local)' is allowed."""
    key = name.lower()
    for heading, content in sections.items():
        if heading == key or (heading.startswith(key) and not heading[len(key)].isalnum()):
            return content
    return None


def check(body: str | None) -> list[str]:
    """Return a list of problems; empty means the description is valid."""
    if not body or not body.strip():
        return ["The PR description is empty. Fill in .github/pull_request_template.md."]
    sections = parse_sections(body)
    problems = []
    for name in REQUIRED_SECTIONS:
        content = _find_section(sections, name)
        if content is None:
            problems.append(f"Missing section: '## {name}'.")
        elif not content:
            problems.append(f"Section '## {name}' is empty; replace the template comment.")
    return problems


def main() -> int:
    problems = check(os.environ.get("PR_BODY"))
    for problem in problems:
        print(f"::error title=PR description::{problem}")
    if problems:
        print(f"PR description check failed ({len(problems)} problem(s)).", file=sys.stderr)
        return 1
    print("PR description matches the template.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
