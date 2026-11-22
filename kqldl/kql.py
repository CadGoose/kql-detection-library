"""Lightweight, string-aware static checks for KQL text.

This is not a KQL parser. It catches the mistakes that most often slip into a
detection repo: unbalanced brackets, unterminated strings, and unbounded queries
with no time filter.
"""

from __future__ import annotations

import re

_PAIRS = {")": "(", "]": "[", "}": "{"}
_TIME_FILTER = re.compile(r"\bago\s*\(|\bbetween\s*\(|\bstartofday\s*\(|\bdatetime\s*\(")


def strip_strings_and_comments(query: str) -> tuple[str, list[str]]:
    """Return (code with string/comment bodies blanked, list of problems)."""
    out: list[str] = []
    problems: list[str] = []
    i, n = 0, len(query)
    while i < n:
        ch = query[i]
        # // line comment
        if ch == "/" and i + 1 < n and query[i + 1] == "/":
            j = query.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        # verbatim string @"..." or @'...' ("" / '' escapes a quote)
        if ch == "@" and i + 1 < n and query[i + 1] in "\"'":
            quote = query[i + 1]
            j = i + 2
            while True:
                k = query.find(quote, j)
                if k == -1:
                    problems.append(f"unterminated verbatim string starting at offset {i}")
                    j = n
                    break
                if k + 1 < n and query[k + 1] == quote:
                    j = k + 2
                    continue
                j = k + 1
                break
            out.append(" " * (j - i))
            i = j
            continue
        # regular string "..." or '...' with backslash escapes
        if ch in "\"'":
            quote = ch
            j = i + 1
            closed = False
            while j < n:
                if query[j] == "\\":
                    j += 2
                    continue
                if query[j] == quote:
                    closed = True
                    j += 1
                    break
                if query[j] == "\n":
                    break
                j += 1
            if not closed:
                problems.append(f"unterminated string starting at offset {i}")
            out.append(" " * (j - i))
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out), problems


def lint_query(query: str) -> list[str]:
    """Return a list of human-readable problems (empty list = clean)."""
    problems: list[str] = []
    if not query or not query.strip():
        return ["query is empty"]
    code, string_problems = strip_strings_and_comments(query)
    problems.extend(string_problems)

    stack: list[tuple[str, int]] = []
    for idx, ch in enumerate(code):
        if ch in "([{":
            stack.append((ch, idx))
        elif ch in ")]}":
            if not stack or stack[-1][0] != _PAIRS[ch]:
                problems.append(f"unbalanced '{ch}' at offset {idx}")
                break
            stack.pop()
    else:
        for opener, idx in stack:
            problems.append(f"unclosed '{opener}' at offset {idx}")

    if not _TIME_FILTER.search(code):
        problems.append("no time filter found (expected ago(), between() or datetime())")
    if "| " not in code and "|\n" not in code:
        problems.append("query has no pipe operators")
    return problems
