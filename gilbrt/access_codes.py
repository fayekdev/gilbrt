"""Static JavaScript literal comparisons and access-code assignments.

JavaScript is parsed as syntax; comments, regex literals and quoted example code
are distinguished from actual comparisons. No code or credential is executed.
"""

import re
from dataclasses import dataclass

LEXER = re.compile(
    r'''(?P<comment>//[^\r\n]*|/\*[\s\S]*?\*/)|(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(?P<number>\b\d+(?:\.\d+)?\b)|(?P<identifier>[A-Za-z_$][\w$]*)|(?P<operator>===|!==|==|!=|=>|&&|\|\|)|(?P<symbol>[^\s])'''
)
PASSWORD_NAME = re.compile(r"password|passwd|(?:^|[_-])(?:pwd|pass)(?:$|[_-])", re.I)
CODE_NAME = re.compile(r"passcode|(?:access|invite|unlock|security|verification|auth)[_-]?code|secret|(?:^|[_-])(?:code|pin|otp)(?:$|[_-])", re.I)


@dataclass(frozen=True, slots=True)
class Token:
    """One lexical token with its original source offset."""

    value: str
    kind: str
    offset: int


@dataclass(frozen=True)
class Candidate:
    """In-memory literal candidate; raw values never go into report findings."""

    value: str
    offset: int
    operator: str
    password: bool
    confident_name: bool


def literal(tokens: list[Token]) -> str | None:
    """Extract a single string/numeric literal without evaluating expressions."""
    while len(tokens) >= 3 and tokens[0].value == "(" and tokens[-1].value == ")":
        tokens = tokens[1:-1]
    if len(tokens) != 1:
        return None
    token = tokens[0]
    if token.kind == "number":
        return token.value if token.value.isdigit() and 1 <= len(token.value) <= 64 else None
    if token.kind != "string" or "${" in token.value:
        return None
    value = token.value[1:-1]
    if not 1 <= len(value) <= 512:
        return None
    # Decode simple JavaScript escapes; this does not execute JavaScript or eval.
    def unescape(match: re.Match[str]) -> str:
        part = match.group(1)
        if part.startswith(("x", "u")) and len(part) > 1:
            return chr(int(part[1:], 16))
        return {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}.get(part, part)
    return re.sub(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[^\r\n])", unescape, value)


def operand(tokens: list[Token], operator_index: int, step: int) -> list[Token]:
    """Read at most 48 adjacent tokens, including property lookups and method calls."""
    result = []
    depth = 0
    index = operator_index + step
    opening, closing = (("(", "["), (")", "]")) if step > 0 else ((")", "]"), ("(", "["))
    for _ in range(48):
        if not 0 <= index < len(tokens):
            break
        token = tokens[index]
        if depth == 0 and token.value in {";", "{", "}", ",", "=", ":", "?", "&&", "||", "===", "!==", "==", "!=", "return", "if"}:
            break
        if token.value in opening:
            depth += 1
        elif token.value in closing:
            if depth == 0:
                break
            depth -= 1
        result.append(token)
        index += step
    return result if step > 0 else result[::-1]


def _detect_lexical(text: str) -> list[Candidate]:
    """Find named code literals and low-confidence literal checks inside if conditions."""
    tokens = [Token(m.group(), m.lastgroup or "symbol", m.start())
              for m in LEXER.finditer(text) if m.lastgroup != "comment"]
    candidates = []
    conditions: list[bool] = []
    for index, token in enumerate(tokens):
        if token.value == "(":
            conditions.append(index > 0 and tokens[index - 1].value == "if")
        elif token.value == ")" and conditions:
            conditions.pop()
        if token.value not in {"===", "!==", "==", "!=", "=", ":"}:
            continue
        before, after = operand(tokens, index, -1), operand(tokens, index, 1)
        left, right = literal(before), literal(after)
        if (left is None) == (right is None):
            # JSON property keys are string literals, so handle them separately below.
            if token.value != ":" or left is None or right is None:
                continue
        value = right if right is not None else left
        other = before if right is not None else after
        if not other or value is None:
            continue
        if any(t.value in {"length", "size", "status", "statusCode", "keyCode", "charCode"}
               and position > 0 and other[position - 1].value == "." for position, t in enumerate(other)):
            continue  # Length/status checks do not expose the value being authenticated.
        names = [re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", t.value.strip("\"'`"))
                 for t in other if t.kind in {"identifier", "string"}]
        password = any(PASSWORD_NAME.search(name) for name in names)
        named = password or any(CODE_NAME.search(name) for name in names)
        comparison = token.value in {"===", "!==", "==", "!="}
        # Generic minified if checks are review candidates, not proven access controls.
        plausible = len(value) >= 4 and value.lower() not in {"true", "false", "null", "undefined"}
        if not named and not (comparison and any(conditions) and plausible):
            continue
        if not comparison and (password or not named):
            continue  # Password assignments already have their own scanner.
        if any(t.kind == "identifier" for t in other) or token.value == ":":
            candidates.append(Candidate(value, token.offset, token.value, password, named))
    return candidates


def detect(text: str) -> list[Candidate]:
    """Use JavaScript syntax to detect literal checks, including minified branches."""
    from .js_parser import candidates
    return [candidate for candidate, _, _ in candidates(text)]
