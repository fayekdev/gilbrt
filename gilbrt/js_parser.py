"""Bounded JavaScript syntax inspection without evaluating website code."""

import heapq
import re
from collections.abc import Iterator

from tree_sitter import Language, Parser
import tree_sitter_javascript

from .access_codes import Candidate, CODE_NAME, PASSWORD_NAME, Token, credential_literal, literal

LANGUAGE = Language(tree_sitter_javascript.language())
BORING = {"true", "false", "null", "undefined", "string", "number", "boolean", "function", "object", "symbol", "loading", "success", "error"}


def subject_names(node, data: bytes) -> list[str]:
    """Read the compared property, without treating its object name as a credential."""
    while node.type == "parenthesized_expression" and node.named_child_count == 1:
        node = node.named_children[0]
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        name = data[prop.start_byte:prop.end_byte].decode() if prop else ""
        if name != "value":
            return [name]
        obj = node.child_by_field_name("object")
        return subject_names(obj, data) if obj else []
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        expression = data[function.start_byte:function.end_byte].decode() if function else ""
        if expression.endswith(("getElementById", "querySelector")) and args:
            return [data[c.start_byte:c.end_byte].decode().strip("\"'#.") for c in args.named_children]
        if function and function.type == "member_expression":
            obj = function.child_by_field_name("object")
            return subject_names(obj, data) if obj else []
        return []
    if node.type == "subscript_expression":
        index = node.child_by_field_name("index")
        return [node_literal(index, data) or ""]
    return [data[node.start_byte:node.end_byte].decode().strip("\"'`")]


def access_branch(node, data: bytes) -> bool:
    """Require access-specific actions in the enclosing branch for ambiguous names."""
    parent = node.parent
    for _ in range(5):
        if parent is None or parent.type in {"program", "statement_block"}:
            break
        if parent.type in {"if_statement", "ternary_expression", "binary_expression", "arrow_function"}:
            fields = ("consequence", "alternative") if parent.type in {"if_statement", "ternary_expression"} else ("right",) if parent.type == "binary_expression" else ("body",)
            for field in fields:
                branch = parent.child_by_field_name(field)
                if branch is None or branch.start_byte <= node.start_byte < branch.end_byte:
                    continue
                # Inspect syntax identifiers, never nearby comments or string labels.
                stack = [branch]
                visited = 0
                while stack and visited < 256:
                    child = stack.pop()
                    visited += 1
                    if child.type in {"identifier", "property_identifier"}:
                        name = data[child.start_byte:child.end_byte].decode()
                        target = child.parent if child.type == "property_identifier" else child
                        call = target.parent if target else None
                        invoked = call is not None and call.type == "call_expression" and call.child_by_field_name("function") == target
                        if invoked and re.fullmatch(r"allow|deny|unlock|authenticate|authorize|openGate|grantAccess|denyAccess|showAdmin|setAuthenticated|setAuthorized|login", name, re.I):
                            return True
                    if child.type not in {"string", "template_string", "regex", "comment"}:
                        stack.extend(child.named_children)
        node, parent = parent, parent.parent
    return False


def node_literal(node, data: bytes) -> str | None:
    """Read a small literal node; dynamic template substitutions are excluded."""
    while node is not None and node.type == "parenthesized_expression" and node.named_child_count == 1:
        node = node.named_children[0]
    if node is None or node.type not in {"string", "number", "template_string"} or node.end_byte - node.start_byte > 2048:
        return None
    if node.type == "template_string" and any(c.type == "template_substitution" for c in node.named_children):
        return None
    raw = data[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    return literal([Token(raw, "number" if node.type == "number" else "string", node.start_byte)])


def relevant_nodes(tree) -> Iterator:
    """Walk the native tree with a cursor rather than materializing all its nodes."""
    cursor = tree.walk()
    while True:
        node = cursor.node
        if node.type in {"binary_expression", "variable_declarator", "assignment_expression", "pair"}:
            yield node
        if node.type not in {"string", "regex", "comment"} and cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def candidates(text: str, limit: int = 128, include_password_assignments: bool = False) -> list[tuple[Candidate, str, int]]:
    """Return at most limit ranked candidates, source excerpts and scores.

    Strings, regex literals and comments are parsed as JavaScript syntax. This
    prevents quotes inside regexes from hiding subsequent access comparisons.
    """
    data = text.encode("utf-8", errors="replace")
    tree = Parser(LANGUAGE).parse(data)
    best = []
    serial = 0
    for node in relevant_nodes(tree):
        comparison = node.type == "binary_expression"
        if comparison:
            operator_node = node.child_by_field_name("operator")
            if operator_node is None:
                continue
            operator = data[operator_node.start_byte:operator_node.end_byte].decode()
            if operator not in {"===", "==", "!==", "!="}:
                continue
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            left_value, right_value = node_literal(left, data), node_literal(right, data)
            if (left_value is None) == (right_value is None):
                continue
            value, other = (right_value, left) if right_value is not None else (left_value, right)
        else:
            operator = ":" if node.type == "pair" else "="
            other = node.child_by_field_name("key" if node.type == "pair" else "name" if node.type == "variable_declarator" else "left")
            value_node = node.child_by_field_name("value" if node.type in {"pair", "variable_declarator"} else "right")
            value = node_literal(value_node, data)
        if value is None or not credential_literal(value) or other is None or other.end_byte - other.start_byte > 2000:
            continue
        expression = data[other.start_byte:other.end_byte].decode("utf-8", errors="replace")
        if re.search(r"\.\s*(?:length|size|status|statusCode|keyCode|charCode)\b", expression):
            continue
        names = [re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name) for name in subject_names(other, data)]
        password = any(PASSWORD_NAME.search(name) for name in names)
        named = password or any(CODE_NAME.search(name) for name in names)
        generic_code = any(re.fullmatch(r"(?:entered[_-]?)?code", name, re.I) for name in names)
        # Generic `code` commonly means an HTTP/error/keyboard code. A PIN-shaped
        # value or an access-specific branch is needed before treating it as a gate.
        named = named or (generic_code and comparison and (
            value.isdigit() and 4 <= len(value) <= 12 and "." not in expression and "[" not in expression
            or access_branch(node, data)))
        if comparison and value.lower() in BORING:
            continue
        if not named and (not comparison or len(value) < 4 or not access_branch(node, data)):
            continue
        if not comparison and password and not include_password_assignments:
            continue  # The dedicated password-assignment check handles these.
        # Keep a short excerpt; never copy enormous embedded binary strings.
        context_start, context_end = max(0, node.start_byte - 100), min(len(data), node.end_byte + 100)
        context = data[context_start:context_end].decode("utf-8", errors="replace")
        score = (80 if named else 0) + (80 if password else 0) + (60 if comparison else 0)
        score += 30 * len(set(re.findall(r"password|passwd|admin|passcode|unlock|login|access.?code", context, re.I)))
        score += 25 if value.isdigit() and 4 <= len(value) <= 12 else 0
        offset = len(data[:node.start_byte].decode("utf-8", errors="replace"))
        candidate = Candidate(value, offset, operator, password, named)
        entry = (score, -serial, candidate, context[:700])
        serial += 1
        if len(best) < limit:
            heapq.heappush(best, entry)
        elif entry[:2] > best[0][:2]:
            heapq.heapreplace(best, entry)
    return [(c, context, score) for score, _, c, context in sorted(best, reverse=True)]
