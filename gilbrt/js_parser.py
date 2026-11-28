"""Bounded JavaScript syntax inspection without evaluating website code."""

import base64
import binascii
import heapq
import re
from collections.abc import Iterator

from tree_sitter import Language, Parser
import tree_sitter_javascript

from .access_codes import Candidate, CODE_NAME, PASSWORD_NAME, Token, credential_literal, literal

LANGUAGE = Language(tree_sitter_javascript.language())
BORING = {"true", "false", "null", "undefined", "string", "number", "boolean", "function", "object", "symbol", "loading", "success", "error"}
COLLECTION_CALLBACKS = {"filter", "map", "find", "findIndex", "some", "every", "sort", "reduce", "forEach", "then", "catch"}
REVIEW_STATES = {"done", "prog", "pending", "complete", "completed", "present", "absent", "active", "inactive", "expanded", "collapsed", "ready", "checked", "unchecked"}


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


def _constant_binding(node, data: bytes):
    """Resolve an earlier const through lexical scopes, respecting shadowing.

    Arrays are accepted only when every reference is a join call. Any mutation,
    escape, alias, indexing or unknown use makes an array binding ineligible.
    """
    name = data[node.start_byte:node.end_byte]
    binding = None
    scope = node.parent
    budget = 4096
    while scope is not None:
        if scope.type in {"for_statement", "for_in_statement", "catch_clause", "class_body"}:
            return None  # These introduce bindings requiring a different analysis.
        if scope.type in {"function_declaration", "function_expression", "arrow_function", "method_definition"}:
            params = scope.child_by_field_name("parameters") or scope.child_by_field_name("parameter")
            if params is not None and re.search(rb"(?<![\w$])" + re.escape(name) + rb"(?![\w$])", data[params.start_byte:params.end_byte]):
                return None
            label = scope.child_by_field_name("name")
            if label is not None and data[label.start_byte:label.end_byte] == name:
                return None
            body = scope.child_by_field_name("body")
            pending = [body] if body is not None else []
            visited = 0
            while pending:
                child = pending.pop()
                visited += 1
                if visited > 8192:
                    return None
                if child.type == "variable_declaration":
                    for item in child.named_children:
                        key = item.child_by_field_name("name")
                        if key is not None and re.search(rb"(?<![\w$])" + re.escape(name) + rb"(?![\w$])", data[key.start_byte:key.end_byte]):
                            return None  # var is function-scoped, including inside branches.
                if child.type == "call_expression":
                    target = child.child_by_field_name("function")
                    if target is not None and data[target.start_byte:target.end_byte] == b"eval":
                        return None
                if child.type not in {"string", "comment", "regex", "function_declaration", "function_expression", "arrow_function"}:
                    pending.extend(child.named_children)
        if scope.type in {"statement_block", "program"}:
            if scope.end_byte - scope.start_byte > 128_000:
                return None
            for declaration in scope.named_children:
                budget -= 1
                if budget < 0:
                    return None
                if declaration.type == "export_statement":
                    declaration = declaration.child_by_field_name("declaration") or declaration
                if declaration.type not in {"lexical_declaration", "variable_declaration"}:
                    # Imports, function/class declarations can shadow outer names.
                    label = declaration.child_by_field_name("name")
                    if label is not None and data[label.start_byte:label.end_byte] == name:
                        return None
                    if declaration.type == "import_statement" and re.search(rb"(?<![\w$])" + re.escape(name) + rb"(?![\w$])", data[declaration.start_byte:declaration.end_byte]):
                        return None
                    continue
                for item in declaration.named_children:
                    key = item.child_by_field_name("name")
                    if key is None:
                        continue
                    if key.type != "identifier":
                        if re.search(rb"(?<![\w$])" + re.escape(name) + rb"(?![\w$])", data[key.start_byte:key.end_byte]):
                            return None
                        continue
                    if data[key.start_byte:key.end_byte] == name:
                        if (binding is not None or item.end_byte >= node.start_byte or
                                not re.match(rb"const\b", data[declaration.start_byte:declaration.start_byte + 6])):
                            return None
                        binding = item.child_by_field_name("value")
            if binding is not None:
                break
        scope = scope.parent
    if binding is None:
        return None
    if binding.type == "array":
        stack = [scope]
        visited = 0
        while stack:
            child = stack.pop()
            visited += 1
            if visited > 8192:
                return None
            if child.type == "identifier" and data[child.start_byte:child.end_byte] == name:
                parent = child.parent
                if parent.type == "variable_declarator" and parent.child_by_field_name("name") == child:
                    pass
                elif parent.type == "member_expression" and parent.child_by_field_name("object") == child:
                    prop = parent.child_by_field_name("property")
                    call = parent.parent
                    if (prop is None or data[prop.start_byte:prop.end_byte] != b"join" or call.type != "call_expression"
                            or call.child_by_field_name("function") != parent):
                        return None
                else:
                    return None
            if child.type not in {"string", "comment", "regex"}:
                stack.extend(child.named_children)
    return binding


def _builtin_unshadowed(node, data: bytes, name: str) -> bool:
    """Reject explicit shadows/replacements of the built-in within bounded source.

    Unknown uses are conservatively rejected. Runtime monkeypatching outside the
    fetched source cannot be determined by static inspection.
    """
    root = node
    while root.parent is not None:
        root = root.parent
    if root.end_byte - root.start_byte > 128_000:
        return False
    stack = [root]
    visited = 0
    while stack:
        child = stack.pop()
        visited += 1
        if visited > 8192:
            return False
        if child.type in {"identifier", "property_identifier"} and data[child.start_byte:child.end_byte].decode() == name:
            parent = child.parent
            if name == "atob":
                if parent.type != "call_expression" or parent.child_by_field_name("function") != child:
                    return False
            else:
                prop = parent.child_by_field_name("property") if parent.type == "member_expression" else None
                call = parent.parent
                if (parent.type != "member_expression" or parent.child_by_field_name("object") != child
                        or prop is None or data[prop.start_byte:prop.end_byte] != b"fromCharCode"
                        or call is None or call.type != "call_expression" or call.child_by_field_name("function") != parent):
                    return False
        if child.type not in {"string", "comment", "regex"}:
            stack.extend(child.named_children)
    return True


def node_literal(node, data: bytes) -> str | None:
    """Fold a bounded allowlist of constant syntax, without executing JavaScript.

    Supports string concatenation, literal atob, String.fromCharCode and literal
    array join, including eligible earlier const bindings in the same block.
    Unknown calls, mutable variables, dynamic templates and oversized input fail
    closed. This is candidate discovery, not a full JavaScript interpreter.
    """
    budget = [128]

    def mutable_scalar(part, depth):
        """Track only straight-line local scalar writes preceding this use.

        Calls, control flow, unknown expressions, redeclarations and escapes
        stop resolution. Mutable values are never propagated across a closure.
        """
        scope = part.parent
        while scope is not None and scope.type not in {"statement_block", "program"}:
            if scope.type in {"function_declaration", "function_expression", "arrow_function", "for_statement", "for_in_statement", "catch_clause"}:
                return None
            scope = scope.parent
        if scope is None or scope.end_byte - scope.start_byte > 128000:
            return None
        name = data[part.start_byte:part.end_byte]
        value = None
        for statement in scope.named_children:
            budget[0] -= 1
            if budget[0] < 0:
                return None
            if statement.end_byte >= part.start_byte:
                break
            if statement.type in {"comment", "empty_statement"}:
                continue
            if statement.type in {"lexical_declaration", "variable_declaration"}:
                for item in statement.named_children:
                    key = item.child_by_field_name("name")
                    expression = item.child_by_field_name("value")
                    if key is not None and key.type == "identifier" and data[key.start_byte:key.end_byte] == name:
                        if value is not None:
                            return None
                        value = fold(expression, depth + 1)
                        if not isinstance(value, (str, int)):
                            return None
                    elif value is not None and not isinstance(fold(expression, depth + 1), (str, int)):
                        return None
                continue
            expression = statement.named_children[0] if statement.type == "expression_statement" and statement.named_child_count == 1 else None
            if value is None:
                continue
            if expression is None or expression.type not in {"assignment_expression", "augmented_assignment_expression"}:
                return None
            left = expression.child_by_field_name("left")
            if left is None or left.type != "identifier" or data[left.start_byte:left.end_byte] != name:
                return None
            right = fold(expression.child_by_field_name("right"), depth + 1)
            if not isinstance(right, (str, int)):
                return None
            operator = expression.child_by_field_name("operator")
            op = data[operator.start_byte:operator.end_byte] if operator is not None else b"="
            if op == b"=":
                value = right
            elif op == b"+=" and (isinstance(value, str) or isinstance(right, str)):
                value = str(value) + str(right)
            else:
                return None
            if len(str(value)) > 512:
                return None
        return value

    def fold(part, depth=0):
        budget[0] -= 1
        if part is None or depth > 10 or budget[0] < 0 or part.end_byte - part.start_byte > 4096:
            return None
        raw = data[part.start_byte:part.end_byte].decode("utf-8", errors="replace")
        if part.type == "parenthesized_expression" and part.named_child_count == 1:
            return fold(part.named_children[0], depth + 1)
        if part.type in {"string", "number", "template_string"}:
            if part.type == "template_string" and any(c.type == "template_substitution" for c in part.named_children):
                return None
            value = "" if raw in {'""', "''", "``"} else literal([Token(raw, "number" if part.type == "number" else "string", part.start_byte)])
            if part.type == "number" and (not re.fullmatch(r"0|[1-9][0-9]{0,15}", raw) or int(raw) > 2**53 - 1):
                return None  # Avoid legacy octal and JavaScript precision differences.
            return int(value) if value is not None and part.type == "number" else value
        if part.type == "identifier":
            binding = _constant_binding(part, data)
            return fold(binding, depth + 1) if binding is not None else mutable_scalar(part, depth + 1)
        if part.type == "binary_expression":
            op = part.child_by_field_name("operator")
            if op is None or data[op.start_byte:op.end_byte] != b"+":
                return None
            left, right = (fold(part.child_by_field_name(side), depth + 1) for side in ("left", "right"))
            if isinstance(left, (str, int)) and isinstance(right, (str, int)) and (isinstance(left, str) or isinstance(right, str)):
                result = str(left) + str(right)
                return result if len(result) <= 512 else None
        if part.type == "array" and part.named_child_count <= 64:
            # Disallow holes and spreads; JavaScript's join rules otherwise differ.
            items = [c for c in part.children if c.type != "comment"]
            if any(a.type == "," and b.type in {",", "]"} for a, b in zip(items, items[1:])) or (len(items) > 1 and items[1].type == ","):
                return None
            values = [fold(c, depth + 1) for c in part.named_children]
            return values if all(isinstance(v, (str, int)) for v in values) else None
        if part.type == "call_expression":
            function = part.child_by_field_name("function")
            args = part.child_by_field_name("arguments")
            if function is None or args is None or args.named_child_count > 64:
                return None
            name = data[function.start_byte:function.end_byte].decode()
            values = [fold(c, depth + 1) for c in args.named_children]
            if name == "atob" and len(values) == 1 and isinstance(values[0], str):
                if not _builtin_unshadowed(part, data, "atob"):
                    return None
                try:
                    encoded = re.sub(r"[\t\n\f\r ]", "", values[0])
                    if len(encoded) % 4 == 1:
                        return None
                    return base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True).decode("latin-1")
                except (ValueError, binascii.Error):
                    return None
            if name == "String.fromCharCode" and values and all(isinstance(v, int) and 0 <= v <= 65535 for v in values):
                if not _builtin_unshadowed(part, data, "String"):
                    return None
                return "".join(chr(v) for v in values)
            if function.type == "member_expression":
                prop = function.child_by_field_name("property")
                if prop is not None and data[prop.start_byte:prop.end_byte] == b"join" and len(values) <= 1:
                    sequence = fold(function.child_by_field_name("object"), depth + 1)
                    separator = values[0] if values else ","
                    if isinstance(sequence, list) and isinstance(separator, str):
                        result = separator.join(str(v) for v in sequence)
                        return result if len(result) <= 512 else None
        return None

    result = fold(node)
    return str(result) if isinstance(result, (str, int)) and 1 <= len(str(result)) <= 512 else None


def relevant_nodes(tree) -> Iterator:
    """Walk the native tree with a cursor rather than materializing all its nodes."""
    cursor = tree.walk()
    while True:
        node = cursor.node
        if node.type in {"binary_expression", "variable_declarator", "assignment_expression", "pair", "switch_case"}:
            yield node
        if node.type not in {"string", "regex", "comment"} and cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def callback_input_kind(node, other, data: bytes) -> str | None:
    """Connect a compared callback parameter to an explicit password/code input.

    Custom dialog names and minified parameter names are allowed. The evidence
    comes from the callback's own call arguments, never nearby comments or labels
    from unrelated functions. No callback or target code is executed.
    """
    parent = node.parent
    for _ in range(12):
        if parent is None:
            return None
        if parent.type in {"arrow_function", "function_expression", "function_declaration"}:
            args = parent.parent
            if args is None or args.type != "arguments" or args.parent.type != "call_expression":
                return None
            function = args.parent.child_by_field_name("function")
            if function is not None and function.type == "member_expression":
                prop = function.child_by_field_name("property")
                if prop is not None and data[prop.start_byte:prop.end_byte].decode() in COLLECTION_CALLBACKS:
                    return None
            params = parent.child_by_field_name("parameters") or parent.child_by_field_name("parameter")
            parameters = params.named_children if params is not None and params.type == "formal_parameters" else [params] if params is not None else []
            names = {data[p.start_byte:p.end_byte].decode() for p in parameters if p.type == "identifier"}
            if not names.intersection(subject_names(other, data)):
                return None
            values = [node_literal(arg, data) for arg in args.named_children if arg != parent]
            if any(value is not None and value.lower() == "password" for value in values):
                return "password"
            if any(value is not None and re.fullmatch(r"admin code|access code|passcode|pin", value, re.I) for value in values):
                return "access-code"
            return None
        parent = parent.parent
    return None


def review_control(node, data: bytes, other=None) -> bool:
    """Broader AI-only pool: literal checks in returning/security-related code.

    This is syntax grounding, not a verdict that a literal is a credential. The
    model must distinguish credential validators from ordinary UI predicates.
    """
    enclosing = node.parent
    for _ in range(16):
        if enclosing is None:
            break
        if enclosing.type == "template_substitution":
            return False  # Rendering a style/status is not an access decision.
        if enclosing.type in {"function_declaration", "function_expression", "arrow_function"}:
            args = enclosing.parent
            if args is not None and args.type == "arguments" and args.parent.type == "call_expression":
                function = args.parent.child_by_field_name("function")
                prop = function.child_by_field_name("property") if function is not None and function.type == "member_expression" else None
                if prop is not None and data[prop.start_byte:prop.end_byte].decode() in COLLECTION_CALLBACKS:
                    return False
                # A returning callback is not evidence about its input when the
                # compared value is an unrelated closure/global variable.
                params = enclosing.child_by_field_name("parameters") or enclosing.child_by_field_name("parameter")
                parameters = params.named_children if params is not None and params.type == "formal_parameters" else [params] if params is not None else []
                names = {data[p.start_byte:p.end_byte].decode() for p in parameters if p.type == "identifier"}
                if other is None or not names.intersection(subject_names(other, data)):
                    return False
            name = enclosing.child_by_field_name("name")
            if name is None and enclosing.parent is not None and enclosing.parent.type == "variable_declarator":
                name = enclosing.parent.child_by_field_name("name")
            label = data[name.start_byte:name.end_byte].decode() if name is not None else ""
            label = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", label)
            if re.search(r"(?:^|_)(?:theme|color|locale|currency|format|layout|mime|route|path)(?:_|$)", label, re.I):
                return False
            break
        enclosing = enclosing.parent
    parent = node.parent
    for _ in range(8):
        if parent is None or parent.type == "program":
            break
        if parent.type == "return_statement":
            return True
        if parent.type == "arrow_function" and parent.child_by_field_name("body") is not None:
            body = parent.child_by_field_name("body")
            return body.type != "statement_block" and body.start_byte <= node.start_byte < body.end_byte
        if parent.type in {"if_statement", "ternary_expression"}:
            stack = [parent]
            visited = 0
            while stack and visited < 128:
                child = stack.pop()
                visited += 1
                if child.type == "return_statement" and any(c.type in {"true", "false"} for c in child.named_children):
                    return True
                if child.type == "call_expression":
                    target = child.child_by_field_name("function")
                    if target is not None and target.type == "member_expression":
                        target = target.child_by_field_name("property")
                    if target is not None and target.type in {"identifier", "property_identifier"}:
                        name = data[target.start_byte:target.end_byte].decode()
                        if re.search(r"protected|authenticat|authoriz|login|access|invit", name, re.I):
                            return True
                if child.type not in {"string", "template_string", "regex", "comment", "function_declaration", "function_expression", "arrow_function"}:
                    stack.extend(child.named_children)
        if parent.type in {"function_declaration", "function_expression", "arrow_function"}:
            break
        parent = parent.parent
    return False


def secret_literals(text: str) -> Iterator[tuple[str, int]]:
    """Yield bounded literal/constant values at credential-like assignment sites."""
    data = text.encode("utf-8", errors="replace")
    tree = Parser(LANGUAGE).parse(data)
    for node in relevant_nodes(tree):
        if node.type not in {"variable_declarator", "assignment_expression", "pair"}:
            continue
        subject = node.child_by_field_name("key" if node.type == "pair" else "name" if node.type == "variable_declarator" else "left")
        if subject is None or subject.end_byte - subject.start_byte > 256:
            continue
        names = [re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name) for name in subject_names(subject, data)]
        if not any(PASSWORD_NAME.search(name) or CODE_NAME.search(name) or re.search(r"(?:^|[_-])(?:api[_-]?key|key|token|secret|authorization)(?:$|[_-])", name, re.I) for name in names):
            continue
        value_node = node.child_by_field_name("value" if node.type in {"pair", "variable_declarator"} else "right")
        value = node_literal(value_node, data)
        if value is not None:
            yield value, len(data[:node.start_byte].decode("utf-8", errors="replace"))


def candidates(text: str, limit: int = 128, include_password_assignments: bool = False,
               review: bool = False) -> list[tuple[Candidate, str, int]]:
    """Return at most limit ranked candidates, source excerpts and scores.

    Strings, regex literals and comments are parsed as JavaScript syntax. This
    prevents quotes inside regexes from hiding subsequent access comparisons.
    """
    data = text.encode("utf-8", errors="replace")
    tree = Parser(LANGUAGE).parse(data)
    best = []
    serial = 0
    for node in relevant_nodes(tree):
        comparison = node.type in {"binary_expression", "switch_case"}
        if node.type == "switch_case":
            operator = "==="
            value = node_literal(node.child_by_field_name("value"), data)
            switch = node.parent.parent if node.parent is not None else None
            other = switch.child_by_field_name("value") if switch is not None else None
        elif comparison:
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
        callback_kind = callback_input_kind(node, other, data) if comparison else None
        password = any(PASSWORD_NAME.search(name) for name in names) or callback_kind == "password"
        named = password or callback_kind == "access-code" or any(CODE_NAME.search(name) for name in names)
        generic_code = any(re.fullmatch(r"(?:entered[_-]?)?code", name, re.I) for name in names)
        # Generic `code` commonly means an HTTP/error/keyboard code. A PIN-shaped
        # value or an access-specific branch is needed before treating it as a gate.
        named = named or (generic_code and comparison and (
            value.isdigit() and 4 <= len(value) <= 12 and "." not in expression and "[" not in expression
            or access_branch(node, data)))
        if comparison and value.lower() in BORING:
            continue
        if not named and (not comparison or len(value) < 4 or not access_branch(node, data)):
            if not (review and comparison and value.lower() not in REVIEW_STATES and 4 <= len(value) <= 512 and not value.startswith(("/", "http:", "https:"))
                    and "/" not in value and review_control(node, data, other)):
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
        basis = "password-input callback comparison" if callback_kind == "password" else "code-input callback comparison" if callback_kind else "named credential or access branch" if named or access_branch(node, data) else "validator review only"
        candidate = Candidate(value, offset, operator, password, named, basis)
        entry = (score, -serial, candidate, context[:700])
        serial += 1
        if len(best) < limit:
            heapq.heappush(best, entry)
        elif entry[:2] > best[0][:2]:
            heapq.heapreplace(best, entry)
    return [(c, context, score) for score, _, c, context in sorted(best, reverse=True)]
