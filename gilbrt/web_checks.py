"""Passive browser and connection-string candidates; never execute target code."""

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from tree_sitter import Parser

from .js_parser import LANGUAGE, _constant_binding, node_literal
from .models import Finding
from .scanner import mask, safe_url
from .access_codes import credential_literal


CONNECTION = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?|mssql|https?)://"
    r"[^\s\"'`<>/:@]{1,128}:([^\s\"'`<>/@]{1,512})@[^\s\"'`<>/;]{1,255}(?:/[^\s\"'`<>;]*)?", re.I)


def connections(text, url, on_secret=None):
    """Find URI userinfo passwords without contacting any database or provider."""
    findings = []
    seen = set()
    for match in CONNECTION.finditer(text):
        value = match.group()
        password = match.group(1)
        if not credential_literal(password) or value in seen:
            continue
        seen.add(value)
        finding = Finding("Critical", "Connection", "Credential-bearing connection URL", safe_url(url),
                          f"Line {text.count(chr(10), 0, match.start()) + 1}; {mask(value)}; URI value withheld",
                          "Remove client-side connection credentials and rotate real exposed passwords. Access databases through an authorized server.")
        findings.append(finding)
        if on_secret:
            on_secret(finding, value)
    return findings


def forms(text, url):
    """Inspect password form destinations and insecure embedded resources."""
    soup = BeautifulSoup(text, "html.parser")
    findings = []

    def add(category, title, line, advice):
        findings.append(Finding("Warning", category, title, safe_url(url),
                                f"Line {line or 1}; static HTML candidate; destination withheld", advice))

    for form in soup.find_all("form"):
        password_fields = form.find_all("input", attrs={"type": re.compile("^password$", re.I)})
        if not any(field.get("name") and not field.has_attr("disabled")
                   and (not field.has_attr("form") or field.get("form") == form.get("id"))
                   and not field.find_parent("fieldset", attrs={"disabled": True}) for field in password_fields):
            continue
        # Include button/input overrides; they can bypass an otherwise secure form.
        targets = [(form.get("action", ""), form.get("method", "get"), form.sourceline)]
        targets += [(button.get("formaction", form.get("action", "")),
                     button.get("formmethod", form.get("method", "get")), button.sourceline)
                    for button in form.find_all(["button", "input"]) if button.has_attr("formaction") or button.has_attr("formmethod")]
        reported = set()
        for action, method, line in targets:
            if str(method).lower() == "dialog":
                continue  # Dialog forms do not submit credentials.
            try:
                destination = urlsplit(urljoin(url, str(action)))
                original = urlsplit(url)
            except ValueError:
                continue
            titles = []
            if str(method).lower() != "post":
                titles.append(("Password form uses GET", "Submit passwords using POST over HTTPS; keep credentials out of URLs and logs."))
            if destination.scheme == "http":
                titles.append(("Password form submits over HTTP", "Serve login forms and their submission endpoint over HTTPS."))
            if destination.scheme in {"http", "https"} and (destination.scheme, destination.netloc) != (original.scheme, original.netloc):
                titles.append(("Password form submits to another origin", "Confirm this credential destination is trusted and intentionally configured."))
            for title, advice in titles:
                if title not in reported:
                    add("Form", title, line, advice)
                    reported.add(title)
    if urlsplit(url).scheme == "https":
        for node in soup.find_all(["script", "iframe", "img", "link", "audio", "video", "source"]):
            attribute = "href" if node.name == "link" else "src"
            if node.name == "link" and not set(node.get("rel", [])) & {"stylesheet", "preload", "modulepreload"}:
                continue
            value = node.get(attribute)
            if value and str(value).strip().lower().startswith("http://"):
                add("Mixed content", "HTTP resource referenced by HTTPS page", node.sourceline,
                    "Use HTTPS for embedded resources. Browser blocking or upgrades vary by resource type.")
    return findings


def browser_code(text, url, line_offset=0):
    """Report direct browser-controlled inputs flowing into unsafe syntax sinks.

    No arbitrary data flow is inferred. Unknown calls (including sanitizers),
    quoted examples and comments do not count as direct input flows.
    """
    data = text.encode("utf-8", errors="replace")
    tree = Parser(LANGUAGE).parse(data)
    findings = []

    def raw(node):
        return data[node.start_byte:node.end_byte].decode("utf-8", errors="replace") if node else ""

    def browser_input(node, depth=0):
        if node is None or depth > 8 or node.end_byte - node.start_byte > 4096:
            return False
        if node.type in {"member_expression", "subscript_expression"}:
            return bool(re.fullmatch(r"(?:(?:window|document)\s*\.\s*)?location(?:\s*\.\s*(?:hash|search|href|pathname))?|document\s*\.\s*(?:URL|documentURI|referrer)|window\s*\.\s*name", raw(node)))
        if node.type == "identifier":
            if raw(node) == "location":
                return True
            binding = _constant_binding(node, data)
            if binding is not None:
                return browser_input(binding, depth + 1)
            # Recognize only same-block const destructuring of known location
            # string properties. Unknown aliases and mutable bindings fail closed.
            scope = node.parent
            while scope is not None and scope.type not in {"program", "statement_block"}:
                scope = scope.parent
            if scope is not None and scope.end_byte - scope.start_byte <= 128000:
                for declaration in scope.named_children:
                    if declaration.end_byte >= node.start_byte or declaration.type != "lexical_declaration" or not re.match(r"const\b", raw(declaration)):
                        continue
                    for item in declaration.named_children:
                        pattern = item.child_by_field_name("name")
                        if pattern is not None and pattern.type == "object_pattern":
                            for property_node in pattern.named_children:
                                if property_node.type == "shorthand_property_identifier_pattern" and raw(property_node) == raw(node) and raw(node) in {"hash", "search", "href", "pathname"}:
                                    return browser_input(item.child_by_field_name("value"), depth + 1)
            return False
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type == "member_expression" and raw(function.child_by_field_name("property")) in {"get", "getAll"}:
                obj = function.child_by_field_name("object")
                if obj is not None and obj.type == "new_expression" and raw(obj.child_by_field_name("constructor")) == "URLSearchParams":
                    args = obj.child_by_field_name("arguments")
                    return args is not None and any(browser_input(child, depth + 1) for child in args.named_children)
            return False
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            return raw(operator) == "+" and any(browser_input(child, depth + 1) for child in node.named_children)
        if node.type in {"parenthesized_expression", "template_string", "template_substitution"}:
            return any(browser_input(child, depth + 1) for child in node.named_children)
        return False

    def add(node, title, advice, severity="Warning"):
        findings.append(Finding(severity, "Browser code", title, safe_url(url),
                                f"Line {node.start_point.row + line_offset + 1}; syntax candidate; source and payload withheld; exploitability unconfirmed", advice))

    cursor = tree.walk()
    while True:
        node = cursor.node
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                if raw(prop) in {"innerHTML", "outerHTML"} and browser_input(right):
                    add(node, "Browser input assigned to HTML sink", "Use textContent for text; sanitize HTML with a reviewed sanitizer and enforce Trusted Types where supported.")
        if node.type in {"call_expression", "new_expression"}:
            function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            arguments = args.named_children if args else []
            name = re.sub(r"\s+", "", raw(function))
            if name in {"eval", "window.eval", "Function", "setTimeout", "setInterval", "window.setTimeout", "window.setInterval"} and arguments:
                # Function takes its executable body as the final argument.
                body = arguments[-1] if name == "Function" else arguments[0]
                if browser_input(body):
                    add(node, "Browser input reaches code execution sink", "Remove string evaluation of browser input; use parsed data and function callbacks.")
            if name in {"document.write", "document.writeln"} and any(browser_input(arg) for arg in arguments):
                add(node, "Browser input reaches document.write", "Build DOM nodes with textContent or use a reviewed HTML sanitizer.")
            if name.endswith(".insertAdjacentHTML") and len(arguments) >= 2 and browser_input(arguments[1]):
                add(node, "Browser input reaches HTML insertion sink", "Use text insertion APIs or sanitize the HTML before insertion.")
            if name.endswith(".postMessage") and len(arguments) >= 2 and node_literal(arguments[1], data) == "*":
                add(node, "Wildcard postMessage destination", "Use an exact trusted target origin when sending sensitive messages.", "Info")
            if name in {"localStorage.setItem", "sessionStorage.setItem", "window.localStorage.setItem", "window.sessionStorage.setItem"} and len(arguments) >= 2:
                key = node_literal(arguments[0], data)
                if key and re.fullmatch(r"(?:auth|access|refresh|session|id)[_-]?token|password|secret|api[_-]?key|jwt", key, re.I):
                    add(node, "Sensitive value stored in browser storage", "Review whether this value is secret; scripts on the origin can read browser storage. Prefer HttpOnly cookies for session credentials where appropriate.", "Info")
        if node.type not in {"string", "regex", "comment"} and cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return findings
