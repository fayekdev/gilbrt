"""Opt-in, atomic persistence of redacted CLI reports for the local GUI."""

import json
import os
import tempfile
from pathlib import Path

from .models import Finding
from .reporter import SEVERITIES, report_document

MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 50000
REPORT_NAME = "last-cli-report.json"


def read_report(path):
    """Validate an ordinary gilbrt JSON export; never interpret report contents."""
    try:
        with Path(path).open("rb") as stream:
            payload = stream.read(MAX_REPORT_BYTES + 1)
        if len(payload) > MAX_REPORT_BYTES:
            raise ValueError()
        def invalid_constant(_value):
            raise ValueError()
        document = json.loads(payload.decode("utf-8-sig"), parse_constant=invalid_constant)
        if not isinstance(document, dict) or document.get("tool") != "gilbrt" or not isinstance(document.get("metadata"), dict):
            raise ValueError()
        entries = document.get("findings")
        if not isinstance(entries, list) or len(entries) > MAX_FINDINGS:
            raise ValueError()
        fields = set(Finding.__dataclass_fields__)
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != fields or
                    any(not isinstance(value, str) for value in entry.values()) or entry["severity"] not in SEVERITIES):
                raise ValueError()
        count = document["metadata"].get("resources_scanned")
        if count is not None and (type(count) is not int or count < 0):
            raise ValueError()
        metadata = document["metadata"]
        if "resource_inventory" in metadata:
            inventory = metadata["resource_inventory"]
            if not isinstance(inventory, list) or any(
                    not isinstance(item, dict) or not isinstance(item.get("resource"), str) or
                    not isinstance(item.get("kind"), str) or type(item.get("bytes")) is not int or item["bytes"] < 0
                    for item in inventory):
                raise ValueError()
        if "search_categories" in metadata and (not isinstance(metadata["search_categories"], list) or
                any(not isinstance(category, str) for category in metadata["search_categories"])):
            raise ValueError()
        if "local_ai" in metadata and metadata["local_ai"] is not None and not isinstance(metadata["local_ai"], dict):
            raise ValueError()
        # Rebuild sanitized findings and recompute assessment instead of trusting
        # an imported report's claimed verdict, session, or revealed-evidence map.
        result = report_document([Finding(**entry) for entry in entries], document["metadata"])
        if isinstance(document.get("generated_at"), str):
            result["generated_at"] = document["generated_at"]
        return result
    except (OSError, ValueError, TypeError, RecursionError, KeyError) as error:
        raise ValueError("Unable to load report. Choose a valid gilbrt JSON export up to 32 MiB and 50,000 findings.") from error


def save_report(path, findings, metadata):
    """Save exported findings, never the terminal's separately revealed values."""
    path = Path(path)
    if len(findings) > MAX_FINDINGS:
        raise ValueError("Too many findings to save for the GUI (maximum 50,000).")
    payload = json.dumps(report_document(findings, metadata), ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds the 32 MiB GUI persistence limit.")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".cli-report-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # mkstemp's permissions are private on POSIX; Windows uses directory ACLs.
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return path
