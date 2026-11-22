"""Shared report structures; never retain raw secret values in findings."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    """A redacted, actionable observation, not proof of exploitability."""

    severity: str
    category: str
    title: str
    url: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        """Return a serializable representation."""
        return asdict(self)
