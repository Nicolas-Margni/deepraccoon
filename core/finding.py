"""
Finding: represents a single detection result produced by any module.

All detection modules return lists of Finding instances.
This is the core data structure of DeepRaccoon.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}


@dataclass
class Finding:
    """
    Represents a Shadow AI finding detected on the system.

    Attributes:
        module:         Name of the module that generated this finding.
        severity:       Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO.
        title:          Short descriptive name of the finding.
        description:    Detailed explanation of what was found and why it matters.
        evidence:       The concrete data found (path, PID, package name, etc.).
        recommendation: What the analyst should do to mitigate or investigate.
        timestamp:      When the finding was generated (auto-assigned).
    """

    module:         str
    severity:       str
    title:          str
    description:    str
    evidence:       str
    recommendation: str
    timestamp:      str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self) -> None:
        """Validate that severity is one of the allowed values."""
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: '{self.severity}'. "
                f"Allowed values: {VALID_SEVERITIES}"
            )

    def severity_order(self) -> int:
        """Return an integer for sorting findings by severity (lower = more critical)."""
        return SEVERITY_ORDER.get(self.severity, 99)

    def to_dict(self) -> dict:
        """Serialize the Finding to a dictionary for JSON or TXT export."""
        return {
            "module":         self.module,
            "severity":       self.severity,
            "title":          self.title,
            "description":    self.description,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "timestamp":      self.timestamp,
        }

    def __str__(self) -> str:
        """Readable representation for quick debugging."""
        return f"[{self.severity}] {self.title} (module: {self.module})"
