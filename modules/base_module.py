"""
BaseModule: abstract base class that defines the common interface
for all Shadow AI detection modules.

Every new module must:
  1. Inherit from BaseModule
  2. Implement the run() method returning list[Finding]
  3. Register itself in core/scanner.py (the only file that knows all modules)
"""

from abc import ABC, abstractmethod
from core.finding import Finding


class BaseModule(ABC):
    """
    Abstract base class for all detection modules.

    Defines the single interface that the orchestrator (scanner.py)
    uses to run any module without knowing its internal details.
    """

    def __init__(self, signatures: dict) -> None:
        """
        Args:
            signatures: Dictionary loaded from config/signatures.json.
                        Each module extracts the section it needs.
        """
        self.signatures = signatures

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this module. Used in findings and reports."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what this module detects."""
        ...

    @abstractmethod
    def run(self) -> list[Finding]:
        """
        Execute the detection logic and return all findings.

        Returns:
            List of Finding objects. Empty list if nothing was found.
            Must never raise unhandled exceptions.
        """
        ...

    def __str__(self) -> str:
        return f"Module({self.name})"
