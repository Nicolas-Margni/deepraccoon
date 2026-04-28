"""
ConfigScanner: detects configuration folders and files left by AI tools
on the system, such as Claude Desktop, Cursor IDE, LM Studio, etc.

Paths are defined in signatures.json["config_paths"] and support both
Windows environment variables (%APPDATA%, %LOCALAPPDATA%, %USERPROFILE%)
and Unix-style paths (~/.cursor, ~/Library/...).
"""

import json
import os
import platform
import re
from pathlib import Path

from core.finding import Finding
from modules.base_module import BaseModule


def _expand_windows_vars(path_str: str) -> str:
    """
    Expand Windows environment variables in a path string.

    Handles %APPDATA%, %LOCALAPPDATA%, %USERPROFILE% and any other
    %VAR% style variables present in the environment.

    Args:
        path_str: Raw path string from signatures.json.

    Returns:
        Expanded path string with env vars resolved.
    """
    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return re.sub(r"%([^%]+)%", _replace, path_str)


def _resolve_path(path_str: str) -> Path:
    """
    Resolve a path string from signatures.json to an absolute Path.

    Handles both Windows-style (%APPDATA%\\Claude) and
    Unix-style (~/.cursor) path formats.

    Args:
        path_str: Raw path string from signatures.json.

    Returns:
        Resolved absolute Path object.
    """
    expanded = _expand_windows_vars(path_str)
    return Path(expanded).expanduser()


def _parse_mcp_servers(config_path: Path) -> list[str]:
    """
    Parse MCP server names from a Claude Desktop config file.

    Args:
        config_path: Path to claude_desktop_config.json or similar.

    Returns:
        List of MCP server names found, empty list if none or parse error.
    """
    try:
        content = config_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        mcp_servers = data.get("mcpServers", {})
        return list(mcp_servers.keys())
    except (json.JSONDecodeError, OSError):
        return []


class ConfigScanner(BaseModule):
    """
    Detects AI tool configuration folders and files on the system.

    Checks all paths defined in signatures.json["config_paths"],
    resolving both Windows and Unix environment variables.

    Generates LOW findings for each detected config folder, and
    MEDIUM findings if a Claude Desktop config with MCP servers is found.
    """

    @property
    def name(self) -> str:
        return "config_scanner"

    @property
    def description(self) -> str:
        return "Detects AI tool configuration folders and files on the system"

    def run(self) -> list[Finding]:
        """
        Iterate over all known config paths and check if they exist.

        Returns:
            List of Finding objects, one per detected config path.
        """
        findings: list[Finding] = []
        config_paths = self.signatures.get("config_paths", [])
        current_platform = "windows" if platform.system() == "Windows" else "unix"

        for entry in config_paths:
            entry_platform = entry.get("platform", "unix")

            # Skip paths that don't apply to the current platform
            if entry_platform != current_platform:
                continue

            try:
                resolved = _resolve_path(entry["path"])
            except (KeyError, ValueError):
                continue

            if not resolved.exists():
                continue

            findings.append(Finding(
                module=self.name,
                severity="LOW",
                title=f"AI tool config found: {entry['tool']}",
                description=(
                    f"Configuration folder for {entry['tool']} was found on this system. "
                    f"This indicates the tool has been installed or used by a user."
                ),
                evidence=str(resolved),
                recommendation=(
                    f"Verify whether {entry['tool']} is authorized for use in this environment. "
                    f"If not, uninstall the tool and remove the configuration folder: {resolved}"
                ),
            ))

            # Bonus: if it's a Claude Desktop config, parse MCP servers
            findings.extend(self._check_mcp_config(resolved, entry["tool"]))

        return findings

    def _check_mcp_config(self, config_dir: Path, tool_name: str) -> list[Finding]:
        """
        Look for claude_desktop_config.json inside a config folder
        and report any MCP servers configured.

        Args:
            config_dir: The detected config folder path.
            tool_name:  Display name of the tool.

        Returns:
            List of additional findings for MCP servers, may be empty.
        """
        findings: list[Finding] = []

        candidate_files = [
            config_dir / "claude_desktop_config.json",
            config_dir / "config.json",
        ]

        for config_file in candidate_files:
            if not config_file.exists():
                continue

            mcp_servers = _parse_mcp_servers(config_file)
            if not mcp_servers:
                continue

            findings.append(Finding(
                module=self.name,
                severity="MEDIUM",
                title=f"MCP servers configured in {tool_name}",
                description=(
                    f"Claude Desktop has {len(mcp_servers)} MCP server(s) configured. "
                    f"MCP servers extend Claude's capabilities with external tool access "
                    f"and may represent an additional data exposure risk."
                ),
                evidence=f"{config_file} → servers: {', '.join(mcp_servers)}",
                recommendation=(
                    f"Review each MCP server to ensure it is authorized. "
                    f"Remove any unauthorized servers from {config_file}."
                ),
            ))

        return findings
