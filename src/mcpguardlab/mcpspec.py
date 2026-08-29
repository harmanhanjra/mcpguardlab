"""MCP protocol data types."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Tool:
    """MCP Tool definition."""
    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Resource:
    """MCP Resource definition."""
    uri: str
    name: str
    mime_type: str = "text/plain"


@dataclass
class Prompt:
    """MCP Prompt definition."""
    name: str
    description: str
    arguments: Dict[str, str] = field(default_factory=dict)


@dataclass
class CallResult:
    """Result of an MCP tool call."""
    success: bool
    content: Optional[str] = None
    error: Optional[str] = None


@dataclass
class MCPRequest:
    """MCP request structure."""
    method: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPResponse:
    """MCP response structure."""
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None


class MCPServer:
    """Simulated MCP server with tools."""

    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._resources: Dict[str, Resource] = {}
        self._calls: List[Dict[str, Any]] = []

    def register_tool(self, tool: Tool) -> None:
        """Register a tool with the server."""
        self._tools[tool.name] = tool

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> CallResult:
        """Call a registered tool."""
        if name not in self._tools:
            return CallResult(success=False, error=f"Unknown tool: {name}")

        self._calls.append({"tool": name, "args": arguments})
        return CallResult(success=True, content=f"Called {name} with {arguments}")

    def get_tool(self, name: str) -> Optional[Tool]:
        """Get a registered tool by name."""
        return self._tools.get(name)

    @property
    def call_count(self) -> int:
        """Number of tool calls made."""
        return len(self._calls)
