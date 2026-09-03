"""Security guard for MCP requests."""

import ipaddress
import re
from typing import Any, Iterator, List, Tuple
from urllib.parse import urlparse

# Safe tool name pattern: alphanumeric and underscores only
TOOL_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

# Dangerous patterns for parameter sanitization
SHELL_METACHARACTERS = re.compile(r'[;|&$`\\"]')
PATH_TRAVERSAL = re.compile(r'\.\./')
SQL_INJECTION = re.compile(r"('|\")?(--|#|;|' OR '|'|\" OR \")", re.IGNORECASE)

# Allowed URI schemes
ALLOWED_URI_SCHEMES = {'mcp', 'https', 'data', 'mcp+ws', 'mcp+wss'}
FORBIDDEN_URI_SCHEMES = {'file', 'http', 'gopher', 'dict', 'ftp', 'ssh', 'telnet'}
LOCAL_HOSTNAMES = {'localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback'}
MAX_URI_LENGTH = 8192
MAX_PARAM_DEPTH = 20
MAX_PARAM_NODES = 10_000

# Known prompt injection patterns
INJECTION_PATTERNS = [
    re.compile(r'ignore\s+previous', re.IGNORECASE),
    re.compile(r'system:\s*\n?(.*)', re.IGNORECASE),
    re.compile(r'override\s+instructions', re.IGNORECASE),
    re.compile(r'disable\s+safety', re.IGNORECASE),
    re.compile(r'exfil\(', re.IGNORECASE),
    re.compile(r'exec\(', re.IGNORECASE),
    re.compile(r'eval\(', re.IGNORECASE),
]


class ToolValidator:
    """Validates tool names against allowlist pattern."""

    def validate(self, tool_name: str) -> Tuple[bool, str]:
        """Validate tool name. Returns (is_valid, error_message)."""
        if not tool_name:
            return False, "Empty tool name"

        if not TOOL_NAME_PATTERN.match(tool_name):
            return False, f"Tool name contains invalid characters: {tool_name}"

        # Check for path separators
        if '/' in tool_name or '\\' in tool_name:
            return False, f"Tool name contains path separator: {tool_name}"

        return True, ""


class ParamSanitizer:
    """Sanitizes tool parameters for security."""

    def sanitize(self, param_value: str) -> Tuple[str, bool]:
        """Sanitize parameter value. Returns (sanitized, was_dangerous)."""
        if not isinstance(param_value, str):
            return str(param_value), False

        original = param_value

        # Block path traversal entirely
        if PATH_TRAVERSAL.search(original):
            return "", True

        # Block dangerous URI schemes in parameter values
        if self._has_dangerous_uri(original):
            return "", True

        # Block shell metacharacters entirely (don't just escape)
        if SHELL_METACHARACTERS.search(original):
            return "", True

        # Check for SQL injection
        if SQL_INJECTION.search(original):
            cleaned = re.sub(r"['\"]", r"\'", original)
            return cleaned, True

        return original, False

    def _has_dangerous_uri(self, value: str) -> bool:
        """Check if value contains a dangerous URI scheme."""
        normalized = value.lstrip().casefold()
        return any(normalized.startswith(f"{scheme}://") for scheme in FORBIDDEN_URI_SCHEMES)


class URIValidator:
    """Validates resource URIs for security."""

    def validate(self, uri: str) -> Tuple[bool, str]:
        """Validate URI and block obvious SSRF targets.

        This performs deterministic checks only; it intentionally does not resolve
        DNS, because hostname resolution belongs at the network egress boundary.
        """
        if not uri:
            return False, "Empty URI"

        if len(uri) > MAX_URI_LENGTH:
            return False, "URI exceeds maximum allowed length"

        if uri.startswith('data:'):
            return True, ""

        if '://' not in uri:
            return False, f"URI missing scheme: {uri}"

        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()

        if scheme in FORBIDDEN_URI_SCHEMES:
            return False, f"Forbidden URI scheme: {scheme} in {uri}"

        if scheme not in ALLOWED_URI_SCHEMES:
            return False, f"Unknown URI scheme: {scheme} in {uri}"

        if scheme == 'https':
            if parsed.username or parsed.password:
                return False, "Credentials in HTTPS URIs are not allowed"
            if not parsed.hostname:
                return False, "HTTPS URI missing hostname"
            safe, reason = self._validate_network_host(parsed.hostname)
            if not safe:
                return False, reason

        return True, ""

    def _validate_network_host(self, hostname: str) -> Tuple[bool, str]:
        """Reject localhost and non-public literal IP addresses."""
        host = hostname.rstrip('.').lower()

        if host in LOCAL_HOSTNAMES or host.endswith('.localhost'):
            return False, f"Local hostname is not allowed: {hostname}"

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return True, ""

        if not address.is_global:
            return False, f"Non-public IP address is not allowed: {hostname}"

        return True, ""


class PromptCleaner:
    """Detects and neutralizes prompt injection."""

    def detect(self, prompt: str) -> Tuple[bool, List[str]]:
        """Detect injection patterns. Returns (is_safe, detected_patterns)."""
        if not isinstance(prompt, str):
            return True, []

        detected = []
        for pattern in INJECTION_PATTERNS:
            if pattern.search(prompt):
                detected.append(pattern.pattern)

        return len(detected) == 0, detected

    def clean(self, prompt: str) -> Tuple[str, bool]:
        """Clean prompt by neutralizing injection patterns. Returns (cleaned, was_cleaned)."""
        if not isinstance(prompt, str):
            return str(prompt), False

        original = prompt
        cleaned = prompt

        for pattern in INJECTION_PATTERNS:
            cleaned = pattern.sub('[REDACTED]', cleaned)

        return cleaned, cleaned != original


class SecurityGuard:
    """Main security guard combining all validators."""

    def __init__(self):
        self.tool_validator = ToolValidator()
        self.param_sanitizer = ParamSanitizer()
        self.uri_validator = URIValidator()
        self.prompt_cleaner = PromptCleaner()

    def validate_tool_call(self, tool_name: str, arguments: dict) -> Tuple[bool, str]:
        """Validate a tool call. Returns (is_valid, error_message)."""
        # Validate tool name
        valid, error = self.tool_validator.validate(tool_name)
        if not valid:
            return False, f"Invalid tool: {error}"

        if not isinstance(arguments, dict):
            return False, "Tool arguments must be an object"

        try:
            values = self._walk_arguments(arguments)
            for path, prompt_like, value in values:
                if prompt_like:
                    safe, _ = self.prompt_cleaner.detect(value)
                    if not safe:
                        return False, f"Prompt injection detected in '{path}'"

                _, was_dangerous = self.param_sanitizer.sanitize(value)
                if was_dangerous:
                    return False, f"Dangerous parameter value in '{path}'"
        except ValueError as exc:
            return False, str(exc)

        return True, ""

    def _walk_arguments(self, arguments: dict) -> Iterator[Tuple[str, bool, str]]:
        """Yield every nested string with bounded traversal.

        MCP arguments are JSON-like and may contain arbitrarily nested objects and
        arrays. Security checks must cover the full structure without allowing a
        deeply nested or oversized payload to exhaust the process.
        """
        prompt_keys = {"prompt", "query", "message", "text"}
        stack: List[Tuple[Any, str, bool, int]] = [(arguments, "$", False, 0)]
        seen_containers = set()
        nodes = 0

        while stack:
            value, path, prompt_like, depth = stack.pop()
            nodes += 1
            if nodes > MAX_PARAM_NODES:
                raise ValueError("Tool arguments exceed maximum size")
            if depth > MAX_PARAM_DEPTH:
                raise ValueError("Tool arguments exceed maximum nesting depth")

            if isinstance(value, str):
                yield path, prompt_like, value
                continue

            if isinstance(value, dict):
                container_id = id(value)
                if container_id in seen_containers:
                    raise ValueError("Tool arguments contain a circular reference")
                seen_containers.add(container_id)
                for key, child in value.items():
                    if not isinstance(key, str):
                        raise ValueError("Tool argument object keys must be strings")
                    child_path = f"{path}.{key}"
                    stack.append((child, child_path, key.casefold() in prompt_keys, depth + 1))
                continue

            if isinstance(value, (list, tuple)):
                container_id = id(value)
                if container_id in seen_containers:
                    raise ValueError("Tool arguments contain a circular reference")
                seen_containers.add(container_id)
                for index, child in enumerate(value):
                    stack.append((child, f"{path}[{index}]", prompt_like, depth + 1))

    def validate_resource_uri(self, uri: str) -> Tuple[bool, str]:
        """Validate a resource URI. Returns (is_valid, error_message)."""
        return self.uri_validator.validate(uri)

    def check_prompt(self, prompt: str) -> Tuple[bool, List[str]]:
        """Check prompt for injection. Returns (is_safe, detected_patterns)."""
        return self.prompt_cleaner.detect(prompt)
