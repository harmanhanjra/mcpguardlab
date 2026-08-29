"""Security guard for MCP requests."""

import re
from typing import List, Optional, Tuple


# Safe tool name pattern: alphanumeric and underscores only
TOOL_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

# Dangerous patterns for parameter sanitization
SHELL_METACHARACTERS = re.compile(r'[;|&$`\\"]')
PATH_TRAVERSAL = re.compile(r'\.\./')
SQL_INJECTION = re.compile(r"('|\")?(--|#|;|' OR '|'|\" OR \")", re.IGNORECASE)

# Allowed URI schemes
ALLOWED_URI_SCHEMES = {'mcp', 'https', 'data', 'mcp+ws', 'mcp+wss'}
FORBIDDEN_URI_SCHEMES = {'file', 'http', 'gopher', 'dict', 'ftp', 'ssh', 'telnet'}

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
        for scheme in FORBIDDEN_URI_SCHEMES:
            if value.startswith(f"{scheme}://"):
                return True
        return False


class URIValidator:
    """Validates resource URIs for security."""

    def validate(self, uri: str) -> Tuple[bool, str]:
        """Validate URI. Returns (is_valid, error_message)."""
        if not uri:
            return False, "Empty URI"

        # Handle data: URIs specially
        if uri.startswith('data:'):
            return True, ""

        # Check for scheme
        if '://' not in uri:
            return False, f"URI missing scheme: {uri}"

        scheme = uri.split('://')[0].lower()

        if scheme in FORBIDDEN_URI_SCHEMES:
            return False, f"Forbidden URI scheme: {scheme} in {uri}"

        if scheme not in ALLOWED_URI_SCHEMES:
            return False, f"Unknown URI scheme: {scheme} in {uri}"

        # Block absolute paths in file URIs
        if scheme == 'file' and uri.startswith('file:///'):
            return False, f"File URI not allowed: {uri}"

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

        # Sanitize arguments
        for key, value in list(arguments.items()):
            if isinstance(value, str):
                # Check for prompt injection in prompt-like parameters
                if key in ("prompt", "query", "message", "text"):
                    safe, patterns = self.prompt_cleaner.detect(value)
                    if not safe:
                        return False, f"Prompt injection detected in '{key}'"

                sanitized, was_dangerous = self.param_sanitizer.sanitize(value)
                if was_dangerous:
                    return False, f"Dangerous parameter value in '{key}'"
                arguments[key] = sanitized

        return True, ""

    def validate_resource_uri(self, uri: str) -> Tuple[bool, str]:
        """Validate a resource URI. Returns (is_valid, error_message)."""
        return self.uri_validator.validate(uri)

    def check_prompt(self, prompt: str) -> Tuple[bool, List[str]]:
        """Check prompt for injection. Returns (is_safe, detected_patterns)."""
        return self.prompt_cleaner.detect(prompt)
