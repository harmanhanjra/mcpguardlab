"""Tests for MCPGuardLab CLI and edge cases."""

import subprocess
import sys
from pathlib import Path


def test_cli_help():
    """CLI should show help."""
    result = subprocess.run(
        [sys.executable, "-m", "mcpguardlab.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "MCP Security Validation" in result.stdout


def test_verify_cli():
    """Verify command should work."""
    result = subprocess.run(
        [sys.executable, "-m", "mcpguardlab.verify"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "OVERALL: PASS" in result.stdout


def test_simulate_cli():
    """Simulate command should work."""
    result = subprocess.run(
        [sys.executable, "-m", "mcpguardlab.cli", "simulate", "--seed", "42"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_check_valid_tool():
    """Check command should accept valid tools."""
    result = subprocess.run(
        [sys.executable, "-m", "mcpguardlab.cli", "check", "get_weather"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "VALID" in result.stdout


def test_check_invalid_tool():
    """Check command should reject invalid tools."""
    result = subprocess.run(
        [sys.executable, "-m", "mcpguardlab.cli", "check", "cmd/exec"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "REJECTED" in result.stdout


def test_edge_case_empty_params():
    """Test with empty parameters."""
    from mcpguardlab.security import SecurityGuard

    guard = SecurityGuard()
    valid, _ = guard.validate_tool_call("test_tool", {})
    assert valid


def test_edge_case_none_params():
    """Test with None values in parameters."""
    from mcpguardlab.security import SecurityGuard

    guard = SecurityGuard()
    valid, _ = guard.validate_tool_call("test_tool", {"key": None})
    assert valid  # None should be converted to string


def test_edge_case_numeric_params():
    """Test with numeric parameters."""
    from mcpguardlab.security import SecurityGuard

    guard = SecurityGuard()
    valid, _ = guard.validate_tool_call("calculate", {"a": 42, "b": 100})
    assert valid
