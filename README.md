# MCPGuardLab

Verified MCP (Model Context Protocol) Security Validation Harness.

## Overview

MCP is the emerging standard for connecting LLMs to external tools. MCPGuardLab provides:
- From-scratch Python MCP implementation
- Security validation with verified properties
- Adversarial testing with mutation detection
- Educational reference for secure MCP design

## Features

- **P1: Tool Name Validation** — Regex allowlist enforcement
- **P2: Parameter Sanitization** — Shell/SQL injection blocking
- **P3: URI Validation** — Scheme enforcement (no file://)
- **P4: Prompt Injection Detection** — Pattern matching
- **M1/M2: Mutation Tests** — Prove harness non-vacuity

## Installation

```bash
uv venv .venv
uv pip install -e ".[test]" --python .venv
```

## Usage

```bash
# Run verification harness
mcpguardlab-verify --seed 42 --trials 100

# Run adversarial simulation
mcpguardlab simulate --seed 42

# Check a single tool
mcpguardlab check get_weather
```

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=mcpguardlab --cov-report=term-missing
```

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for threat model and security measures.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design.

## License

MIT
