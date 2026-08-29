# MCPGuardLab — Architecture Document

## System Overview
MCPGuardLab is a verification harness for MCP (Model Context Protocol) security. It proves that security controls work correctly under adversarial conditions.

## Components

### 1. mcpspec.py — Protocol Data Types
- Tool: name, description, parameters
- Resource: uri, name, mime_type
- Prompt: name, description, arguments
- CallResult: success, content, error

### 2. security.py — Security Guard
- ToolValidator: regex allowlist
- ParamSanitizer: dangerous char escaping
- URIValidator: scheme enforcement
- PromptCleaner: injection detection

### 3. simulator.py — Adversarial Simulator
- Generates attack fixtures
- Tests normal operation
- Tests edge cases

### 4. verify.py — Verification Harness
- CLI entry point
- Property test runners
- Mutation test runners
- Exit code reporting

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   User      │────▶│  Security   │────▶│    MCP      │
│   Prompt    │     │   Guard     │     │   Engine    │
└─────────────┘     └─────────────┘     └─────────────┘
                            │
                            ▼
                    ┌─────────────┐
                    │  Verification │
                    │    Harness   │
                    └─────────────┘
```

## Security Properties

### P1: Tool Name Validation
- Only tools matching allowlist regex can be called
- Disallowed patterns are rejected immediately

### P2: Parameter Sanitization
- Shell metacharacters escaped: `; | & $ ` etc.
- Path traversal blocked: `../` sequences rejected
- SQL injection patterns escaped

### P3: URI Scheme Enforcement
- Only safe schemes allowed: `mcp://`, `https://`
- Forbidden: `file://`, `http://`, `gopher://`, `dict://`

### P4: Prompt Injection Detection
- Pattern matching for common injection techniques
- Delimiter confusion detection
- Escape sequence neutralization

## Testing Strategy

### Deterministic Testing
- Seeded RNG for reproducible attack generation
- Fixed attack fixtures for regression testing

### Property-Based Testing
- Generate random valid/invalid inputs
- Assert security properties hold

### Mutation Testing
- Introduce controlled bugs
- Verify harness detects them

## Failure Modes

### False Positives
- Legitimate tool names blocked
- Safe parameters rejected
- Benign URIs blocked

### False Negatives
- Malicious tool names accepted
- Dangerous parameters allowed
- Injection patterns missed

### Mitigation
- Conservative defaults (reject unknown)
- Explicit allowlists
- Defense in depth
