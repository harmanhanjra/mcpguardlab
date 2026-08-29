# MCPGuardLab — Project Specification

## Problem Statement
MCP (Model Context Protocol) enables LLMs to interact with external tools and data sources. As adoption grows, security becomes critical:
- Tool calls can execute arbitrary commands
- Resource URIs can access sensitive files
- Prompts can contain injection attacks
- No Python implementation proves these defenses work

## Architecture

### Core Components
1. **MCPServer** — Simulated MCP server with tools
2. **MCPClient** — Client that sends requests
3. **SecurityGuard** — Validation layer with verified properties
4. **AdversarialSimulator** — Tests attack scenarios
5. **MCPGuardVerify** — CLI harness for verification gates

### Data Flow
```
User Prompt → SecurityGuard (validate) → MCPClient → MCPServer
                                          ↑
                                    Attack fixtures
                                    (injected prompts,
                                     dangerous URIs,
                                     malformed tools)
```

### Security Layers
1. **Tool Validator** — Regex pattern matching for tool names
2. **Param Sanitizer** — Escape dangerous characters, block path traversal
3. **URI Validator** — Enforce scheme whitelist (no file://, http://)
4. **Prompt Cleaner** — Detect and neutralize injection patterns

## Testing Strategy

### Unit Tests
- Tool name validation
- Parameter sanitization
- URI scheme enforcement
- Prompt injection detection

### Property Tests
- P1: All allowlisted tools pass, all disallowed fail
- P2: Dangerous params are sanitized or rejected
- P3: Forbidden URI schemes are blocked
- P4: Known injection patterns are detected

### Mutation Tests
- M1: Broken tool validator (accepts everything)
- M2: Broken param sanitizer (accepts dangerous input)
- Both must be detected by harness

## Implementation Plan

### Phase 1: Core MCP (30 min)
- Tool/Resource/Prompt data classes
- Basic request/response types

### Phase 2: SecurityGuard (45 min)
- Tool validator with allowlist
- Param sanitizer
- URI validator
- Prompt cleaner

### Phase 3: Test Suite (30 min)
- Unit tests for each component
- Property tests
- Mutation tests

### Phase 4: CLI & Documentation (15 min)
- argparse interface
- README
- Security docs
