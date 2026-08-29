# MCPGuardLab — Security Document

## Threat Model

### Assets
- LLM API credentials
- User data in prompts
- Filesystem access via MCP
- Network connections

### Attackers
- **Malicious MCP Server**: Attempts to exploit client
- **Prompt Injection**: User provides malicious input
- **Tool Exploitation**: Abusing tool parameters

### Trust Boundaries
- Client ↔ Server (untrusted channel)
- User Input ↔ Security Guard
- Tool Execution ↔ System

## Security Controls

### 1. Tool Name Validation
- Regex allowlist: `^[a-zA-Z_][a-zA-Z0-9_]*$`
- Reject tools with special characters
- Reject tools with path separators

### 2. Parameter Sanitization
- Escape shell metacharacters
- Block path traversal sequences
- Sanitize SQL patterns

### 3. URI Validation
- Whitelist allowed schemes
- Reject absolute paths
- Validate hostname format

### 4. Prompt Cleaning
- Detect injection patterns
- Neutralize escape sequences
- Flag suspicious content

## Vulnerabilities Mitigated

### OWASP Top 10 for LLMs
1. **LLM01: Prompt Injection** — Detected and neutralized
2. **LLM02: Insecure Output Handling** — Output validated
3. **LLM03: Training Data Poisoning** — N/A for runtime
4. **LLM04: Model Denial of Service** — Rate limiting (future)
5. **LLM05: Supply Chain Vulnerabilities** — Tool validation
6. **LLM06: Sensitive Information Disclosure** — URI validation
7. **LLM07: Insecure Plugin Design** — Tool name validation
8. **LLM08: Excessive Agency** — Parameter sanitization
9. **LLM09: Overreliance** — Validation warnings
10. **LLM10: Model Theft** — N/A for runtime

### CWE Mappings
- CWE-78: OS Command Injection — Parameter sanitization
- CWE-89: SQL Injection — Parameter sanitization
- CWE-22: Path Traversal — URI validation
- CWE-79: XSS — Prompt cleaning

## Accepted Risks

### B603: subprocess call with shell=True
- NOT USED — no subprocess calls in this project

### B311: auditable function call
- Used for deterministic seeding only (accepted)

### B110: test assumptions
- Test fixtures use controlled dangerous input (accepted)

## Security Testing

### Static Analysis
- Bandit: Clean at -ll
- Ruff: Clean after auto-fix

### Dynamic Testing
- Property tests verify security controls
- Mutation tests prove harness sensitivity

### Attack Simulation
- 50+ attack fixtures
- 100+ adversarial prompts
- Coverage of OWASP LLM Top 10

## Incident Response

### If Vulnerability Discovered
1. Document in SECURITY.md
2. Create regression test
3. Fix in source
4. Update version

### Reporting
- GitHub Issues
- Responsible disclosure
