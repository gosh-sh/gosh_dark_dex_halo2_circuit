# AGENTS.md - Project Rules

## General Rules

- **DO NOT modify files in the main project** - all original source files are read-only
- **Only modify files in the `Pruvendo/` directory and this `AGENTS.md` file**
- **Code and comments must be in English**
- **Notes and reports may be in Russian unless otherwise specified**

## Project Structure

- `src/` - Main source code (READ-ONLY)
- `config/` - Configuration files (READ-ONLY)
- `Pruvendo/` - Pruvendo company documentation, tests, and notes
- `AGENTS.md` - This file with project rules

## Pruvendo Directory Structure

```
Pruvendo/
├── docs/           # Documentation and reports
├── tests/          # Additional test files
└── notes/          # Working notes and analysis
```

## Bug Candidate Naming Convention

**IMPORTANT: Use "BC" (Bug Candidate) instead of "BUG"**

We use the term "Bug Candidate" (BC) instead of "Bug" because:
1. We cannot be 100% certain something is a bug until fully verified
2. Some findings may be expected behavior or design decisions
3. It avoids prematurely alarming stakeholders

**Naming rules:**
- Use `BC-XXX` format (e.g., BC-001, BC-007)
- Use `BugCandidate` or `BC` in code identifiers
- In documentation, write "bug candidate" not "bug"
- Only after full verification and confirmation, a BC may be referred to as a confirmed bug

**Example:**
```rust
// Good:
pub const BC_007: BugCandidateInfo = ...;
// "BC-007: deposit_sum collision candidate"

// Bad:
pub const BUG_007: BugInfo = ...;
// "BUG-007: deposit_sum collision"
```

