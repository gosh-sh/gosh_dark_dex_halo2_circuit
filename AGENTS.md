# AGENTS.md - Project Rules

## Role Definition

**We are security auditors, NOT developers.**

This means:
- We **find and document** bugs/vulnerabilities, we do NOT fix them
- Fixes are the responsibility of the project developers
- Our deliverables are: tests, bug candidate reports, coverage analysis
- We do NOT modify the main project source code (`src/`, `config/`)

## General Rules

- **DO NOT modify files in the main project** - all original source files are read-only
- **Only modify files in the `Pruvendo/` directory and this `AGENTS.md` file**
- **Code and comments must be in English**
- **Notes and reports may be in Russian unless otherwise specified**

## Plan-First Principle

**IMPORTANT: Always follow the plan!**

Before starting any work:
1. **Check if a plan exists** - look for `Pruvendo/docs/TESTING_PLAN.md` or similar
2. **Review current priorities** - check task list and plan status
3. **If plan is outdated** - update the plan FIRST, then work according to updated plan
4. **Never work without a plan** - if no plan exists, create one before starting

This ensures:
- Consistent progress tracking
- No duplicate or forgotten work
- Clear communication with stakeholders
- Reproducible audit process

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

## Tool Usage Instructions

### Fuzzing

Fuzz tests are located in `Pruvendo/fuzz/`. There is a symlink `fuzz -> Pruvendo/fuzz` in the project root.

**Run fuzzing from the project root:**
```bash
# List all fuzz targets
cargo +nightly fuzz list --fuzz-dir Pruvendo/fuzz

# Run a specific target (e.g., 1000 runs)
cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_determinism -- -runs=1000

# Run with time limit (e.g., 60 seconds)
cargo +nightly fuzz run --fuzz-dir Pruvendo/fuzz fuzz_soundness -- -max_total_time=60

# Quick smoke test of all targets
./Pruvendo/fuzz/quick_smoke_test.sh

# Overnight fuzzing
./Pruvendo/fuzz/run_overnight.sh
```

**Important:** Always run from the project root directory, not from `Pruvendo/fuzz/`.

### Apalache (Bounded Model Checking)

Apalache is installed in `Pruvendo/external_packages/apalache/`. It requires Java 17+.

**Setup Java (if not in PATH):**
```bash
export JAVA_HOME="/usr/local/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$PATH"
```

**Run Apalache verification via Quint:**
```bash
export APALACHE_DIST="$(pwd)/Pruvendo/external_packages/apalache/apalache"

# Verify a specific invariant
quint verify --init=init --step=step --invariant=inv_dex_non_negative --max-steps=10 \
  Pruvendo/models/dark_dex_protocol.qnt

# Available invariants:
# - inv_dex_non_negative
# - inv_owner_only
# - inv_no_double_withdraw
# - inv_unique_digests
# - inv_total_conservation
```

**Run Quint random simulation (faster, not exhaustive):**
```bash
quint run --init=init --step=step --invariant=inv_dex_non_negative \
  --max-samples=1000 --max-steps=20 Pruvendo/models/dark_dex_protocol.qnt
```

### Property Tests

Property tests are in `Pruvendo/tests/property_tests/`.

```bash
cd Pruvendo/tests/property_tests

# Run all property tests
cargo test --release

# Run specific test
cargo test --release prop_valid_sk

# Run with verbose output
cargo test --release -- --nocapture
```

### Code Coverage

```bash
cd Pruvendo/tests/property_tests

# Text report
cargo llvm-cov --text

# HTML report
cargo llvm-cov --html --output-dir coverage/

# Note: May take several minutes due to compilation with instrumentation
```
