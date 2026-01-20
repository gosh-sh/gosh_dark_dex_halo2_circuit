# Korrekt Integration for Dark DEX

## Summary

**Status: ✅ Successfully compiled korrekt with scroll-halo2 v1.1**

Korrekt (halo2-analyzer by Quantstamp) is a static analysis tool for Halo2 circuits that can detect:
- Unused gates
- Unused columns  
- Unconstrained cells
- Under-constrained circuits (via SMT solver)

## Problem

The original korrekt uses `Analyzable-Halo2/scroll-halo2` which is based on an older version (v0.2.0) of scroll-halo2.
Dark DEX uses `scroll-tech/halo2` v1.1.0 which is incompatible.

## Solution

We rebased Quantstamp's visibility patches onto scroll-tech/halo2 v1.1:

### Patched Repository

Location: `Pruvendo/korrekt_integration/scroll-halo2`
Branch: `v1.1-analyzer`

```
321bec21 Add visibility patches for korrekt analyzer compatibility with v1.1
15a9f841 selector_map visiblity changed (#3)
66c18fca InstanceQuery visiblity changed (#2)
38681e28 modifications for analyzer-2
e5ddf67e better err for mv lookup failure  <- scroll-tech/halo2 v1.1 HEAD
```

### Changes Made

1. **scroll-halo2 patches** (visibility changes):
   - `halo2_proofs/src/plonk.rs`: `pub mod permutation`
   - `halo2_proofs/src/plonk/circuit.rs`: Multiple field visibility changes
   - `halo2_proofs/src/plonk/permutation/keygen.rs`: `pub columns`, `pub mapping`, `pub sizes`

2. **korrekt patches**:
   - `korrekt/src/circuit_analyzer/analyzer.rs`: Hardcoded BN256 Fr modulus (bn256::fr module is private)
   - `Cargo.toml`: Use local patched scroll-halo2 and scroll-tech/halo2curves v0.1.0

## How to Use

### Build korrekt

```bash
cd Pruvendo/korrekt_integration/halo2-analyzer/korrekt
cargo build --no-default-features --features use_scroll_halo2_proofs
```

### Run Tests

```bash
cargo test --no-default-features --features use_scroll_halo2_proofs
```

### Analyze a Circuit

To analyze Dark DEX circuit, you would need to:

1. Add korrekt as a dev-dependency to Dark DEX project
2. Create a test that instantiates `Analyzer` with `DarkDexCircuit`

Example (conceptual):
```rust
use korrekt::circuit_analyzer::analyzer::Analyzer;
use korrekt::io::analyzer_io_type::AnalyzerType;

#[test]
fn analyze_dark_dex() {
    let circuit = DarkDexCircuit::default();
    let k = 8;
    
    let mut analyzer = Analyzer::new(&circuit, k, AnalyzerType::UnusedGates, None).unwrap();
    let result = analyzer.analyze_unused_custom_gates().unwrap();
    println!("Unused gates: {:?}", result);
}
```

## Limitations

1. **Complex Dependencies**: Dark DEX uses poseidon-circuit, halo2-base, halo2-ecc which makes direct integration complex
2. **Config File**: Dark DEX's `configure()` reads from `config/circuit.config` file
3. **SMT Solver**: Under-constrained analysis requires CVC5 SMT solver installed

## Comparison: Korrekt vs Our Fuzzing

| Check | Korrekt | Our Fuzzing |
|-------|---------|-------------|
| Unused gates | ✅ | ✅ `fuzz_unused_public_inputs` |
| Unused columns | ✅ | Partial |
| Unconstrained cells | ✅ | ✅ `fuzz_witness_unconstrained` |
| Under-constrained | ✅ (SMT) | ✅ `fuzz_soundness`, `fuzz_copy_constraint_violation` |
| Proof replay | ❌ | ✅ `fuzz_proof_replay` |
| Digest collisions | ❌ | ✅ `fuzz_digest_collision` |
| Witness manipulation | ❌ | ✅ `fuzz_witness_manipulation` |

## Recommendation

For Dark DEX audit, our fuzzing approach provides better coverage because:
1. It tests runtime behavior, not just static structure
2. It covers cryptographic properties (collision resistance, binding)
3. It doesn't require complex integration

Korrekt would be valuable for:
1. Large circuits where manual review is impractical
2. Finding structural issues early in development
3. Formal verification via SMT solver

## Files

- `Pruvendo/korrekt_integration/scroll-halo2/` - Patched scroll-halo2 v1.1
- `Pruvendo/korrekt_integration/halo2-analyzer/` - Modified korrekt

