# Static Analysis Report: DarkDexCircuit

**Date:** 2026-01-15  
**Analyst:** Pruvendo  
**Circuit:** `src/circuit.rs`  
**Method:** Manual constraint analysis (Korrekt-style)

---

## 1. Overview

This report documents the manual static analysis of the DarkDexCircuit following the methodology used by Korrekt (halo2-analyzer). We analyze:

1. **Unused Gates** - Gates that are never enabled
2. **Unused Columns** - Columns not used in any constraint
3. **Unconstrained Cells** - Assigned cells not in any polynomial
4. **Under-constrained Regions** - Areas where witness freedom exists

---

## 2. Circuit Architecture Summary

### 2.1 Gates (Lines 202-225)

| Gate Name | Selector | Polynomial | Rows Affected |
|-----------|----------|------------|---------------|
| `vertical-add` | `q_enable` | `(w0 + w1 + w2) - w3 = 0` | deposit_identifier_data[0..3] |
| `big-vertical-add` | `q_enable_2` | `(w0+w1+w2+w3+w4+w5+w6+w7+w8) - w9 = 0` | key_data[0..9] |

### 2.2 Columns (Lines 186-197)

| Column | Type | Purpose | Equality Enabled |
|--------|------|---------|------------------|
| `a` | Advice | x_eq result | ✅ |
| `b` | Advice | y_eq result | ✅ |
| `c` | Fixed | Constant = 1 | ✅ |
| `key_data` | Advice | 9 limbs + sum | ✅ |
| `deposit_identifier_data` | Advice | sum/token/vault + sum | ✅ |
| `public_inputs` | Instance | 3 public values | ✅ |
| `advices[0..4]` | Advice | Poseidon internal | ✅ |
| `lagrange_coeffs[0..5]` | Fixed | Poseidon constants | 1 constant enabled |

### 2.3 Public Inputs Constraints (Lines 447-451)

| Index | Value | Source |
|-------|-------|--------|
| 0 | `private_note_sum` | deposit_identifier_data.0[0] |
| 1 | `token_type` | deposit_identifier_data.0[1] |
| 2 | `digest` | Poseidon hash output |

---

## 3. Analysis Results

### 3.1 Unused Gates Analysis

**Status:** ✅ PASS

Both gates are enabled during synthesis:
- `q_enable` is enabled at line 433
- `q_enable_2` is enabled at line 400

**Verification:**
```rust
// Line 400
config.q_enable_2.enable(&mut region, 0)?;

// Line 433
config.q_enable.enable(&mut region, 0)?;
```

### 3.2 Unused Columns Analysis

**Status:** ✅ PASS

All columns are used:
- `a`, `b`, `c` are used in "check final equality result" region
- `key_data` is used in key limbs assignment
- `deposit_identifier_data` is used in deposit assignment
- `public_inputs` is used via `constrain_instance`
- Poseidon advices and fixed columns used by PoseidonChip

### 3.3 Unconstrained Cells Analysis

**Status:** ⚠️ POTENTIAL ISSUE FOUND

**Finding:** `vault_rand_val` is NOT a public input!

```rust
// Lines 447-448: Only sum and token are public
for i in 0..2 {
    layouter.constrain_instance(deposit_identifier_data.0[i], config.public_inputs, i)?;
}
// deposit_identifier_data.0 = [private_note_sum.cell(), token_type.cell()]
```

**vault_rand_val analysis:**
- ✅ Assigned at line 418-420
- ✅ Constrained by `vertical-add` gate (line 433)
- ❌ NOT a public input
- ✅ Bound via digest (Poseidon hash)

**Conclusion:** This is **intentional design** - vault_rand_val is hidden from the verifier but bound via the digest. It cannot be changed without changing the digest.

### 3.4 Equality Constraint Analysis

**Status:** ✅ PASS

Critical constraints verified:
```rust
// Lines 359-362: pk = sk * g verification
region.constrain_equal(cell_x, res.0.cell())?; // x_eq from ECC
region.constrain_equal(cell_y, res.1.cell())?; // y_eq from ECC
region.constrain_equal(cell_x, fix)?;           // x_eq == 1
region.constrain_equal(cell_y, fix)?;           // y_eq == 1
```

This enforces `pk == sk * g` through the following chain:
1. `scalar_multiply(g, sk)` computes `mul = sk * g`
2. `is_equal(pk.x, mul.x)` returns x_eq
3. `is_equal(pk.y, mul.y)` returns y_eq
4. Constraints enforce x_eq == 1 and y_eq == 1
5. Therefore pk.x == mul.x AND pk.y == mul.y

---

## 4. Security Assessment

### 4.1 Soundness Properties

| Property | Status | Notes |
|----------|--------|-------|
| pk = sk * g enforced | ✅ | Via equality constraints |
| digest binds all inputs | ✅ | Poseidon(key_sum, deposit_sum) |
| token_type is public | ✅ | constrain_instance index 1 |
| private_note_sum is public | ✅ | constrain_instance index 0 |
| digest is public | ✅ | constrain_instance index 2 |
| vault_rand_val is private | ✅ | Intentional |

### 4.2 Known Issues

| ID | Description | Severity | Exploitable |
|----|-------------|----------|-------------|
| BC-007 | deposit_sum additive collision | Low | ❌ No (public inputs protect) |

---

## 5. Recommendations

### 5.1 Defense in Depth (Low Priority)

**Current:**
```rust
deposit_sum = token + sum + vault
digest = Poseidon(key_sum, deposit_sum)
```

**Recommended:**
```rust
digest = Poseidon(key_sum, token, sum, vault)
```

This provides defense in depth by not relying on public input protection.

### 5.2 Consider Adding Comments

The circuit would benefit from inline documentation explaining:
- Why vault_rand_val is intentionally private
- The security model of the deposit binding

---

## 6. Tool Compatibility Note

**Korrekt (halo2-analyzer)** could not be used directly due to version incompatibility:
- Project uses: `scroll-tech/halo2 v1.1`
- Korrekt expects: `scroll-tech/halo2` (different internal API)

The scroll-halo2 used in this project has private fields that Korrekt tries to access:
- `LookupTracker.inputs` (private)
- `LookupTracker.table` (private)
- `FixedQuery.column_index` (private)

**Recommendation:** Either update Korrekt fork or wait for compatibility update.

---

## 7. Conclusion

The DarkDexCircuit passes manual static analysis:

| Check | Result |
|-------|--------|
| Unused Gates | ✅ PASS |
| Unused Columns | ✅ PASS |
| Unconstrained Cells | ✅ PASS (vault_rand_val is intentionally private) |
| Critical Constraints | ✅ PASS |
| Under-constrained | ❓ Would require SMT solver (CVC5) |

**Overall Assessment:** No critical under-constrained issues found through manual analysis. The circuit appears sound.

---

*Report generated by manual analysis following Korrekt methodology.*

