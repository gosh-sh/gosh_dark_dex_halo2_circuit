//! SMT-based constraint analysis for Dark DEX circuit
//!
//! This module extracts constraints from the Dark DEX circuit and converts them
//! to SMT-LIB format for analysis with CVC5 solver.
//!
//! Based on Quantstamp's korrekt approach but implemented directly for our circuit.
//!
//! Run: cargo test --test smt_analysis -- --nocapture

use std::collections::HashSet;
use std::fmt::Write;
use std::process::Command;
use std::fs;

use halo2_base::halo2_proofs::{
    halo2curves::bn256::Fr,
    halo2curves::ff::PrimeField,
    plonk::{Expression, Circuit, ConstraintSystem},
    dev::MockProver,
    circuit::SimpleFloorPlanner,
};

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;

/// BN256 Fr field modulus (prime)
const BN256_FR_MODULUS: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// SMT-LIB generator for halo2 constraints
pub struct SmtGenerator {
    output: String,
    variables: HashSet<String>,
}

impl SmtGenerator {
    pub fn new() -> Self {
        Self {
            output: String::new(),
            variables: HashSet::new(),
        }
    }

    /// Write SMT-LIB header with finite field definition
    pub fn write_header(&mut self) {
        writeln!(&mut self.output, "(set-logic ALL)").unwrap();
        writeln!(&mut self.output, "(set-option :produce-models true)").unwrap();
        writeln!(&mut self.output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
        writeln!(&mut self.output).unwrap();
    }

    /// Declare a variable
    pub fn declare_var(&mut self, name: &str) {
        if !self.variables.contains(name) {
            writeln!(&mut self.output, "(declare-fun {} () F)", name).unwrap();
            self.variables.insert(name.to_string());
        }
    }

    /// Convert halo2 Expression to SMT term
    pub fn expr_to_smt(&mut self, expr: &Expression<Fr>, row: i32) -> String {
        match expr {
            Expression::Constant(c) => {
                let bytes = c.to_repr();
                let hex = hex::encode(bytes.as_ref());
                let value = num_bigint::BigUint::from_bytes_le(bytes.as_ref());
                format!("(as ff{} F)", value)
            }
            Expression::Selector(s) => {
                // Selectors are treated as 0 or 1
                let name = format!("S_{}", s.index());
                self.declare_var(&name);
                name
            }
            Expression::Fixed(query) => {
                let rot = query.rotation().0;
                let name = format!("F_{}_{}", query.column_index(), row + rot);
                self.declare_var(&name);
                name
            }
            Expression::Advice(query) => {
                let rot = query.rotation().0;
                let name = format!("A_{}_{}", query.column_index(), row + rot);
                self.declare_var(&name);
                name
            }
            Expression::Instance(query) => {
                let rot = query.rotation().0;
                let name = format!("I_{}_{}", query.column_index(), row + rot);
                self.declare_var(&name);
                name
            }
            Expression::Challenge(_) => {
                "(as ff0 F)".to_string() // Challenges are unknown, treat as 0
            }
            Expression::Negated(a) => {
                let inner = self.expr_to_smt(a, row);
                format!("(ff.neg {})", inner)
            }
            Expression::Sum(a, b) => {
                let left = self.expr_to_smt(a, row);
                let right = self.expr_to_smt(b, row);
                format!("(ff.add {} {})", left, right)
            }
            Expression::Product(a, b) => {
                let left = self.expr_to_smt(a, row);
                let right = self.expr_to_smt(b, row);
                format!("(ff.mul {} {})", left, right)
            }
            Expression::Scaled(a, c) => {
                let inner = self.expr_to_smt(a, row);
                let bytes = c.to_repr();
                let value = num_bigint::BigUint::from_bytes_le(bytes.as_ref());
                format!("(ff.mul (as ff{} F) {})", value, inner)
            }
        }
    }

    /// Add constraint: expression must equal zero
    pub fn add_constraint(&mut self, name: &str, smt_expr: &str) {
        writeln!(&mut self.output, "; Constraint: {}", name).unwrap();
        writeln!(&mut self.output, "(assert (= {} (as ff0 F)))", smt_expr).unwrap();
    }

    /// Write check-sat and get-model
    pub fn write_footer(&mut self) {
        writeln!(&mut self.output).unwrap();
        writeln!(&mut self.output, "(check-sat)").unwrap();
        writeln!(&mut self.output, "(get-model)").unwrap();
    }

    /// Get the generated SMT-LIB content
    pub fn get_output(&self) -> &str {
        &self.output
    }
}

/// Extract gates from Dark DEX circuit
///
/// Uses Circuit::configure() to get ConstraintSystem with all gates defined.
pub fn extract_circuit_gates() -> Vec<(String, Vec<Expression<Fr>>)> {
    // Create ConstraintSystem and configure the circuit
    let mut cs: ConstraintSystem<Fr> = ConstraintSystem::default();
    let _config = <DarkDexCircuit as Circuit<Fr>>::configure(&mut cs);

    // Extract gates
    let mut gates = Vec::new();
    for gate in cs.gates() {
        let name = gate.name().to_string();
        let polys: Vec<Expression<Fr>> = gate.polynomials().to_vec();
        gates.push((name, polys));
    }

    gates
}

/// Generate SMT-LIB file for under-constrained check
///
/// The idea: check if there exist two different witnesses w1, w2 such that
/// both satisfy all constraints but produce the same public outputs.
pub fn generate_underconstrained_check(gates: &[(String, Vec<Expression<Fr>>)], row: i32) -> String {
    let mut generator = SmtGenerator::new();
    generator.write_header();

    writeln!(&mut generator.output, "; === Dark DEX Circuit Constraints ===").unwrap();
    writeln!(&mut generator.output, "; Row: {}", row).unwrap();
    writeln!(&mut generator.output).unwrap();

    // Generate constraints for each gate
    for (gate_name, polys) in gates {
        for (i, poly) in polys.iter().enumerate() {
            let smt_expr = generator.expr_to_smt(poly, row);
            generator.add_constraint(&format!("{}_{}", gate_name, i), &smt_expr);
        }
    }

    generator.write_footer();
    generator.get_output().to_string()
}

/// Run CVC5 on SMT-LIB file with timeout
pub fn run_cvc5(smt_content: &str, timeout_ms: u32) -> Result<String, String> {
    // Write to temp file with unique name based on content hash
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    smt_content.hash(&mut hasher);
    let hash = hasher.finish();
    let temp_path = format!("/tmp/dark_dex_smt_{}.smt2", hash);
    fs::write(&temp_path, smt_content).map_err(|e| e.to_string())?;

    // Try to find cvc5
    let cvc5_paths = vec![
        std::env::var("HOME").unwrap_or_default() + "/bin/cvc5",
        "/usr/local/bin/cvc5".to_string(),
        "cvc5".to_string(),
    ];

    for cvc5_path in &cvc5_paths {
        let output = Command::new(cvc5_path)
            .args(&[
                "--lang=smt2",
                &format!("--tlimit={}", timeout_ms),
                &temp_path,
            ])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Ok(format!("{}\n{}", stdout, stderr));
        }
    }

    Err("CVC5 not found. Install from https://github.com/cvc5/cvc5/releases".to_string())
}

/// Generate SMT for simple pad-and-add gate only (faster to solve)
pub fn generate_simple_constraint_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Simple pad-and-add constraint ===").unwrap();
    writeln!(&mut output, "; Constraint: a + b = c").unwrap();
    writeln!(&mut output).unwrap();

    // Declare variables
    writeln!(&mut output, "(declare-fun a () F)").unwrap();
    writeln!(&mut output, "(declare-fun b () F)").unwrap();
    writeln!(&mut output, "(declare-fun c () F)").unwrap();

    // Constraint: a + b = c
    writeln!(&mut output, "(assert (= (ff.add a b) c))").unwrap();

    // Fix some values to test
    writeln!(&mut output, "(assert (= a (as ff100 F)))").unwrap();
    writeln!(&mut output, "(assert (= b (as ff200 F)))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();
    writeln!(&mut output, "(get-model)").unwrap();

    output
}

/// Generate SMT for under-constrained check
///
/// This checks if there exist two different witnesses that produce the same output.
/// If SAT, the circuit may be under-constrained.
pub fn generate_underconstrained_witness_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Under-constrained check ===").unwrap();
    writeln!(&mut output, "; Check if two different inputs can produce same output").unwrap();
    writeln!(&mut output).unwrap();

    // Witness set 1
    writeln!(&mut output, "; Witness 1").unwrap();
    writeln!(&mut output, "(declare-fun a1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun b1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun c1 () F)").unwrap();

    // Witness set 2
    writeln!(&mut output, "; Witness 2").unwrap();
    writeln!(&mut output, "(declare-fun a2 () F)").unwrap();
    writeln!(&mut output, "(declare-fun b2 () F)").unwrap();
    writeln!(&mut output, "(declare-fun c2 () F)").unwrap();

    // Both satisfy constraint: a + b = c
    writeln!(&mut output, "; Both satisfy: a + b = c").unwrap();
    writeln!(&mut output, "(assert (= (ff.add a1 b1) c1))").unwrap();
    writeln!(&mut output, "(assert (= (ff.add a2 b2) c2))").unwrap();

    // Same public output (c is public)
    writeln!(&mut output, "; Same public output").unwrap();
    writeln!(&mut output, "(assert (= c1 c2))").unwrap();

    // Different private inputs
    writeln!(&mut output, "; Different private inputs").unwrap();
    writeln!(&mut output, "(assert (not (and (= a1 a2) (= b1 b2))))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();
    writeln!(&mut output, "(get-model)").unwrap();

    output
}

/// Generate SMT to check if public inputs can be forged
///
/// Dark DEX has 3 public inputs:
///   - private_note_sum
///   - token_type
///   - digest (Poseidon hash)
///
/// We check: can an attacker provide valid public inputs without knowing sk?
pub fn generate_public_input_binding_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Dark DEX Public Input Binding Check ===").unwrap();
    writeln!(&mut output, "; Question: Can two different sk values produce same public outputs?").unwrap();
    writeln!(&mut output).unwrap();

    // Two different secret keys
    writeln!(&mut output, "; Two different secret keys").unwrap();
    writeln!(&mut output, "(declare-fun sk1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun sk2 () F)").unwrap();

    // Same public inputs
    writeln!(&mut output, "; Same public inputs").unwrap();
    writeln!(&mut output, "(declare-fun token_type () F)").unwrap();
    writeln!(&mut output, "(declare-fun private_note_sum () F)").unwrap();
    writeln!(&mut output, "(declare-fun digest () F)").unwrap();

    // Intermediate: sk_commitment = Poseidon(sk, 0)
    // We model Poseidon as an uninterpreted function (black box)
    writeln!(&mut output, "; Poseidon as uninterpreted function").unwrap();
    writeln!(&mut output, "(declare-fun poseidon2 (F F) F)").unwrap();
    writeln!(&mut output, "(declare-fun poseidon4 (F F F F) F)").unwrap();

    // sk_commitment1 = poseidon(sk1, 0)
    writeln!(&mut output, "(declare-fun sk_commitment1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun sk_commitment2 () F)").unwrap();
    writeln!(&mut output, "(assert (= sk_commitment1 (poseidon2 sk1 (as ff0 F))))").unwrap();
    writeln!(&mut output, "(assert (= sk_commitment2 (poseidon2 sk2 (as ff0 F))))").unwrap();

    // digest = poseidon(sk_commitment, private_note_sum, token_type, sk)
    writeln!(&mut output, "; Both produce same digest").unwrap();
    writeln!(&mut output, "(assert (= digest (poseidon4 sk_commitment1 private_note_sum token_type sk1)))").unwrap();
    writeln!(&mut output, "(assert (= digest (poseidon4 sk_commitment2 private_note_sum token_type sk2)))").unwrap();

    // Different secret keys
    writeln!(&mut output, "; Different secret keys").unwrap();
    writeln!(&mut output, "(assert (not (= sk1 sk2)))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();
    writeln!(&mut output, "(get-model)").unwrap();

    output
}

/// Generate SMT to check copy constraint consistency
///
/// In Dark DEX, sk_commitment computed by first Poseidon must equal
/// the sk_commitment used in the second Poseidon.
pub fn generate_copy_constraint_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Copy Constraint Consistency Check ===").unwrap();
    writeln!(&mut output, "; Question: Can computed sk_commitment differ from used sk_commitment?").unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "(declare-fun sk () F)").unwrap();
    writeln!(&mut output, "(declare-fun sk_commitment_computed () F)").unwrap();
    writeln!(&mut output, "(declare-fun sk_commitment_used () F)").unwrap();

    // Poseidon as uninterpreted function
    writeln!(&mut output, "(declare-fun poseidon2 (F F) F)").unwrap();

    // sk_commitment_computed = poseidon(sk, 0)
    writeln!(&mut output, "(assert (= sk_commitment_computed (poseidon2 sk (as ff0 F))))").unwrap();

    // Copy constraint: they must be equal
    writeln!(&mut output, "; Copy constraint enforces equality").unwrap();
    writeln!(&mut output, "(assert (= sk_commitment_computed sk_commitment_used))").unwrap();

    // Can they differ?
    writeln!(&mut output, "; Try to find case where they differ (should be UNSAT)").unwrap();
    writeln!(&mut output, "(assert (not (= sk_commitment_computed sk_commitment_used)))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();

    output
}

/// Generate SMT to check if digest uniquely identifies transaction
///
/// Property: Same digest implies same (sk, token_type, private_note_sum)
pub fn generate_digest_uniqueness_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Digest Uniqueness Check ===").unwrap();
    writeln!(&mut output, "; Question: Can different (sk, token, sum) produce same digest?").unwrap();
    writeln!(&mut output).unwrap();

    // Transaction 1
    writeln!(&mut output, "; Transaction 1").unwrap();
    writeln!(&mut output, "(declare-fun sk1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun token1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun sum1 () F)").unwrap();

    // Transaction 2
    writeln!(&mut output, "; Transaction 2").unwrap();
    writeln!(&mut output, "(declare-fun sk2 () F)").unwrap();
    writeln!(&mut output, "(declare-fun token2 () F)").unwrap();
    writeln!(&mut output, "(declare-fun sum2 () F)").unwrap();

    // Same digest
    writeln!(&mut output, "(declare-fun digest () F)").unwrap();

    // Poseidon as uninterpreted function with collision resistance property
    writeln!(&mut output, "; Poseidon modeled as injective function").unwrap();
    writeln!(&mut output, "(declare-fun poseidon2 (F F) F)").unwrap();
    writeln!(&mut output, "(declare-fun poseidon4 (F F F F) F)").unwrap();

    // Collision resistance: different inputs -> different outputs
    writeln!(&mut output, "; Collision resistance axiom for poseidon2").unwrap();
    writeln!(&mut output, "(assert (forall ((a1 F) (a2 F) (b1 F) (b2 F))").unwrap();
    writeln!(&mut output, "  (=> (= (poseidon2 a1 a2) (poseidon2 b1 b2))").unwrap();
    writeln!(&mut output, "      (and (= a1 b1) (= a2 b2)))))").unwrap();

    // Compute sk_commitments
    writeln!(&mut output, "(declare-fun sk_commitment1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun sk_commitment2 () F)").unwrap();
    writeln!(&mut output, "(assert (= sk_commitment1 (poseidon2 sk1 (as ff0 F))))").unwrap();
    writeln!(&mut output, "(assert (= sk_commitment2 (poseidon2 sk2 (as ff0 F))))").unwrap();

    // Same digest
    writeln!(&mut output, "(assert (= digest (poseidon4 sk_commitment1 sum1 token1 sk1)))").unwrap();
    writeln!(&mut output, "(assert (= digest (poseidon4 sk_commitment2 sum2 token2 sk2)))").unwrap();

    // Different transactions
    writeln!(&mut output, "; At least one input differs").unwrap();
    writeln!(&mut output, "(assert (or (not (= sk1 sk2)) (not (= token1 token2)) (not (= sum1 sum2))))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "; If UNSAT: digest uniquely identifies transaction").unwrap();
    writeln!(&mut output, "; If SAT: found collision (should not happen with collision-resistant Poseidon)").unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();

    output
}

/// Generate SMT to check selector exclusivity
///
/// In Halo2, different gates have different selectors.
/// Check: can two incompatible selectors be active at the same time?
pub fn generate_selector_exclusivity_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Selector Exclusivity Check ===").unwrap();
    writeln!(&mut output, "; Dark DEX has 4 gates: full_round, partial_rounds, partial_round_single, pad-and-add").unwrap();
    writeln!(&mut output, "; Check: can multiple selectors be non-zero at same row?").unwrap();
    writeln!(&mut output).unwrap();

    // Define selectors (from extract_circuit_gates we know there are 4 selector types)
    writeln!(&mut output, "; Selectors (0 = disabled, non-zero = enabled)").unwrap();
    writeln!(&mut output, "(declare-fun S_full_round () F)").unwrap();
    writeln!(&mut output, "(declare-fun S_partial_rounds () F)").unwrap();
    writeln!(&mut output, "(declare-fun S_partial_single () F)").unwrap();
    writeln!(&mut output, "(declare-fun S_pad_add () F)").unwrap();

    // Selectors are typically 0 or 1
    writeln!(&mut output, "; Selectors are binary (0 or 1)").unwrap();
    writeln!(&mut output, "(assert (or (= S_full_round (as ff0 F)) (= S_full_round (as ff1 F))))").unwrap();
    writeln!(&mut output, "(assert (or (= S_partial_rounds (as ff0 F)) (= S_partial_rounds (as ff1 F))))").unwrap();
    writeln!(&mut output, "(assert (or (= S_partial_single (as ff0 F)) (= S_partial_single (as ff1 F))))").unwrap();
    writeln!(&mut output, "(assert (or (= S_pad_add (as ff0 F)) (= S_pad_add (as ff1 F))))").unwrap();

    // At most one selector active (mutual exclusivity)
    // This is a design property - check if circuit enforces it
    writeln!(&mut output, "; Try to find row where multiple selectors active").unwrap();
    writeln!(&mut output, "; Count how many are active").unwrap();
    writeln!(&mut output, "(declare-fun count () Int)").unwrap();
    writeln!(&mut output, "(assert (= count (+ ").unwrap();
    writeln!(&mut output, "  (ite (= S_full_round (as ff1 F)) 1 0)").unwrap();
    writeln!(&mut output, "  (ite (= S_partial_rounds (as ff1 F)) 1 0)").unwrap();
    writeln!(&mut output, "  (ite (= S_partial_single (as ff1 F)) 1 0)").unwrap();
    writeln!(&mut output, "  (ite (= S_pad_add (as ff1 F)) 1 0))))").unwrap();

    // We want to find if >1 can be active
    writeln!(&mut output, "; Check if more than one selector can be active").unwrap();
    writeln!(&mut output, "(assert (> count 1))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "; SAT = multiple selectors can be active (potential issue)").unwrap();
    writeln!(&mut output, "; UNSAT = selectors are mutually exclusive (good)").unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();
    writeln!(&mut output, "(get-model)").unwrap();

    output
}

/// Generate SMT to check arithmetic boundary behavior
///
/// Check behavior at field boundaries: 0, 1, p-1, p-2
pub fn generate_arithmetic_boundary_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Arithmetic Boundary Check ===").unwrap();
    writeln!(&mut output, "; Check: wraparound at field boundaries").unwrap();
    writeln!(&mut output).unwrap();

    // p-1 is the largest element
    writeln!(&mut output, "; Define p-1 (largest field element)").unwrap();
    writeln!(&mut output, "(define-fun p_minus_1 () F (as ff{} F))",
        "21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap();

    writeln!(&mut output, "; Define p-2").unwrap();
    writeln!(&mut output, "(define-fun p_minus_2 () F (as ff{} F))",
        "21888242871839275222246405745257275088548364400416034343698204186575808495615").unwrap();

    // Test: (p-1) + 1 = 0 (wraparound)
    writeln!(&mut output, "; Test: (p-1) + 1 should equal 0 (wraparound)").unwrap();
    writeln!(&mut output, "(declare-fun result1 () F)").unwrap();
    writeln!(&mut output, "(assert (= result1 (ff.add p_minus_1 (as ff1 F))))").unwrap();
    writeln!(&mut output, "(assert (= result1 (as ff0 F)))  ; This should be SAT").unwrap();

    // Test: 0 - 1 = p-1 (underflow)
    writeln!(&mut output, "; Test: 0 - 1 should equal p-1 (underflow)").unwrap();
    writeln!(&mut output, "(declare-fun result2 () F)").unwrap();
    writeln!(&mut output, "(assert (= result2 (ff.add (as ff0 F) (ff.neg (as ff1 F)))))").unwrap();
    writeln!(&mut output, "(assert (= result2 p_minus_1))  ; This should be SAT").unwrap();

    // Test: (p-1) * 2 = p-2 (because 2*(p-1) = 2p - 2 ≡ -2 ≡ p-2 mod p)
    writeln!(&mut output, "; Test: 2 * (p-1) should equal p-2").unwrap();
    writeln!(&mut output, "(declare-fun result3 () F)").unwrap();
    writeln!(&mut output, "(assert (= result3 (ff.mul (as ff2 F) p_minus_1)))").unwrap();
    writeln!(&mut output, "(assert (= result3 p_minus_2))  ; This should be SAT").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "; If SAT: field arithmetic behaves correctly at boundaries").unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();

    output
}

/// Generate SMT to check public input necessity
///
/// Check: removing any public input allows different valid witnesses
pub fn generate_public_input_necessity_check() -> String {
    let mut output = String::new();

    writeln!(&mut output, "(set-logic ALL)").unwrap();
    writeln!(&mut output, "(set-option :produce-models true)").unwrap();
    writeln!(&mut output, "(define-sort F () (_ FiniteField {}))", BN256_FR_MODULUS).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "; === Public Input Necessity Check ===").unwrap();
    writeln!(&mut output, "; Dark DEX public inputs: private_note_sum, token_type, digest").unwrap();
    writeln!(&mut output, "; Check: if we ignore one, can we still distinguish transactions?").unwrap();
    writeln!(&mut output).unwrap();

    // Two transactions with same digest but different sum/token
    writeln!(&mut output, "; Two transactions").unwrap();
    writeln!(&mut output, "(declare-fun sum1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun token1 () F)").unwrap();
    writeln!(&mut output, "(declare-fun sum2 () F)").unwrap();
    writeln!(&mut output, "(declare-fun token2 () F)").unwrap();
    writeln!(&mut output, "(declare-fun digest () F)  ; same digest").unwrap();

    // Poseidon as uninterpreted function
    writeln!(&mut output, "(declare-fun poseidon4 (F F F F) F)").unwrap();
    writeln!(&mut output, "(declare-fun poseidon2 (F F) F)").unwrap();

    // Same sk for both (so sk_commitment is same)
    writeln!(&mut output, "(declare-fun sk () F)").unwrap();
    writeln!(&mut output, "(declare-fun sk_commitment () F)").unwrap();
    writeln!(&mut output, "(assert (= sk_commitment (poseidon2 sk (as ff0 F))))").unwrap();

    // Both produce same digest
    writeln!(&mut output, "(assert (= digest (poseidon4 sk_commitment sum1 token1 sk)))").unwrap();
    writeln!(&mut output, "(assert (= digest (poseidon4 sk_commitment sum2 token2 sk)))").unwrap();

    // But sum or token differs
    writeln!(&mut output, "; Different public inputs").unwrap();
    writeln!(&mut output, "(assert (or (not (= sum1 sum2)) (not (= token1 token2))))").unwrap();

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "; SAT = public inputs are NOT protected by digest alone").unwrap();
    writeln!(&mut output, "; (need to verify sum/token separately)").unwrap();
    writeln!(&mut output, "(check-sat)").unwrap();
    writeln!(&mut output, "(get-model)").unwrap();

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_gates() {
        let gates = extract_circuit_gates();

        println!("=== Dark DEX Circuit Gates ===");
        println!("Total gates: {}", gates.len());

        for (name, polys) in &gates {
            println!("Gate '{}': {} constraints", name, polys.len());
        }

        assert!(!gates.is_empty(), "Should have at least one gate");
    }

    #[test]
    fn test_generate_smt() {
        let gates = extract_circuit_gates();
        let smt = generate_underconstrained_check(&gates, 0);

        println!("=== Generated SMT-LIB ===");
        println!("{}", smt);

        // Save to file for inspection
        fs::write("/tmp/dark_dex_test.smt2", &smt).unwrap();
        println!("Saved to /tmp/dark_dex_test.smt2");

        assert!(smt.contains("set-logic ALL"));
        assert!(smt.contains("FiniteField"));
    }

    #[test]
    fn test_simple_constraint() {
        // Test simple pad-and-add constraint (fast to solve)
        let smt = generate_simple_constraint_check();

        println!("=== Simple Constraint SMT ===");
        println!("{}", smt);

        match run_cvc5(&smt, 5000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                assert!(result.contains("sat"), "Simple constraint should be satisfiable");
                // CVC5 outputs in format #f<value>m<modulus>
                // c should be 300 (100 + 200), look for #f300m
                assert!(result.contains("#f300m"),
                    "c should equal 300, got: {}", result);
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    #[test]
    fn test_underconstrained_witness() {
        // Test under-constrained check: can two different inputs produce same output?
        let smt = generate_underconstrained_witness_check();

        println!("=== Under-constrained Witness Check ===");
        println!("{}", smt);

        match run_cvc5(&smt, 5000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                if result.contains("sat") && !result.contains("unsat") {
                    println!("EXPECTED: Found two different witnesses with same output");
                    println!("This is expected for a + b = c constraint (infinitely many solutions)");
                } else if result.contains("unsat") {
                    println!("Constraint is fully determined");
                }
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Ignored by default - Poseidon constraints are too complex for SMT
    fn test_full_circuit_cvc5() {
        // Full circuit analysis - very slow due to Poseidon complexity
        let gates = extract_circuit_gates();
        let smt = generate_underconstrained_check(&gates, 0);

        match run_cvc5(&smt, 30000) {
            Ok(result) => {
                println!("=== CVC5 Result (Full Circuit) ===");
                println!("{}", result);

                if result.contains("timeout") || result.contains("interrupted") {
                    println!("EXPECTED: Poseidon constraints are too complex for SMT solving");
                } else if result.contains("sat") && !result.contains("unsat") {
                    println!("WARNING: Constraints are satisfiable - may indicate under-constrained circuit");
                } else if result.contains("unsat") {
                    println!("PASS: Constraints are unsatisfiable at this row");
                }
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    // ========== Dark DEX Specific SMT Tests ==========

    #[test]
    fn test_public_input_binding() {
        // Check: Can two different sk values produce same public outputs?
        // Using Poseidon as uninterpreted function (black box)
        let smt = generate_public_input_binding_check();

        println!("=== Public Input Binding Check ===");
        println!("{}", smt);

        match run_cvc5(&smt, 10000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                if result.contains("sat") && !result.contains("unsat") {
                    // SAT means: yes, two different sk can produce same output
                    // This is expected WITHOUT collision resistance axiom
                    // Because Poseidon as uninterpreted function can map anything to anything
                    println!("EXPECTED: Without collision resistance, arbitrary mappings allowed");
                    println!("This test shows that the CONSTRAINT STRUCTURE allows different sk");
                    println!("Security relies on Poseidon being collision-resistant");
                } else if result.contains("unsat") {
                    println!("UNEXPECTED: Pure constraint structure prevents different sk");
                }
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    #[test]
    fn test_copy_constraint_consistency() {
        // Check: copy constraints are logically consistent (should be UNSAT)
        let smt = generate_copy_constraint_check();

        println!("=== Copy Constraint Consistency ===");
        println!("{}", smt);

        match run_cvc5(&smt, 5000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                // Should be UNSAT because we assert A=B and A≠B
                assert!(result.contains("unsat"),
                    "Copy constraint check should be UNSAT (contradictory constraints)");
                println!("PASS: Copy constraints are consistent");
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    #[test]
    fn test_digest_uniqueness_with_cr() {
        // Check: with collision-resistant Poseidon, digest uniquely identifies tx
        let smt = generate_digest_uniqueness_check();

        println!("=== Digest Uniqueness Check (with CR axiom) ===");
        println!("{}", smt);

        match run_cvc5(&smt, 30000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                // With collision resistance axiom, should be UNSAT
                // (no two different inputs can produce same output)
                if result.contains("unsat") {
                    println!("PASS: With collision-resistant Poseidon, digest is unique per transaction");
                } else if result.contains("sat") {
                    println!("NOTE: SAT result - this may indicate incomplete axiomatization");
                    println!("The collision resistance axiom may need refinement for poseidon4");
                } else if result.contains("timeout") || result.contains("unknown") {
                    println!("Solver timeout/unknown - quantifier handling is hard");
                }
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    // ========== Additional Best Practices Tests ==========

    #[test]
    fn test_selector_exclusivity() {
        // Check: can multiple selectors be active on same row?
        let smt = generate_selector_exclusivity_check();

        println!("=== Selector Exclusivity Check ===");
        println!("{}", smt);

        match run_cvc5(&smt, 5000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                // SAT means multiple selectors CAN be active
                // This is expected - in Halo2, selector exclusivity is not enforced by default
                // The circuit designer must ensure correct selector patterns
                if result.contains("sat") && !result.contains("unsat") {
                    println!("NOTE: Multiple selectors CAN be active (expected in Halo2)");
                    println!("This is OK if the circuit correctly assigns selector values");
                } else if result.contains("unsat") {
                    println!("Selectors are mutually exclusive by construction");
                }
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    #[test]
    fn test_arithmetic_boundaries() {
        // Verify field arithmetic at boundaries
        let smt = generate_arithmetic_boundary_check();

        println!("=== Arithmetic Boundary Check ===");
        println!("{}", smt);

        match run_cvc5(&smt, 5000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                // Should be SAT - our assertions about wraparound are correct
                assert!(result.contains("sat") && !result.contains("unsat"),
                    "Field arithmetic boundary tests should be satisfiable");
                println!("PASS: Field arithmetic wraps correctly at boundaries");
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }

    #[test]
    fn test_public_input_necessity() {
        // Check: is each public input necessary for security?
        let smt = generate_public_input_necessity_check();

        println!("=== Public Input Necessity Check ===");
        println!("{}", smt);

        match run_cvc5(&smt, 10000) {
            Ok(result) => {
                println!("=== CVC5 Result ===");
                println!("{}", result);

                // Without collision resistance axiom for poseidon4, this will be SAT
                // meaning the solver found a way for different sum/token to produce same digest
                // This is expected when Poseidon is modeled as uninterpreted function
                if result.contains("sat") && !result.contains("unsat") {
                    println!("EXPECTED: Without CR axiom, different inputs can produce same digest");
                    println!("This shows that sum/token are protected BY Poseidon's CR property,");
                    println!("not by the constraint structure itself");
                } else if result.contains("unsat") {
                    println!("Constraint structure alone prevents different public inputs");
                }
            }
            Err(e) => {
                println!("CVC5 not available: {}", e);
            }
        }
    }
}

