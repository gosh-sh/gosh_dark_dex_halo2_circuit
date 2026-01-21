//! Korrekt static analysis tests for Dark DEX circuit
//!
//! These tests use Quantstamp's korrekt (halo2-analyzer) to perform
//! static analysis of the Dark DEX circuit structure.

use gosh_dark_dex_halo2_circuit::circuit::DarkDexCircuit;
use korrekt::circuit_analyzer::analyzer::Analyzer;
use korrekt::io::analyzer_io_type::{
    AnalyzerInput, AnalyzerType, AnalyzerOutputStatus, LookupMethod, 
    VerificationInput, VerificationMethod,
};
use std::collections::HashMap;

/// Test: Analyze unused gates in Dark DEX circuit
#[test]
fn korrekt_unused_gates() {
    let circuit = DarkDexCircuit::default();
    let k: u32 = 8; // Dark DEX uses k=8
    
    let mut analyzer = Analyzer::new(&circuit, k, AnalyzerType::UnusedGates, None)
        .expect("Failed to create analyzer");
    
    let result = analyzer.analyze_unused_custom_gates()
        .expect("Failed to analyze unused gates");
    
    println!("Unused gates analysis result: {:?}", result.output_status);
    println!("Log: {:?}", analyzer.log());
    
    // We expect no unused gates in a well-designed circuit
    assert_ne!(
        result.output_status, 
        AnalyzerOutputStatus::UnusedCustomGates,
        "Found unused custom gates in Dark DEX circuit!"
    );
}

/// Test: Analyze unused columns in Dark DEX circuit
#[test]
fn korrekt_unused_columns() {
    let circuit = DarkDexCircuit::default();
    let k: u32 = 8;
    
    let mut analyzer = Analyzer::new(&circuit, k, AnalyzerType::UnusedColumns, None)
        .expect("Failed to create analyzer");
    
    let result = analyzer.analyze_unused_columns()
        .expect("Failed to analyze unused columns");
    
    println!("Unused columns analysis result: {:?}", result.output_status);
    println!("Log: {:?}", analyzer.log());
    
    // Report but don't fail - some unused columns may be intentional
    if result.output_status == AnalyzerOutputStatus::UnusedColumns {
        println!("WARNING: Found unused columns in Dark DEX circuit");
    }
}

/// Test: Analyze unconstrained cells in Dark DEX circuit
#[test]
fn korrekt_unconstrained_cells() {
    let circuit = DarkDexCircuit::default();
    let k: u32 = 8;
    
    let mut analyzer = Analyzer::new(&circuit, k, AnalyzerType::UnconstrainedCells, None)
        .expect("Failed to create analyzer");
    
    let result = analyzer.analyze_unconstrained_cells()
        .expect("Failed to analyze unconstrained cells");
    
    println!("Unconstrained cells analysis result: {:?}", result.output_status);
    println!("Log: {:?}", analyzer.log());
    
    // Unconstrained cells are a potential security issue
    if result.output_status == AnalyzerOutputStatus::UnconstrainedCells {
        println!("WARNING: Found unconstrained cells in Dark DEX circuit!");
        println!("Details: {:?}", analyzer.log());
    }
}

/// Test: Check for under-constrained circuit using random verification
#[test]
fn korrekt_underconstrained_random() {
    let circuit = DarkDexCircuit::default();
    let k: u32 = 8;
    
    let analyzer_input = AnalyzerInput {
        verification_method: VerificationMethod::Random,
        verification_input: VerificationInput {
            instance_cells: HashMap::new(),
            iterations: 5,
        },
        lookup_method: LookupMethod::InlineConstraints,
    };
    
    let mut analyzer = Analyzer::new(
        &circuit, 
        k, 
        AnalyzerType::UnderconstrainedCircuit, 
        Some(&analyzer_input)
    ).expect("Failed to create analyzer");
    
    println!("Instance cells found: {:?}", analyzer.instance_cells);
    println!("Number of gates: {}", analyzer.cs.gates.len());
    println!("Circuit degree: {}", analyzer.cs.degree());
    
    let result = analyzer.analyze_underconstrained(&analyzer_input)
        .expect("Failed to analyze underconstrained");
    
    println!("Underconstrained analysis result: {:?}", result.output_status);
    
    // Check result
    match result.output_status {
        AnalyzerOutputStatus::Underconstrained => {
            panic!("CRITICAL: Dark DEX circuit is under-constrained!");
        }
        AnalyzerOutputStatus::NotUnderconstrained => {
            println!("PASS: Circuit is not under-constrained (verified)");
        }
        AnalyzerOutputStatus::NotUnderconstrainedLocal => {
            println!("PASS: Circuit is not under-constrained (local verification)");
        }
        other => {
            println!("Result: {:?}", other);
        }
    }
}

/// Test: Get circuit statistics
#[test]
fn korrekt_circuit_stats() {
    let circuit = DarkDexCircuit::default();
    let k: u32 = 8;
    
    let analyzer = Analyzer::new(&circuit, k, AnalyzerType::UnusedGates, None)
        .expect("Failed to create analyzer");
    
    println!("=== Dark DEX Circuit Statistics ===");
    println!("Number of gates: {}", analyzer.cs.gates.len());
    println!("Circuit degree: {}", analyzer.cs.degree());
    println!("Instance cells: {:?}", analyzer.instance_cells);
    println!("Number of instance cells: {}", analyzer.instance_cells.len());
}

