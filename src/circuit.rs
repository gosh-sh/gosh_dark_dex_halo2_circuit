use crate::proof::*;
use crate::poseidon::*;
use std::marker::PhantomData;

use halo2_base::AssignedValue;
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::{Fr, Bn256}},
    plonk::Fixed,
};
use halo2_base::utils::BigPrimeField;
use rand::random;
use halo2_ecc::fields::FpStrategy;

use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;

use halo2_base::gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage};
use std::fs::File;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde::Deserialize;

use halo2_base::gates::circuit::builder::*;
use halo2_base::gates::circuit::BaseCircuitParams;

use halo2_base::gates::RangeChip;

use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;


use halo2_ecc::secp256k1::FqChip;
use halo2_ecc::secp256k1::FpChip;

use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::FieldChip;
use halo2_ecc::ecc::fixed_base;
use halo2_ecc::ecc::scalar_multiply;

use halo2_base::{
    Context,
    utils::{CurveAffineExt},
};
use rand_core::OsRng;
use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};

use halo2_base::halo2_proofs::{
    
    circuit::SimpleFloorPlanner,
    circuit::Layouter,
    circuit::Value,
    dev::MockProver,
    halo2curves::secp256k1,
    halo2curves::bn256,
    plonk::{keygen_pk, keygen_vk},
    plonk::{self, Advice, ConstraintSystem, Circuit, Column, Instance, Expression, Selector},
    poly::kzg::commitment::{ParamsKZG}
};
use halo2_base::gates::RangeInstructions;


//#[derive(Default)]
pub struct DarkDexCircuit {
    pub k: u32,
    pub unusable_rows: usize,
    pub lookup_bits: usize,
    pub token_type: Fr,
    pub private_note_sum: Fr,
    pub sk_u: Fr,
    pub sk_u_commitment: Fr,
}

impl DarkDexCircuit {

    pub fn default( k: u32, unusable_rows: usize,) -> Self {
        let lookup_bits = k as usize - 1;
        let sk_u = Fr::zero();
        let token_type = Fr::zero();
        let private_note_sum = Fr::zero();
        let sk_u_commitment = poseidon_hash(&[Fr::zero(), Fr::zero()]);
        Self {
            k,
            unusable_rows,
            lookup_bits,
            token_type,
            private_note_sum,
            sk_u,
            sk_u_commitment
        }
    }

    pub fn new(
        k: u32,
        unusable_rows: usize,
        token_type: Fr,
        private_note_sum: Fr,
        sk_u: Fr,
        sk_u_commitment: Fr,
    ) -> Self {
        let lookup_bits = k as usize - 1;
        Self {
            k,
            unusable_rows,
            lookup_bits,
            token_type,
            private_note_sum,
            sk_u,
            sk_u_commitment
        }
    }

    pub fn create_mock(&self) -> BaseCircuitBuilder<Fr> {
        let mut builder = RangeCircuitBuilder::default().use_k(self.k as usize).use_instance_columns(1 as usize);
        builder.set_lookup_bits(self.lookup_bits);
        let range = RangeChip::new(self.lookup_bits, builder.lookup_manager().clone());
        let mut instances = self.closure(builder.pool(0), &range);
        builder.assigned_instances[0] = instances;
        builder
    }
 
    pub fn closure(&self, core: &mut SinglePhaseCoreManager<Fr>, range: &RangeChip<Fr>) -> Vec<AssignedValue<Fr>>{
        let ctx = core.main();

        let values = [self.sk_u, Fr::zero()];
        let inputs = ctx.assign_witnesses(values.clone());
        let len = ctx.load_witness(Fr::from(inputs.len() as u64));

        let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
        let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
        hasher.initialize_consts(ctx, range.gate());
        let hasher_result = hasher.hash_var_len_array(ctx, range, &inputs, len);

        let values = [self.sk_u_commitment];
        let sk_u_commitment_cell = ctx.assign_witnesses(values.clone())[0];

        ctx.constrain_equal(&sk_u_commitment_cell,&hasher_result);

        let values = [self.private_note_sum, self.token_type, self.sk_u];
        let mut inputs_ = ctx.assign_witnesses(values.clone());
        let mut inputs = vec![sk_u_commitment_cell];
        inputs.append(&mut inputs_);
        let len = ctx.load_witness(Fr::from(inputs.len() as u64));
        let final_hasher_result = hasher.hash_var_len_array(ctx, range, &inputs, len);

        println!("final_hasher_result = {:?}", final_hasher_result.value());

        let values = [self.private_note_sum, self.token_type];
        let mut instances = ctx.assign_witnesses(values.clone());
        instances.push(final_hasher_result);
        return instances;
        
    }

    pub fn public_inputs(&self) -> Vec<Vec<Fr>> {
        let data_to_hash = [
            self.sk_u_commitment,
            self.private_note_sum,
            self.token_type,
            self.sk_u,
        ];

        let digest = poseidon_hash(&data_to_hash);

        println!("digest {:?}", digest);

        vec![vec![self.private_note_sum, self.token_type, digest]]
    }
}

pub fn generate_dark_dex_proof(
    k: u32,
    unusable_rows: usize,
    params: &ParamsKZG<Bn256>,
    token_type: Fr,
    private_note_sum: Fr,
    sk_u: Fr,
    sk_u_commitment: Fr,
    break_points_path: String, 
    config_params_path: String, 
    proof_key_path: String, 
) -> Result<Proof, plonk::Error> {
    let f = |core: &mut SinglePhaseCoreManager<Fr>, range: &RangeChip<Fr>| -> Vec<Vec<AssignedValue<Fr>>>{
        let circuit: DarkDexCircuit = DarkDexCircuit::new(k, unusable_rows, token_type, private_note_sum, sk_u, sk_u_commitment);
        let res = circuit.closure(core, range);
        vec![res]
    };
    let data_to_hash = [sk_u_commitment, private_note_sum, token_type, sk_u];
    let digest = poseidon_hash(&data_to_hash);
    let mut pub_inputs: Vec<Fr> = vec![private_note_sum, token_type, digest];

    let proof = Proof::create_for_curcuit_builder(k, true, 1, &params, break_points_path, config_params_path, proof_key_path, &[&pub_inputs], f);
    
    Ok(proof)
}

#[test]
fn simple_test() {
    let k = 12u32;
    let unusable_rows = 9;

    let sk_u = Fr::from(random::<u64>());
    let token_type = Fr::from(1u64);
    let private_note_sum = Fr::from(1000u64);
    let sk_u_commitment = poseidon_hash(&[sk_u, Fr::zero()]);

    println!("sk_u_commitment {:?}", sk_u_commitment);

    let circuit: DarkDexCircuit = DarkDexCircuit::new(k, unusable_rows, token_type, private_note_sum, sk_u, sk_u_commitment);
    let mut builder = circuit.create_mock();
    let unusable_rows = 9;

    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
        
    let lookup_bits = if t_cells_lookup == 0 { None } else { builder.lookup_bits() };
    builder.config_params.lookup_bits = lookup_bits;

    builder.calculate_params(Some(unusable_rows));
        
    MockProver::run(k, &builder, circuit.public_inputs()).unwrap().assert_satisfied();

    let invalid_instances = vec![vec![Fr::one(), Fr::one(), Fr::one()]];

    assert!(MockProver::run(k, &builder, invalid_instances).unwrap().verify().is_ok() == false);

}
