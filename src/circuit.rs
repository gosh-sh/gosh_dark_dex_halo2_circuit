use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};
use halo2_base::utils::BigPrimeField;
use rand::random;
use halo2_ecc::fields::FpStrategy;

use std::fs::File;

use serde::Serialize;
use serde::Deserialize;

use halo2_base::gates::circuit::builder::*;

use halo2_base::gates::RangeChip;

use halo2_ecc::secp256k1::FqChip;
use halo2_ecc::secp256k1::FpChip;

use halo2_ecc::ecc::EccChip;
use halo2_ecc::fields::FieldChip;
use halo2_ecc::ecc::fixed_base;
use halo2_ecc::ecc::scalar_multiply;

use halo2_base::{
    utils::{CurveAffineExt},
};

use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};

use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    circuit::Layouter,
    circuit::Value,
    dev::MockProver,
    halo2curves::secp256k1,
    halo2curves::bn256,
    plonk::{self, Advice, ConstraintSystem, Circuit, Column, Instance, Expression, Selector},
};
use halo2_base::gates::RangeInstructions;
use pse_poseidon::Poseidon;
const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

pub fn poseidon_hash(message: &[Fr]) -> Fr {
    let mut native_sponge = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    native_sponge.update(message);
    native_sponge.squeeze()
}

//#[derive(Default)]
struct DarkDexCircuit {
    pub k: u32,
    pub lookup_bits: usize,
    pub token_type: Fr,
    pub private_note_sum: Fr,
    pub sk_u: Fr,
    pub sk_u_commitment: Fr,
}

impl DarkDexCircuit {

    pub fn new(
        k: u32,
        token_type: Fr,
        private_note_sum: Fr,
        sk_u: Fr,
        sk_u_commitment: Fr,
    ) -> Self {
        let lookup_bits = k as usize - 1;
        Self {
            k,
            lookup_bits,
            token_type,
            private_note_sum,
            sk_u,
            sk_u_commitment
        }
    }

    pub fn create(&self) -> BaseCircuitBuilder<Fr> {
        let mut builder = RangeCircuitBuilder::default().use_k(self.k as usize).use_instance_columns(1 as usize);
        builder.set_lookup_bits(self.lookup_bits);

        let range = RangeChip::new(self.lookup_bits, builder.lookup_manager().clone());

        let ctx = builder.pool(0).main();

        let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
        let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
        hasher.initialize_consts(ctx, range.gate());

        let values = [self.sk_u, Fr::zero()];
        let inputs = ctx.assign_witnesses(values.clone());
        let len = ctx.load_witness(Fr::from(inputs.len() as u64));
        let hasher_result = hasher.hash_var_len_array(ctx, &range, &inputs, len);

        let values = [self.sk_u_commitment];
        let sk_u_commitment_cell = ctx.assign_witnesses(values.clone())[0];

        ctx.constrain_equal(&sk_u_commitment_cell,&hasher_result);

        let values = [self.private_note_sum, self.token_type, self.sk_u];
        let mut inputs_ = ctx.assign_witnesses(values.clone());
        let mut inputs = vec![sk_u_commitment_cell];
        inputs.append(&mut inputs_);
        let len = ctx.load_witness(Fr::from(inputs.len() as u64));
        let final_hasher_result = hasher.hash_var_len_array(ctx, &range, &inputs, len);

        println!("final_hasher_result = {:?}", final_hasher_result.value());


        let values = [self.private_note_sum, self.token_type];
        let mut instances = ctx.assign_witnesses(values.clone());
        instances.push(final_hasher_result);

        builder.assigned_instances[0] = instances;

        builder

    }
}

/*pub fn generate_proof(
    params: &ParamsKZG<Bn256>,
    token_type: Option<Fr>,
    private_note_sum: Option<Fr>,
    sk_u: Option<Fr>,
    sk_u_commitment: Option<Fr>,
) -> Result<Proof, plonk::Error> {
    let circuit: DarkDexCircuit =
        DarkDexCircuit::new(token_type, private_note_sum, sk_u, sk_u_commitment);
    let now = Instant::now();
    let vk = keygen_vk(params, &circuit).unwrap();
    let pk = keygen_pk(params, vk.clone(), &circuit).unwrap();
    let public_inputs = circuit.public_inputs();
    let proof = Proof::create(&params, &pk, circuit, &[&public_inputs], OsRng);
    let end = now.elapsed().as_millis();
    //println!("Dark Dex circuit proof generation time: {:?}", end);
    proof
}*/

#[test]
fn simple_test() {
    let k = 12u32;
    let sk_u = random::<u64>();
    let token_type = 1u64;
    let private_note_sum = 1000u64;

    println!("sk_u = {:#x}", sk_u);

    let sk_u = Fr::from(sk_u);
    let token_type = Fr::from(token_type);
    let private_note_sum = Fr::from(private_note_sum);
    let sk_u_commitment = poseidon_hash(&[sk_u, Fr::zero()]);

    println!("sk_u_commitment {:?}", sk_u_commitment);

    let circuit: DarkDexCircuit = DarkDexCircuit::new(k, token_type, private_note_sum, sk_u, sk_u_commitment);
    let mut builder = circuit.create();
    let unusable_rows = 9;

    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
        
    let lookup_bits = if t_cells_lookup == 0 { None } else { builder.lookup_bits() };
    builder.config_params.lookup_bits = lookup_bits;

    builder.calculate_params(Some(unusable_rows));

     let data_to_hash = [
        sk_u_commitment,
        private_note_sum,
        token_type,
        sk_u,
    ];

    let digest = poseidon_hash(&data_to_hash);

    println!("digest {:?}", digest);

    let instances = vec![vec![private_note_sum, token_type, digest]];
        
    MockProver::run(k, &builder, instances).unwrap().assert_satisfied();
}
