use std::io::Cursor;

use halo2_base::{gates::circuit::BaseCircuitParams, halo2_proofs::{
    SerdeFormat, circuit::Value, halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        pairing::Engine,
    }, plonk::{self, Circuit, ProvingKey, VerifyingKey}, poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK}, strategy::SingleStrategy,
        },
    }, transcript::{Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer}
}};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use halo2_base::utils::testing::{gen_proof, gen_proof_with_instances, check_proof, check_proof_with_instances};
use std::panic;

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    rc::Rc,
};
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage};
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::AssignedValue;
use halo2_base::gates::RangeChip;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof(pub Vec<u8>);

impl Proof {

    pub fn create_for_curcuit_builder_(
        k: u32, 
        use_instance_columns: bool,
        num_instance_columns: usize,
        params: &ParamsKZG<Bn256>,
        break_points: Vec<Vec<usize>>, 
        config_params: BaseCircuitParams, 
        pk_bytes: Vec<u8>, 
        pub_inputs: &[&[Fr]],
        f: impl FnOnce(&mut SinglePhaseCoreManager<Fr>, &RangeChip<Fr>) -> Vec<Vec<AssignedValue<Fr>>>
    )  -> Self {
        let lookup_bits = k as usize - 1;
        let mut pk_slice: &[u8] = &pk_bytes;
        let pk: ProvingKey<G1Affine> = ProvingKey::read::<_, BaseCircuitBuilder<Fr>>(&mut pk_slice, SerdeFormat::RawBytesUnchecked, config_params.clone()).expect("Reading pkey should not fail");

        let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points).use_instance_columns(num_instance_columns);
        let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());

        if (use_instance_columns) {
            let instances = f(builder.pool(0), &range);
            assert!(instances.len() == num_instance_columns);
            for i in 0..instances.len() {
                builder.assigned_instances[i] = instances[i].clone();
            }
        }
        else {
            f(builder.pool(0), &range);
        }

        let proof = gen_proof_with_instances(&params, &pk, builder, pub_inputs);
    
        let proof_size = proof.len();

        println!("proof: {:?}", proof);

        Self{0: proof}

    }

    pub fn create_for_curcuit_builder(
        k: u32, 
        use_instance_columns: bool,
        num_instance_columns: usize,
        params: &ParamsKZG<Bn256>,
        break_points_path: String, 
        config_params_path: String, 
        proof_key_path: String, 
        pub_inputs: &[&[Fr]],
        f: impl FnOnce(&mut SinglePhaseCoreManager<Fr>, &RangeChip<Fr>) -> Vec<Vec<AssignedValue<Fr>>>
    )  -> Self {
        let lookup_bits = k as usize - 1;

        let mut file = File::open(config_params_path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let config_params:  BaseCircuitParams = serde_json::from_str(&contents).expect("JSON was not well-formatted");
        println!("config_params: {:?}", config_params);

        let mut pk_bytes: Vec<u8> = std::fs::read(proof_key_path).unwrap();
        let mut pk_slice: &[u8] = &pk_bytes;
        let pk: ProvingKey<G1Affine> = ProvingKey::read::<_, BaseCircuitBuilder<Fr>>(&mut pk_slice, SerdeFormat::RawBytesUnchecked, config_params.clone()).expect("Reading pkey should not fail");

        let mut file = File::open(break_points_path).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        if buffer.len() % 2 != 0 {
            panic!("bad len");
        }

        let mut break_points = Vec::with_capacity(buffer.len() / 2);
        for chunk in buffer.chunks_exact(2) {
            // convert 2 bytes back to u16 assuming little-endian
            let value = u16::from_le_bytes([chunk[0], chunk[1]]);
            break_points.push(value as usize);
        }
        println!("break_points: {:?}", break_points);

        let mut break_points_: Vec<Vec<usize>> = vec![];
        break_points_.push(break_points);

        println!("break_points_: {:?}", break_points_);

        let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points_).use_instance_columns(num_instance_columns);
        let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());

        if (use_instance_columns) {
            let instances = f(builder.pool(0), &range);
            assert!(instances.len() == num_instance_columns);
            for i in 0..instances.len() {
                builder.assigned_instances[i] = instances[i].clone();
            }
        }
        else {
            f(builder.pool(0), &range);
        }

        let proof = gen_proof_with_instances(&params, &pk, builder, pub_inputs);
    
        let proof_size = proof.len();

        println!("proof: {:?}", proof);

        Self{0: proof}

    }

    /*pub fn create<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        circuit: C,
        pub_inputs: &Vec<Fr>,
    ) -> Self {
        Self {0: gen_proof_with_instances(&params, &pk, circuit, &[pub_inputs])}
    }*/

    pub fn verify_with_vk_from_bytes<C: Circuit<Fr>>(
        &self,
        mut vk_slice: &[u8],
        params: &ParamsKZG<Bn256>,
        concrete_params: C::Params,
        pub_inputs: &[&[Fr]],
    ) -> bool  {
        let vk: VerifyingKey<G1Affine> = VerifyingKey::read::<_, C>(&mut vk_slice, SerdeFormat::RawBytesUnchecked, concrete_params).expect("Reading vkey should not fail");
        ;
        match panic::catch_unwind(|| {
            check_proof_with_instances(&params, &vk, &self.0.clone(), pub_inputs,  true);
        }) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

   pub fn verify_with_vk_from_path<C: Circuit<Fr>>(
        &self,
        vk_path: String,
        params: &ParamsKZG<Bn256>,
        concrete_params: C::Params,
        pub_inputs: &[&[Fr]],
    ) -> bool {
        let mut vk_slice: &[u8] = &std::fs::read(vk_path).unwrap();
        self.verify_with_vk_from_bytes::<C>(vk_slice, params, concrete_params, pub_inputs)
    }


    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn value(&self) -> Value<&[u8]> {
        Value::known(self.as_bytes())
    }
}
