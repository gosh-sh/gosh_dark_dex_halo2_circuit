use halo2_base::halo2_proofs::{
    
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{Circuit, Error, create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat
};

use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::AssignedValue;

use crate::proof::*;

use crate::circuit::*;
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fp, Fq, Secp256k1Affine},
    },
    plonk::Fixed,
};
use rand::rngs::OsRng;

use std::time::{Duration, Instant};

use halo2_base::gates::RangeChip;

use halo2_base::gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage};


use std::{
    fs::File,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    path::Path,
    rc::Rc,
};

pub fn read_kzg_params(path: String) -> ParamsKZG<Bn256> {
    let mut params_buf: Vec<u8> = std::fs::read(path).unwrap();
    let mut params_slice: &[u8] = &params_buf;
    let params = ParamsKZG::<Bn256>::read_custom(&mut params_slice, SerdeFormat::RawBytesUnchecked)
        .expect("Reading vkey should not fail");
    params
}

/*pub fn setup(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::new(k)
}

pub fn setup_and_backup_kzg_params(k: u32, path: String) -> ParamsKZG<Bn256> {
    let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
    let mut params_buf: Vec<u8> = Vec::new();
    let _ = params
        .write_custom(&mut params_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();
    println!("KZG params len = {:?}", params_buf.len());
    std::fs::write(path, params_buf).unwrap();
    params
}
*/

/*pub fn generate_keys<C: Circuit<Fr>>(
    k: u32,
    circuit: &C,
) -> (
    ParamsKZG<Bn256>,
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    let params = setup(k);
    let vk = keygen_vk(&params, circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("keygen_pk should not fail");

    (params, vk, pk)
}


pub fn get_params_with_kzg_path<C: Circuit<Fr>>(
    path: String,
    circuit: &C,
) -> (
    ParamsKZG<Bn256>,
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    let params = read_kzg_params(path);
    let vk = keygen_vk(&params, circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), circuit).expect("keygen_pk should not fail");
    (params, vk, pk)
}

pub fn generate_verification_key_without_witness<C: Circuit<Fr> + Default>(
    params: &ParamsKZG<Bn256>,
) -> VerifyingKey<G1Affine> {
    let circuit = C::default();
    keygen_vk(params, &circuit).unwrap()
}

pub fn generate_verification_key_without_witness_and_backup<C: Circuit<Fr> + Default>(
    params: &ParamsKZG<Bn256>,
    path: String,
) {
    let circuit = C::default();
    let vk = keygen_vk(params, &circuit).unwrap();
    let mut vk_buf: Vec<u8> = Vec::new();
    vk.write(&mut vk_buf, SerdeFormat::RawBytesUnchecked).unwrap();
    std::fs::write(path.to_string(), vk_buf).unwrap();
}*/

pub fn generate_keys_and_backup_for_circuit_builder(
    k: u32,
    use_instance_columns: bool,
    num_instance_columns: usize,
    unusable_rows: usize,
    params: &ParamsKZG<Bn256>,
    verification_key_path: String,
    proof_key_path: String,
    break_points_path: String,
    config_params_path: String,
    f: impl FnOnce(&mut SinglePhaseCoreManager<Fr>, &RangeChip<Fr>) -> Vec<Vec<AssignedValue<Fr>>>
) {
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(k as usize);
    if use_instance_columns {
        builder = builder.use_instance_columns(num_instance_columns as usize)
    };
    let lookup_bits = k as usize - 1;
    builder.set_lookup_bits(lookup_bits);
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
 
    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let lookup_bits_ = if t_cells_lookup == 0 { None } else { Some(lookup_bits) };
    builder.config_params.lookup_bits = lookup_bits_;

    let config_params = builder.calculate_params(Some(unusable_rows));
    let config_params_json = serde_json::to_string(&config_params).unwrap();
    println!("config_params_json: {:?}", config_params_json);
    let mut file = File::create(config_params_path).unwrap();
    file.write_all(config_params_json.as_bytes()).unwrap();
    
    let vk = keygen_vk(params, &builder).unwrap();
    let pk = keygen_pk(params, vk.clone(), &builder).unwrap();

    let mut vk_buf: Vec<u8> = Vec::new();
    vk
        .write(&mut vk_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write(verification_key_path.to_string(), vk_buf).unwrap();

    let mut pk_buf: Vec<u8> = Vec::new();
    pk
        .write(&mut pk_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write(proof_key_path.to_string(), pk_buf).unwrap();

    let break_points = builder.break_points();
    println!("break_points: {:?}", break_points.len());
    assert!(break_points.len() == 1);
    println!("break_points: {:?}", break_points[0].len());
    println!("break_points: {:?}", break_points);
    drop(builder);

    assert!(break_points.len() == 1);
    let break_points_ = break_points[0].clone();
    let mut file = File::create(break_points_path.to_string()).unwrap();
    for value in break_points_ {
        let v = value as u16;
        file.write_all(&value.to_le_bytes()[0..2]).unwrap();
    }
}
