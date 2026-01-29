use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{Circuit, Error, create_proof, keygen_pk, keygen_vk, verify_proof},
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
};

use halo2_proofs::plonk::*;

use crate::proof::*;
use halo2_proofs::SerdeFormat;
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};

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

pub fn setup(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::new(k)
}

pub fn setup_and_backup_kzg_params(k: u32, path: String) {
    let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
    let mut params_buf: Vec<u8> = Vec::new();
    let _ = params
        .write_custom(&mut params_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();
    println!("KZG params len = {:?}", params_buf.len());
    std::fs::write(path, params_buf).unwrap();
}

pub fn read_kzg_params(path: String) -> ParamsKZG<Bn256> {
    let mut params_buf: Vec<u8> = std::fs::read(path).unwrap();
    let mut params_slice: &[u8] = &params_buf;
    //println!("KZG params_slice = {:?}", params_slice);
    //println!("KZG params len = {:?}", params_slice.len());
    let params = ParamsKZG::<Bn256>::read_custom(&mut params_slice, SerdeFormat::RawBytesUnchecked)
        .expect("Reading vkey should not fail");
    params
}

pub fn get_params<C: Circuit<Fr>>(
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

pub fn generate_verififcation_key_without_witness<C: Circuit<Fr> + Default>(
    params: &ParamsKZG<Bn256>,
) -> VerifyingKey<G1Affine> {
    let circuit = C::default();
    keygen_vk(params, &circuit).unwrap()
}

pub fn generate_verififcation_key_without_witness_and_backup<C: Circuit<Fr> + Default>(
    params: &ParamsKZG<Bn256>,
    path: String,
) {
    let circuit = C::default();
    let vk_from_empty = keygen_vk(params, &circuit).unwrap();
    let mut vk1_buf: Vec<u8> = Vec::new();
    vk_from_empty
        .write(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();
    //println!("vk1_buf len = {:?}", vk1_buf.len());

    //println!("vk1 = {:?}", hex::encode(vk1_buf.clone()));
    std::fs::write(path, vk1_buf).unwrap();
}
