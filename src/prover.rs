use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Error},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer, Blake2bRead, Blake2bWrite, Challenge255},
};

use halo2_proofs::plonk::{VerifyingKey, ProvingKey};

use halo2_proofs::SerdeFormat;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};
use rand::rngs::OsRng;
use crate::circuit::*;

use std::time::{Instant, Duration};

pub fn setup(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::new(k)
}

pub fn setup_and_backup_kzg_params(k: u32, path: String) {
    let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
    let mut params_buf: Vec<u8> = Vec::new();
    let _ = params.write_custom(&mut params_buf, SerdeFormat::RawBytesUnchecked).unwrap();
    println!("KZG params len = {:?}", params_buf.len());
    std::fs::write(path, params_buf).unwrap();
}

pub fn read_kzg_params(path: String) -> ParamsKZG<Bn256>{
    let mut params_buf: Vec<u8> = std::fs::read(path).unwrap();
    let mut params_slice: &[u8] = &params_buf;
    let params  = ParamsKZG::<Bn256>::read_custom(&mut params_slice, SerdeFormat::RawBytesUnchecked).expect("Reading vkey should not fail");
    params
}

pub fn generate_proof_key(params: &ParamsKZG<Bn256>, token_type: Option<Fr>, private_note_sum: Option<Fr>, vault_rand_val: Option<Fr>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>) -> Result<ProvingKey<G1Affine>, Error>{
    let circuit: DarkDexCircuit = DarkDexCircuit::new(token_type, private_note_sum, vault_rand_val, sk, pk, g);
    let vk = keygen_vk(params, &circuit).unwrap();
    keygen_pk(params, vk, &circuit)
}


pub fn generate_proof(params: &ParamsKZG<Bn256>, token_type: Option<Fr>, private_note_sum: Option<Fr>, vault_rand_val: Option<Fr>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>, pub_inputs: &mut Vec<Fr>) -> Vec<u8>{
    let circuit: DarkDexCircuit = DarkDexCircuit::new( token_type, private_note_sum, vault_rand_val, sk, pk, g);

    let now = Instant::now();
    let vk = keygen_vk(params, &circuit).unwrap();
    let pk = keygen_pk(params, vk.clone(), &circuit).unwrap();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&pub_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    let end  = now.elapsed().as_millis();
    println!("proof generation time: {:?}", end);

     /*let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&params);


   let circuit_: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::default();
    let vk_from_empty = keygen_vk(params, &circuit_).unwrap();

    assert!(verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk_from_empty,
        strategy,
        &[&[&pub_inputs]],
        //&[&[]],
        &mut transcript,
    )
    .is_ok());*/


    proof
}

pub fn generate_verififcation_key_without_witness(params: &ParamsKZG<Bn256>) -> VerifyingKey<G1Affine>{
    let circuit: DarkDexCircuit = DarkDexCircuit::default();
    keygen_vk(params, &circuit).unwrap()
}

pub fn generate_verififcation_key_without_witness_and_backup(params: &ParamsKZG<Bn256>, path: String) {
    let circuit: DarkDexCircuit = DarkDexCircuit::default();
    let vk_from_empty = keygen_vk(params, &circuit).unwrap();
    let mut vk1_buf: Vec<u8> = Vec::new();
    vk_from_empty.write(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
    .unwrap();
    println!("vk1_buf len = {:?}", vk1_buf.len());
    std::fs::write(path, vk1_buf).unwrap();
}