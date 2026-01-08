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

use std::time::{Instant, Duration};

use halo2_proofs::plonk::{VerifyingKey, ProvingKey};

use halo2_proofs::SerdeFormat;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};
use rand::rngs::OsRng;
use crate::circuit::*;

pub fn verification_key_from_bytes(mut slice: &[u8]) -> VerifyingKey<G1Affine> {
    let vk: VerifyingKey<G1Affine> = VerifyingKey::read::<_, DarkDexCircuit>(&mut slice, SerdeFormat::RawBytesUnchecked).expect("Reading vkey should not fail");
    vk
}


pub fn verification_key_from_path(path: String) -> VerifyingKey<G1Affine> {
    let mut vk_bytes: Vec<u8> = std::fs::read(path).unwrap();
    let mut slice: &[u8] = &vk_bytes;
    println!("vk_bytes len = {:?}", vk_bytes.len());
    let vk: VerifyingKey<G1Affine> = VerifyingKey::read::<_, DarkDexCircuit>(&mut slice, SerdeFormat::RawBytesUnchecked).expect("Reading vkey should not fail");
    vk
}

pub fn verify_proof_(params: &ParamsKZG<Bn256>, proof: &[u8], vk: &VerifyingKey<G1Affine>, pub_inputs: Vec<Fr>) -> bool {
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let now = Instant::now();
    let res = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&pub_inputs]],
        //&[&[]],
        &mut transcript,
    )
    .is_ok();
    let end = now.elapsed().as_millis();
    println!("proof generation time: {:?}", end);
    res
}

