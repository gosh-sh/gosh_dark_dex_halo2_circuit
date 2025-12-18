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

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};
use rand::rngs::OsRng;
use crate::circuit::*;

pub fn setup(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::new(k)
}

pub fn generate_proof_key(params: &ParamsKZG<Bn256>, token_type: Option<Fr>, private_note_sum: Option<Fr>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>) -> Result<ProvingKey<G1Affine>, Error>{
    let circuit: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::new(token_type, private_note_sum,  sk, pk, g);
    let vk = keygen_vk(params, &circuit).unwrap();
    keygen_pk(params, vk, &circuit)
}

pub fn generate_proof(params: &ParamsKZG<Bn256>, token_type: Option<Fr>, private_note_sum: Option<Fr>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>, token_type_pub_val: u64, private_note_sum_pub_val: u64) -> Vec<u8>{
    let circuit: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::new(token_type, private_note_sum,  sk, pk, g);
    let vk = keygen_vk(params, &circuit).unwrap();
    let pk = keygen_pk(params, vk, &circuit).unwrap();

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[Fr::from(token_type_pub_val), Fr::from(private_note_sum_pub_val)]]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof: Vec<u8> = transcript.finalize();
    proof
}