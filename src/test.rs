use crate::circuit::*;
use crate::proof::*;
use crate::snark_utils::*;
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        bn256::Fr,
        secp256k1::{Fp, Fq, Secp256k1Affine},
    },
    plonk::Fixed,
};
use halo2_base::halo2_proofs::{
    circuit::Layouter,
    circuit::SimpleFloorPlanner,
    circuit::Value,
    dev::MockProver,
    halo2curves::bn256,
    halo2curves::secp256k1,
    plonk::{self, Advice, Circuit, Column, ConstraintSystem, Expression, Instance, Selector},
};
use halo2_proofs::SerdeFormat;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{Error, create_proof, keygen_pk, keygen_vk, verify_proof},
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

use halo2_base::utils::ScalarField;
use rand::random;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    path::Path,
    rc::Rc,
};

use rand::rngs::OsRng;

use halo2_ecc::fields::PrimeField as OtherPrimeField;

#[test]
fn test () {
   // let data_to_hash = [sk_u_commitment, private_note_sum, token_type, sk_u];

    //let input_bytes = [0u8; 32];
    //let t = [Fr::from_bytes(&input_bytes).unwrap()];

    let t2 = Fr::from(0u64);
    println!("t2: {:?}", t2.to_bytes());
    let digest = poseidon_hash([Fr::zero()]);

    println!("{:?}", hex::encode(digest.to_bytes()));

   
}

#[test]
fn kzg_test_raw() {
    let sk_u = random::<u64>();
    let token_type = 1u64;
    let private_note_sum = 1000u64;

    println!("sk_u = {:#x}", sk_u);

    let sk_u = Fr::from(sk_u);
    let token_type = Fr::from(token_type);
    let private_note_sum = Fr::from(private_note_sum);

    let sk_u_commitment = poseidon_hash([sk_u, Fr::zero()]);

    let data_to_hash = [sk_u_commitment, private_note_sum, token_type, sk_u];

    let digest = poseidon_hash(data_to_hash);

    let mut pub_inputs = vec![private_note_sum, token_type, digest];

    //////

    let params: ParamsKZG<Bn256> = setup(8);
    let circuit: DarkDexCircuit = DarkDexCircuit::new(
        Some(token_type),
        Some(private_note_sum),
        Some(sk_u),
        Some(sk_u_commitment),
    );

    //let prover = MockProver::run(8, &circuit, vec![pub_inputs.clone()]).unwrap();
    //assert_eq!(prover.verify(), Ok(()));

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&pub_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail!");

    let proof: Vec<u8> = transcript.finalize();

    println!("proof len = {:?}", proof.len());

    let empty_circuit: DarkDexCircuit = DarkDexCircuit::default();
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk_from_empty,
            strategy,
            &[&[&pub_inputs]],
            //&[&[]],
            &mut transcript,
        )
        .is_ok()
    );
}

/////////////////
#[test]
fn generate_and_backup_kzg_params_test() {
    let k = 8;
    setup_and_backup_kzg_params(k, "kzg_params.bin".to_string());
}

#[test]
fn generate_and_backup_verification_key_test() {
    let params = read_kzg_params("kzg_params.bin".to_string());
    generate_verififcation_key_without_witness_and_backup::<DarkDexCircuit>(
        &params,
        "verification_key.bin".to_string(),
    );
}

#[test]
fn full_test_with_backuped_params() {
    let sk_u = random::<u64>();
    let token_type = 1u64;
    let private_note_sum = 1000u64;

    println!("sk_u = {:#x}", sk_u);

    let sk_u = Fr::from(sk_u);
    let token_type = Fr::from(token_type);

    let private_note_sum = 1000u64;
    let private_note_sum = Fr::from(private_note_sum);
    let sk_u_commitment = poseidon_hash([sk_u, Fr::zero()]);

    let params = read_kzg_params("kzg_params.bin".to_string());

    let proof = generate_proof(
        &params,
        Some(token_type),
        Some(private_note_sum),
        Some(sk_u),
        Some(sk_u_commitment),
    )
    .unwrap();

    std::fs::write("proof.bin".to_string(), proof.as_bytes().clone()).unwrap();

    let data_to_hash = [sk_u_commitment, private_note_sum, token_type, sk_u];
    let digest = poseidon_hash(data_to_hash);
    let mut pub_inputs = vec![private_note_sum, token_type, digest];

    let res = proof.verify_with_vk_from_path::<DarkDexCircuit>(
        "verification_key.bin".to_string(),
        &params,
        &[&pub_inputs],
    );

    println!("digest = {:?}", digest.to_bytes());

    assert!(res.is_ok());
}

#[test]
fn verifier_sketch_test() {
    let token_type = 1u64;
    let private_note_sum = 1000u64;
    let digest: [u8; 32] = [53, 77, 163, 154, 53, 95, 74, 210, 36, 162, 125, 216, 200, 40, 152, 35, 51, 193, 78, 67, 18, 185, 117, 72, 40, 240, 99, 139, 88, 244, 120, 29];
    let params = read_kzg_params("kzg_params.bin".to_string());
    let mut proof: Vec<u8> = std::fs::read("proof.bin".to_string()).unwrap();

    let proof = Proof::new(proof);

    let mut pub_inputs = vec![
        Fr::from(private_note_sum),
        Fr::from(token_type),
        Fr::from_bytes(&digest).unwrap(),
    ];

    let res = proof.verify_with_vk_from_path::<DarkDexCircuit>(
        "verification_key.bin".to_string(),
        &params,
        &[&pub_inputs],
    );

    assert!(res.is_ok());
}
