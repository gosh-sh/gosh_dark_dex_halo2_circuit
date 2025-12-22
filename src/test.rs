use crate::prover::*;
use crate::verifier::*;
use crate::circuit::*;
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    circuit::Layouter,
    circuit::Value,
    dev::MockProver,
    halo2curves::secp256k1,
    halo2curves::bn256,
    plonk::{self, Advice, ConstraintSystem, Circuit, Column, Instance, Expression, Selector},
};
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};
use halo2_proofs::plonk::VerifyingKey;
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
use halo2_proofs::SerdeFormat;
use rand::random;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    path::Path,
    rc::Rc,
};

#[test]
fn simple_test() {
    let sk = random::<u64>();
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let token_type = Fr::from(1u64);
    let private_note_sum = Fr::from(1000u64);
    
    println!("{:?}", sk);
    println!("{:?}", pk);
    println!("{:?}", g);

    let circuit: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::new(Some(token_type), Some(private_note_sum),  Some(sk), Some(pk), Some(g));

    let prover = MockProver::run(18, &circuit, vec![vec![Fr::from(1u64), Fr::from(1000u64)]]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn generate_and_backup_kzg_params_test() {
    let k = 18;
    setup_and_backup_kzg_params(k, "kzg_params.bin".to_string());
}

#[test]
fn generate_and_backup_verification_key_test() {
    let params = read_kzg_params("kzg_params.bin".to_string());
    generate_verififcation_key_without_witness_and_backup(&params, "verification_key.bin".to_string());
}

#[test]
fn verifier_sketch_test() {
    let token_type_pub = 1u64;
    let private_note_sum_pub =  1000u64;
    let params = read_kzg_params("kzg_params.bin".to_string());
    let mut proof: Vec<u8> = std::fs::read("proof.bin".to_string()).unwrap();
    let vk_from_empty: VerifyingKey<G1Affine> = verification_key_from_path("verification_key.bin".to_string());
    let pub_inputs = vec![Fr::from(token_type_pub), Fr::from(private_note_sum_pub)];
    assert!(verify_proof_(&params, &proof, &vk_from_empty, pub_inputs));
}

#[test]
fn full_test_with_backuped_params() {
    let sk = random::<u64>();
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let token_type = Fr::from(1u64);
    let token_type_pub = 1u64;
    let private_note_sum = Fr::from(1000u64);
    let private_note_sum_pub =  1000u64;

    let params = read_kzg_params("kzg_params.bin".to_string());

    let proof = generate_proof(&params, Some(token_type), Some(private_note_sum), Some(sk), Some(pk), Some(g), token_type_pub, private_note_sum_pub);

    std::fs::write("proof.bin".to_string(), proof.clone()).unwrap();

    let vk_from_empty: VerifyingKey<G1Affine> = verification_key_from_path("verification_key.bin".to_string());
    //generate_verififcation_key_without_witness(&params);

    let pub_inputs = vec![Fr::from(token_type_pub), Fr::from(private_note_sum_pub)];
    assert!(verify_proof_(&params, &proof, &vk_from_empty, pub_inputs));

}

#[test]
fn full_test() {
    let sk = random::<u64>();
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
    let g = Secp256k1Affine::generator();
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let token_type = Fr::from(1u64);
    let token_type_pub = 1u64;
    let private_note_sum = Fr::from(1000u64);
    let private_note_sum_pub =  1000u64;
    let k = 18;
    let params: ParamsKZG<Bn256> = setup(k);

    let mut params_buf: Vec<u8> = Vec::new();

    let _ = params.write_custom(&mut params_buf, SerdeFormat::RawBytesUnchecked).unwrap();
    println!("KZG params len = {:?}", params_buf.len());

    let mut params_slice: &[u8] = &params_buf;

    let params_new  = ParamsKZG::<Bn256>::read_custom(&mut params_slice, SerdeFormat::RawBytesUnchecked).expect("Reading vkey should not fail");

    
    let proof = generate_proof(&params_new, Some(token_type), Some(private_note_sum), Some(sk), Some(pk), Some(g), token_type_pub, private_note_sum_pub);
    println!("proof len = {:?}", proof.len());

    let empty_circuit: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::default();
    let vk_from_empty = keygen_vk(&params_new, &empty_circuit).expect("keygen_vk should not fail");

    let mut vk1_buf: Vec<u8> = Vec::new();
    vk_from_empty.write(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
    .unwrap();
    let mut slice: &[u8] = &vk1_buf;
    println!("vk1_buf len = {:?}", vk1_buf.len());

    let vk_from_empty_new: VerifyingKey<G1Affine> = VerifyingKey::read::<_, DarkDexCircuit<Fr>>(&mut slice, SerdeFormat::RawBytesUnchecked).expect("Reading vkey should not fail");

    //let vk_from_empty_from_bytes: VerifyingKey<G1Affine> = VerifyingKey::< DarkDexCircuit<Fr>>::from_bytes(&vk1_buf, SerdeFormat::RawBytesUnchecked).unwrap();

    //let vk: VerifyingKey<G1Affine> = VerifyingKey::read::<_, DarkDexCircuit<Fr>>(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
                //.expect("Reading vkey should not fail");

    //let path = format!("./data/1.vkey");

    /*match File::open(path.as_str()) {
        Ok(f) => {
            let mut bufreader = BufReader::new(f);
            let vk: VerifyingKey<G1Affine> = VerifyingKey::read::<_, DarkDexCircuit<Fr>>(&mut slice, SerdeFormat::RawBytesUnchecked)
                .expect("Reading vkey should not fail");
        
        }
        Err(_) => {
        }
    }*/

    let strategy = SingleStrategy::new(&params_new);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params_new,
            &vk_from_empty_new,
            strategy,
            &[&[&[Fr::from(1u64), Fr::from(1000u64)]]],
            //&[&[]],
            &mut transcript,
        )
        .is_ok()
    );

}