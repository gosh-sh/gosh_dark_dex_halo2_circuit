use crate::prover::*;
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

use rand::random;

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
    let proof = generate_proof(&params, Some(token_type), Some(private_note_sum), Some(sk), Some(pk), Some(g), token_type_pub, private_note_sum_pub);
    println!("proof len = {:?}", proof.len());

    let empty_circuit: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::default();
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk_from_empty,
        strategy,
        &[&[&[Fr::from(1u64), Fr::from(1000u64)]]],
        //&[&[]],
        &mut transcript,
    )
    .unwrap();

}