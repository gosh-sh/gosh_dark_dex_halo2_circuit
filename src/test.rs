use crate::circuit::*;
use crate::proof::*;
use crate::poseidon::*;
use crate::snark_utils::*;
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        bn256::{Fr, Bn256, G1Affine},
        secp256k1::{Fp, Fq, Secp256k1Affine},
    },
    plonk::Fixed,
};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::AssignedValue;
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::check_proof_with_instances;
use halo2_base::utils::testing::gen_proof_with_instances;
use halo2_base::utils::testing::{gen_proof, check_proof};
use halo2_base::halo2_proofs::{
    circuit::Layouter,
    circuit::SimpleFloorPlanner,
    circuit::Value,
    dev::MockProver,
    halo2curves::bn256,
    halo2curves::secp256k1,
    plonk::{self, Advice, Circuit, Column, ConstraintSystem, Expression, Instance, Selector, ProvingKey, VerifyingKey, keygen_vk, keygen_pk, create_proof, verify_proof},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
        },
        kzg::{multiopen::ProverSHPLONK, strategy::SingleStrategy},
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat
};

use halo2_base::gates::RangeChip;
use halo2_base::utils::ScalarField;
use rand::random;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    path::Path,
    rc::Rc,
};

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;

use rand::rngs::OsRng;

//use halo2_ecc::fields::PrimeField as OtherPrimeField;

use halo2_base::gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage};

#[test]
fn generate_and_backup_kzg_params_test() {
    let k = 8;
    setup_and_backup_kzg_params(k, "kzg_params.bin".to_string());
}

#[test]
fn full_raw_test() {
    let k = 12u32;
    let lookup_bits = k as usize - 1;
    let unusable_rows = 9;

    let mut builder =
            RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(k as usize).use_instance_columns(1 as usize);
    builder.set_lookup_bits(lookup_bits);
    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
    let circuit: DarkDexCircuit = DarkDexCircuit::default(k, unusable_rows);
    let res = circuit.closure(builder.pool(0), &range);
    builder.assigned_instances[0] = res;
    
    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let lookup_bits_ = if t_cells_lookup == 0 { None } else { Some(lookup_bits) };
    builder.config_params.lookup_bits = lookup_bits_;

    let config_params = builder.calculate_params(Some(unusable_rows));

    let params = setup_and_backup_kzg_params(k, "kzg.bin".to_string());
    let vk = keygen_vk(&params, &builder).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &builder).unwrap();

    let mut vk_buf: Vec<u8> = Vec::new();
    vk
        .write(&mut vk_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write("verification_key.bin".to_string(), vk_buf).unwrap();

    let mut pk_buf: Vec<u8> = Vec::new();
    pk
        .write(&mut pk_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write("proof_key.bin".to_string(), pk_buf).unwrap();

    let break_points = builder.break_points();
    println!("break_points: {:?}", break_points.len());
    assert!(break_points.len() == 1);
    println!("break_points: {:?}", break_points[0].len());
    println!("break_points: {:?}", break_points);
    drop(builder);

    let break_points_ = break_points[0].clone();

    let mut file = File::create("break_points.bin").unwrap();
    // Write the u16 data as bytes in little-endian order
    for value in break_points_ {
        let v = value as u16;
        println!("&value.to_le_bytes(): {:?}", &value.to_le_bytes()[0..2]);
        file.write_all(&value.to_le_bytes()[0..2]).unwrap();
    }
    
    let config_params_serialized = serde_json::to_string(&config_params).unwrap();

    println!("config_params_serialized: {:?}", config_params_serialized);

    let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points).use_instance_columns(1 as usize);
    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
   
    let sk_u_ = random::<u64>();
    let token_type_ = 10u64;
    let private_note_sum_ = 1000u64;
    let sk_u_ = Fr::from(sk_u_);
    let token_type_ = Fr::from(token_type_);
    let private_note_sum_ = Fr::from(private_note_sum_);
    let sk_u_commitment_ = poseidon_hash(&[sk_u_, Fr::zero()]);
    let data_to_hash_ = [sk_u_commitment_, private_note_sum_, token_type_, sk_u_];
    let digest_ = poseidon_hash(&data_to_hash_);
    let mut pub_inputs: Vec<Fr> = vec![private_note_sum_, token_type_, digest_];

    let circuit_: DarkDexCircuit = DarkDexCircuit::new(k, unusable_rows, token_type_, private_note_sum_, sk_u_, sk_u_commitment_);
    let res = circuit_.closure(builder.pool(0), &range);
    builder.assigned_instances[0] = res;

    let proof = gen_proof_with_instances(&params, &pk, builder, &[&pub_inputs]);
    
    let proof_size = proof.len();

    println!("proof: {:?}", proof);

    check_proof_with_instances(&params, &vk, &proof, &[&pub_inputs],  true);

    let invalid_instances = vec![Fr::one(), Fr::one(), Fr::one()];

    check_proof_with_instances(&params, &vk, &proof, &[&invalid_instances],  false);
}

#[test]
fn test_1() {
    let k = 12u32;
    let lookup_bits = k as usize - 1;
    let unusable_rows = 9;
    let use_instance_columns = true;
    let num_instance_columns  = 1;
    let params = setup_and_backup_kzg_params(k, "kzg.bin".to_string());
    let verification_key_path = "verification_key.bin";
    let proof_key_path = "proof_key.bin";
    let break_points_path = "break_points.bin";
    let config_params_path = "config_params.bin";

    let sk_u_ = random::<u64>();
    let token_type_ = 10u64;
    let private_note_sum_ = 1000u64;
    let sk_u_ = Fr::from(sk_u_);
    let token_type_ = Fr::from(token_type_);
    let private_note_sum_ = Fr::from(private_note_sum_);
    let sk_u_commitment_ = poseidon_hash(&[sk_u_, Fr::zero()]);
    let data_to_hash_ = [sk_u_commitment_, private_note_sum_, token_type_, sk_u_];
    let digest_ = poseidon_hash(&data_to_hash_);
    let mut pub_inputs: Vec<Fr> = vec![private_note_sum_, token_type_, digest_];

    let f = |core: &mut SinglePhaseCoreManager<Fr>, range: &RangeChip<Fr>| -> Vec<Vec<AssignedValue<Fr>>>{
        let circuit: DarkDexCircuit = DarkDexCircuit::default(k, unusable_rows);
        let res = circuit.closure(core, range);
        vec![res]
    };

    generate_keys_and_backup_for_circuit_builder(
        k,
        use_instance_columns,
        num_instance_columns,
        unusable_rows,
        &params,
        verification_key_path.to_string(),
        proof_key_path.to_string(),
        break_points_path.to_string(),
        config_params_path.to_string(),
        f
    );

    let f = |core: &mut SinglePhaseCoreManager<Fr>, range: &RangeChip<Fr>| -> Vec<Vec<AssignedValue<Fr>>>{
        let circuit: DarkDexCircuit = DarkDexCircuit::new(k, unusable_rows, token_type_, private_note_sum_, sk_u_, sk_u_commitment_);
        let res = circuit.closure(core, range);
        vec![res]
    };

    let proof = Proof::create_for_curcuit_builder(k, use_instance_columns, num_instance_columns, &params,break_points_path.to_string(), config_params_path.to_string(), proof_key_path.to_string(), &[&pub_inputs], f);

    let mut file = File::open(config_params_path.to_string()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let concrete_params:  BaseCircuitParams = serde_json::from_str(&contents).expect("JSON was not well-formatted");
    println!("config_params: {:?}", concrete_params);

    let res = proof.verify_with_vk_from_path::<BaseCircuitBuilder<Fr>>(verification_key_path.to_string(), &params, concrete_params, &[&pub_inputs]);

    println!("res: {:?}", res);
    assert!(res);
}

/////
#[test]
fn t() {
    let k = 12u32;
    let lookup_bits = k as usize - 1;
    let unusable_rows = 9;

    let sk_u = 0u64;
    let token_type = 0u64;
    let private_note_sum = 0u64;
    let sk_u = Fr::from(sk_u);
    let token_type = Fr::from(token_type);
    let private_note_sum = Fr::from(private_note_sum);
    let sk_u_commitment = poseidon_hash(&[sk_u, Fr::zero()]);
    let data_to_hash = [sk_u_commitment, private_note_sum, token_type, sk_u];
    let digest = poseidon_hash(&data_to_hash);
    //let mut pub_inputs: Vec<Fr> = vec![private_note_sum, token_type, digest];

    let mut builder =
            RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(k as usize).use_instance_columns(1 as usize);
    builder.set_lookup_bits(lookup_bits);
    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
    let circuit: DarkDexCircuit = DarkDexCircuit::new(k, unusable_rows, token_type, private_note_sum, sk_u, sk_u_commitment);
    let res = circuit.closure(builder.pool(0), &range);
    builder.assigned_instances[0] = res;
    
    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let lookup_bits_ = if t_cells_lookup == 0 { None } else { Some(lookup_bits) };
    builder.config_params.lookup_bits = lookup_bits_;

    let config_params = builder.calculate_params(Some(unusable_rows));

    let params = gen_srs(k);
    let vk = keygen_vk(&params, &builder).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &builder).unwrap();

    /* let mut vk1_buf: Vec<u8> = Vec::new();
    vk
        .write(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write("verification_key.bin".to_string(), vk1_buf).unwrap();*/

    let mut vk_bytes: Vec<u8> = std::fs::read("verification_key.bin".to_string()).unwrap();
    let mut vk_slice: &[u8] = &vk_bytes;
    let vk_unknown: VerifyingKey<G1Affine> = VerifyingKey::read::<_, BaseCircuitBuilder<Fr>>(&mut vk_slice, SerdeFormat::RawBytesUnchecked, builder.params()).expect("Reading vkey should not fail");


    /////
    /// 
    

    let break_points = builder.break_points();
    println!("break_points: {:?}", break_points.len());
    println!("break_points: {:?}", break_points[0].len());
    println!("break_points: {:?}", break_points);
    drop(builder);


    let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points).use_instance_columns(1 as usize);
    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
   
    let sk_u_ = random::<u64>();
    let token_type_ = 10u64;
    let private_note_sum_ = 1000u64;
    let sk_u_ = Fr::from(sk_u_);
    let token_type_ = Fr::from(token_type_);
    let private_note_sum_ = Fr::from(private_note_sum_);
    let sk_u_commitment_ = poseidon_hash(&[sk_u_, Fr::zero()]);
    let data_to_hash_ = [sk_u_commitment_, private_note_sum_, token_type_, sk_u_];
    let digest_ = poseidon_hash(&data_to_hash_);
    let mut pub_inputs: Vec<Fr> = vec![private_note_sum_, token_type_, digest_];

    //let instances = vec![vec![private_note_sum_, token_type_, digest_]];


    let circuit_: DarkDexCircuit = DarkDexCircuit::new(k, unusable_rows, token_type_, private_note_sum_, sk_u_, sk_u_commitment_);
    let res = circuit_.closure(builder.pool(0), &range);
    builder.assigned_instances[0] = res;

    let proof = gen_proof_with_instances(&params, &pk, builder, &[&pub_inputs]);
    
    let proof_size = proof.len();

    println!("proof: {:?}", proof);

   // let mut pub_inputs_: Vec<Fr> = vec![private_note_sum_, digest_, token_type_];

    check_proof_with_instances(&params, &vk_unknown, &proof, &[&pub_inputs],  true);
}

/*#[test]
fn kzg_test_raw() {
    let k = 12u32;
    let sk_u = random::<u64>();
    let token_type = 1u64;
    let private_note_sum = 1000u64;

    println!("sk_u = {:#x}", sk_u);

    let sk_u = Fr::from(sk_u);
    let token_type = Fr::from(token_type);
    let private_note_sum = Fr::from(private_note_sum);

    let sk_u_commitment = poseidon_hash(&[sk_u, Fr::zero()]);

    let data_to_hash = [sk_u_commitment, private_note_sum, token_type, sk_u];

    let digest = poseidon_hash(&data_to_hash);

    let mut pub_inputs = vec![private_note_sum, token_type, digest];

    //////

    let params: ParamsKZG<Bn256> = setup(k);
    
    let circuit: DarkDexCircuit = DarkDexCircuit::new(k, token_type, private_note_sum, sk_u, sk_u_commitment);
    let mut builder = circuit.create_keygen();//.create_keygen_use_unknown();
    let unusable_rows = 9;

    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
        
    let lookup_bits = if t_cells_lookup == 0 { None } else { builder.lookup_bits() };
    builder.config_params.lookup_bits = lookup_bits;

    builder.calculate_params(Some(unusable_rows));

    


    /*let vk_unknown = keygen_vk(&params, &builder).unwrap();
    //println!("vk = {:?}", vk);

    let mut vk1_buf: Vec<u8> = Vec::new();
    vk_unknown
        .write(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write("verification_key.bin".to_string(), vk1_buf).unwrap();*/


    ///////
    /// 
    
    let mut vk_bytes: Vec<u8> = std::fs::read("verification_key.bin".to_string()).unwrap();
    let mut vk_slice: &[u8] = &vk_bytes;
    let vk_unknown: VerifyingKey<G1Affine> = VerifyingKey::read::<_, BaseCircuitBuilder<Fr>>(&mut vk_slice, SerdeFormat::RawBytesUnchecked, builder.params()).expect("Reading vkey should not fail");

    let vk = keygen_vk(&params, &builder).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &builder).unwrap();

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let mut builder = circuit.create_prover(builder.clone().config_params, builder.clone().break_points());
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[builder],
        &[&[&pub_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail!");

    let proof: Vec<u8> = transcript.finalize();

    println!("proof len = {:?}", proof.len());

    /*let empty_circuit: DarkDexCircuit = DarkDexCircuit::default();
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");*/

    


    let strategy = SingleStrategy::new(&params);
    let verifier_params = params.verifier_params();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(
        verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
        >
        /*<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>*/
        (
            &verifier_params,
            &vk_unknown,
            strategy,
            &[&[&pub_inputs]],
            //&[&[]],
            &mut transcript,
        )
        .is_ok()
    );
}*/

/*
/////////////////


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
}*/
