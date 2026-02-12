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

    let params = gen_srs(k);
    let vk = keygen_vk(&params, &builder).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &builder).unwrap();

    let mut vk_bytes: Vec<u8> = std::fs::read("verification_key.bin".to_string()).unwrap();
    let mut vk_slice: &[u8] = &vk_bytes;
    let vk_unknown: VerifyingKey<G1Affine> = VerifyingKey::read::<_, BaseCircuitBuilder<Fr>>(&mut vk_slice, SerdeFormat::RawBytesUnchecked, builder.clone().params()).expect("Reading vkey should not fail");

    /*let mut vk_buf: Vec<u8> = Vec::new();
    vk
        .write(&mut vk_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write("verification_key.bin".to_string(), vk_buf).unwrap();*/

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

    check_proof_with_instances(&params, &vk_unknown, &proof, &[&pub_inputs],  true);

    let invalid_instances = vec![Fr::one(), Fr::one(), Fr::one()];

    check_proof_with_instances(&params, &vk_unknown, &proof, &[&invalid_instances],  false);
}

#[test]
fn full_test() {
    let k = 12u32;
    let lookup_bits = k as usize - 1;
    let unusable_rows = 9;
    let use_instance_columns = true;
    let num_instance_columns  = 1;
    let params = gen_srs(k); 
    let verification_key_path = "verification_key.bin";
    let proof_key_path = "proof_key.bin";
    let break_points_path = "break_points.bin";
    let config_params_path = "config_params.bin";

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

    let res = proof.verify_with_vk_from_path::<BaseCircuitBuilder<Fr>>(verification_key_path.to_string(), &params, concrete_params.clone(), &[&pub_inputs]);

    println!("res: {:?}", res);
    assert!(res);

    let invalid_instances = vec![Fr::one(), Fr::one(), Fr::one()];

    let res = proof.verify_with_vk_from_path::<BaseCircuitBuilder<Fr>>(verification_key_path.to_string(), &params, concrete_params, &[&invalid_instances]);

    println!("Negative res: {:?}", res);
    assert!(!res);
}

#[test]
fn test_gen_proof_and_verify_using_keys_from_path() {
    let k = 12u32;
    let lookup_bits = k as usize - 1;
    let unusable_rows = 9;
    let use_instance_columns = true;
    let num_instance_columns  = 1;
    let params = gen_srs(k); 
    let verification_key_path = "verification_key.bin";
    let proof_key_path = "proof_key.bin";
    let break_points_path = "break_points.bin";
    let config_params_path = "config_params.bin";

    let sk_u_ = 4u64;
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

#[test]
fn test_verify_using_keys_from_path() {
    let k = 12u32;
    let verification_key_path = "verification_key.bin";
    let config_params_path = "config_params.bin";
    let params = gen_srs(k);

    let sk_u_ = 4u64;
    let token_type_ = 10u64;
    let private_note_sum_ = 1000u64;
    let sk_u_ = Fr::from(sk_u_);
    let token_type_ = Fr::from(token_type_);
    let private_note_sum_ = Fr::from(private_note_sum_);
    let sk_u_commitment_ = poseidon_hash(&[sk_u_, Fr::zero()]);
    let data_to_hash_ = [sk_u_commitment_, private_note_sum_, token_type_, sk_u_];
    let digest_ = poseidon_hash(&data_to_hash_);
    let mut pub_inputs: Vec<Fr> = vec![private_note_sum_, token_type_, digest_];



    let mut file = File::open(config_params_path.to_string()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let concrete_params:  BaseCircuitParams = serde_json::from_str(&contents).expect("JSON was not well-formatted");
    println!("config_params: {:?}", concrete_params);

    let proof_bytes : Vec<u8> = vec![220, 109, 81, 181, 199, 52, 6, 133, 97, 210, 161, 191, 107, 0, 147, 13, 183, 178, 179, 96, 215, 168, 179, 34, 202, 195, 108, 193, 82, 97, 82, 99, 252, 216, 102, 214, 243, 89, 56, 116, 252, 231, 3, 5, 134, 78, 157, 187, 109, 240, 150, 63, 83, 19, 221, 56, 9, 120, 72, 105, 110, 117, 93, 80, 238, 119, 12, 59, 235, 75, 68, 88, 7, 153, 36, 124, 252, 109, 193, 31, 57, 159, 171, 197, 252, 162, 196, 19, 144, 123, 80, 239, 45, 86, 208, 84, 149, 59, 163, 103, 8, 184, 60, 2, 77, 25, 21, 69, 222, 83, 189, 196, 158, 164, 187, 25, 66, 33, 227, 81, 54, 177, 147, 0, 246, 162, 3, 40, 239, 2, 88, 131, 37, 23, 137, 151, 8, 158, 99, 173, 16, 119, 165, 61, 161, 13, 243, 158, 236, 186, 79, 101, 104, 239, 64, 88, 38, 102, 52, 79, 71, 118, 232, 239, 74, 165, 1, 52, 125, 127, 31, 193, 187, 107, 95, 99, 90, 160, 159, 24, 81, 191, 215, 159, 194, 89, 225, 160, 225, 140, 207, 79, 149, 203, 81, 173, 102, 170, 237, 54, 146, 126, 194, 250, 22, 217, 84, 152, 234, 2, 66, 169, 13, 82, 23, 115, 68, 97, 173, 4, 45, 74, 71, 96, 41, 194, 189, 67, 247, 116, 173, 45, 198, 202, 90, 37, 157, 140, 239, 124, 233, 150, 34, 104, 190, 229, 238, 205, 251, 208, 17, 52, 239, 85, 165, 15, 219, 160, 251, 112, 70, 198, 103, 58, 5, 198, 169, 29, 8, 207, 12, 117, 137, 245, 93, 79, 153, 43, 129, 121, 40, 88, 64, 40, 139, 235, 111, 105, 64, 128, 94, 125, 246, 174, 24, 170, 8, 163, 33, 210, 1, 50, 33, 208, 97, 238, 69, 174, 24, 114, 131, 126, 124, 237, 83, 210, 38, 29, 72, 69, 118, 108, 97, 59, 139, 87, 188, 189, 62, 128, 101, 213, 253, 55, 104, 102, 231, 50, 112, 25, 0, 114, 184, 255, 228, 28, 200, 156, 125, 89, 243, 84, 49, 244, 41, 117, 117, 254, 245, 188, 216, 199, 199, 121, 54, 142, 31, 194, 248, 104, 226, 61, 31, 169, 130, 116, 81, 196, 202, 215, 71, 241, 45, 109, 167, 28, 113, 169, 45, 32, 112, 107, 93, 245, 42, 38, 72, 101, 13, 106, 124, 215, 187, 188, 74, 24, 162, 27, 18, 166, 25, 227, 74, 15, 84, 24, 62, 171, 118, 30, 67, 43, 84, 234, 216, 216, 199, 91, 142, 181, 18, 131, 250, 226, 185, 136, 170, 82, 252, 54, 167, 44, 123, 22, 137, 85, 61, 11, 85, 56, 103, 143, 62, 45, 119, 251, 175, 0, 76, 236, 7, 147, 245, 49, 173, 215, 57, 60, 208, 87, 92, 232, 46, 190, 199, 226, 250, 25, 4, 6, 174, 112, 125, 168, 204, 120, 107, 181, 56, 241, 71, 47, 170, 93, 241, 122, 244, 24, 77, 109, 96, 237, 8, 205, 246, 1, 19, 75, 153, 178, 36, 69, 115, 218, 253, 12, 69, 0, 176, 213, 65, 53, 242, 4, 89, 194, 0, 61, 5, 206, 142, 176, 26, 24, 33, 178, 151, 74, 210, 228, 55, 61, 17, 43, 30, 201, 72, 177, 106, 170, 121, 1, 129, 71, 173, 221, 34, 179, 159, 59, 227, 230, 65, 142, 176, 88, 37, 155, 69, 224, 97, 104, 242, 59, 151, 19, 188, 34, 75, 251, 10, 217, 177, 121, 195, 112, 177, 100, 108, 73, 54, 153, 84, 230, 162, 117, 13, 244, 73, 198, 64, 10, 116, 123, 41, 207, 249, 42, 2, 22, 214, 22, 173, 120, 187, 182, 13, 130, 232, 119, 177, 202, 244, 89, 161, 90, 192, 57, 84, 215, 29, 211, 187, 148, 242, 1, 199, 187, 65, 48, 219, 171, 192, 95, 55, 181, 178, 64, 114, 238, 152, 191, 48, 161, 87, 103, 60, 97, 85, 167, 252, 43, 18, 4, 49, 149, 134, 238, 126, 6, 43, 6, 255, 141, 168, 177, 146, 97, 176, 220, 113, 227, 102, 184, 24, 203, 10, 247, 1, 169, 186, 70, 11, 40, 16, 167, 229, 128, 86, 215, 18, 176, 117, 42, 113, 18, 78, 245, 241, 36, 38, 27, 19, 157, 107, 3, 137, 219, 33, 164, 153, 195, 112, 4, 31, 32, 118, 146, 82, 31, 60, 18, 21, 163, 179, 23, 102, 223, 9, 161, 197, 243, 246, 55, 193, 108, 63, 130, 143, 213, 246, 8, 51, 33, 58, 90, 51, 88, 235, 203, 175, 118, 37, 208, 81, 222, 18, 13, 156, 228, 7, 246, 25, 78, 69, 108, 2, 115, 78, 58, 91, 159, 86, 94, 110, 157, 146, 11, 65, 204, 207, 96, 38, 133, 248, 190, 216, 75, 204, 39, 58, 6, 157, 178, 101, 230, 200, 24, 128, 216, 34, 205, 73, 219, 165, 13, 128, 4, 172, 27, 69, 109, 240, 205, 167, 103, 180, 76, 102, 57, 124, 32, 141, 14, 136, 10, 184, 40, 219, 228, 214, 163, 93, 189, 218, 141, 91, 73, 100, 85, 132, 111, 203, 163, 219, 95, 13, 83, 10, 206, 200, 193, 26, 40, 142, 189, 225, 251, 150, 207, 167, 55, 141, 138, 250, 46, 47, 119, 92, 223, 224, 55, 121, 144, 83, 170, 221, 175, 26, 134, 237, 69, 122, 105, 6, 23, 172, 15, 229, 203, 158, 169, 169, 105, 117, 106, 58, 182, 39, 117, 227, 253, 89, 147, 204, 162, 159, 185, 255, 20, 251, 132, 179, 249, 101, 206, 248, 5, 40, 58, 243, 17, 127, 100, 17, 160, 214, 148, 219, 20, 171, 149, 62, 221, 97, 146, 244, 88, 255, 85, 240, 212, 79, 251, 155, 136, 201, 116, 54, 30, 215, 57, 125, 229, 1, 238, 212, 242, 60, 213, 35, 208, 130, 10, 120, 167, 220, 254, 227, 117, 20, 165, 31, 98, 32, 149, 53, 97, 85, 94, 59, 10, 221, 130, 104, 19, 216, 81, 181, 61, 238, 57, 222, 128, 117, 131, 233, 213, 210, 147, 35, 63, 247, 182, 28, 81, 41, 68, 132, 146, 147, 138, 17, 30, 129, 4, 101, 82, 114, 148, 79, 93, 243, 9, 30, 204, 108, 68, 72, 247, 226, 61, 208, 107, 59, 28, 191, 166, 19, 138, 162, 52, 135, 3, 38, 19, 241, 17, 67, 50, 192, 153, 198, 173, 113, 12, 35, 239, 128, 46, 63, 21, 103, 150, 236, 89, 194, 243, 1, 57, 102, 82, 138, 54, 192, 255, 240, 26, 106, 212, 210, 188, 12, 175, 168, 13, 230, 166, 130, 20, 188, 237, 100, 242, 55, 61, 2, 45, 68, 33, 48, 81, 58, 97, 166, 219, 8, 68, 247, 15, 115, 153, 155, 123, 217, 184, 211, 176, 177, 165, 235, 0, 109, 240, 63, 24, 128, 193, 241, 3, 39, 136, 78, 66, 101, 48, 74, 51, 212, 217, 165, 32, 133, 202, 126, 58, 118, 68, 93, 201, 118, 181, 64, 135, 13, 162, 109, 171, 155, 93, 126, 171, 9, 94, 100, 164, 41, 166, 155, 89, 21, 169, 222, 15, 231, 119, 37, 29, 124, 173, 40, 17, 100, 138, 120, 136, 78, 151, 220, 202, 199, 251, 241, 182, 112, 88, 75, 106, 175, 68, 186, 1, 12, 252, 196, 1, 196, 5, 224, 110, 17, 104, 220, 65, 166, 75, 91, 78, 212, 66, 215, 172, 116, 140, 114, 167, 225, 0, 204, 47, 73, 13, 85, 187, 226, 69, 178, 47, 2, 212, 18, 36, 112, 60, 218, 251, 77, 27, 160, 90, 73, 54, 167, 164, 119, 204, 151, 12, 93, 15, 103, 203, 249, 101, 43, 185, 105, 9, 52, 18, 227, 45, 205, 59, 119, 26, 204, 10, 58, 255, 13, 0, 41, 112, 41, 86, 216, 145, 78, 19, 151, 221, 61, 34, 115, 191, 81, 9, 128, 243, 156, 13, 157, 208, 64, 67, 240, 197, 40, 143, 193, 108, 233, 224, 127, 2, 73, 246, 2, 209, 240, 245, 219, 214, 130, 67, 223, 203, 75, 26, 78, 255, 13, 31, 169, 87, 64, 143, 211, 203, 178, 182, 1, 99, 14, 64, 106, 50, 99, 24, 242, 39, 50, 194, 63, 254, 24, 142, 201, 23, 163, 154, 35, 213, 113, 37, 39, 42, 78, 193, 145, 102, 183, 246, 119, 255, 188, 33, 171, 91, 185, 44, 135, 123, 173, 205, 19, 92, 218, 179, 207, 149, 178, 112, 30, 45, 1, 26, 227, 123, 90, 224, 67, 145, 176, 71, 66, 77, 247, 151, 237, 38, 160, 146, 27, 146, 20, 197, 246, 9, 95, 19, 49, 63, 155, 114, 116, 216, 36, 9, 97, 39, 184, 252, 139, 207, 108, 97, 205, 42, 61, 164, 17, 198, 42, 56, 232, 255, 223, 228, 218, 148, 235, 159, 171, 2, 177, 196, 142, 124, 65, 28, 163, 165, 249, 219, 110, 10, 22, 30, 249, 205, 135, 54, 191, 253, 251, 44, 136, 99, 42, 205, 96, 178, 143, 26, 230, 115, 64, 215, 191, 13, 151, 6, 195, 200, 191, 69, 196, 242, 246, 140, 18, 105, 25, 113, 126, 100, 116, 154, 252, 139, 75, 62, 76, 18, 20, 48, 79, 146, 114, 23, 230, 68, 138, 26, 146, 124, 238, 19, 95, 109, 186, 149, 253, 128, 82, 90, 49, 87, 255, 146, 15, 186, 153, 24, 59, 169, 105, 222, 224, 63, 201, 66, 198, 120, 39, 35, 17, 158, 116, 214, 100, 11, 236, 136, 33, 38, 149, 104, 162, 214, 48, 40, 178, 124, 222, 229, 97, 239, 43, 71, 67, 204, 246, 219, 87, 4, 27, 40, 121, 15, 101, 0, 128, 84, 53, 207, 234, 59, 134, 128, 121, 243, 116, 184, 23, 184, 150, 51, 24, 124, 12, 235, 57, 94, 67, 173, 65, 200, 50, 36, 187, 126, 47, 118, 136, 34, 166, 86, 31, 240, 248, 181, 178, 50, 190, 142, 120, 78, 55, 182, 7, 85, 92, 155, 163, 53, 254, 219, 133, 83, 173, 42, 206, 150, 82, 215, 29, 28, 190, 177, 133, 133, 34, 210, 114, 96, 141, 85, 97, 202, 201, 111, 125, 16, 76, 153, 132, 76, 153, 44, 211, 235, 213, 10, 219, 230, 11, 170, 167, 34, 203, 151, 232, 172, 133, 57, 38, 149, 24, 171, 178, 115, 237, 211, 41, 236, 152, 160, 29, 1, 101, 87, 134, 62, 200, 14, 74, 168, 88, 190, 45, 194, 54, 107, 127, 159, 203, 14, 112, 3, 31, 240, 45, 107, 4, 107, 123, 75, 99, 65, 189, 46, 63, 81, 53, 15, 59, 20, 2, 149, 124, 72, 8, 133, 160, 24, 98, 31, 8, 145, 111, 255, 20, 66, 217, 29, 173, 77, 235, 133, 144, 92, 93, 213, 63, 129, 208, 60, 5, 30, 92, 130, 13, 145, 71, 24, 86, 37, 157, 249, 251, 76, 212, 122, 246, 65, 29, 111, 253, 75, 148, 189, 217, 69, 199, 40, 66, 198, 96, 78, 165, 35, 191, 221, 134, 111, 25, 209, 203, 85, 142, 43, 219, 11, 113, 247, 173, 105, 163, 224, 228, 105, 111, 166, 231, 100, 204, 22, 220, 3, 208, 22, 70, 20, 25, 77, 142, 9, 107, 7, 240, 63, 162, 143, 181, 68, 228, 117, 235, 107, 32, 230, 2, 200, 181, 33, 63, 81, 206, 73, 114, 55, 97, 168, 243, 31, 186, 126, 20, 56, 110, 166, 128, 120, 154, 141, 225, 94, 11, 199, 138, 59, 253, 205, 216, 57, 16, 65, 73, 115, 36, 30, 79, 33, 231, 141, 26, 30, 171, 144, 88, 69, 59, 108, 155, 105, 61, 173, 97, 18, 183, 98, 22, 15, 211, 12, 57, 212, 245, 203, 83, 16, 89, 139, 43, 49, 253, 154, 165, 40, 49, 102, 56, 176, 17, 171, 110, 127, 47, 248, 33, 255, 222, 125, 144, 196, 94, 163, 108, 151, 240, 117, 253, 132, 247, 131, 230, 80, 136, 140, 13, 48, 40, 213, 163, 19, 13, 9, 185, 181, 217, 194, 186, 147, 247, 75, 72, 150, 72, 30, 127, 250, 156, 105, 97, 129, 48, 242, 229, 225, 81, 235, 177, 29, 182, 203, 250, 4, 2, 252, 181, 3, 253, 14, 18, 124, 203, 204, 46, 131, 72, 249, 78, 188, 122, 5, 141, 7, 230, 96, 16, 233, 35, 225, 99, 78, 87, 242, 28, 163, 126, 129, 188, 28, 56, 195, 180, 110, 218, 93, 95, 120, 243, 212, 127, 108, 201, 13, 160, 181, 224, 172, 216, 39, 49, 100, 6, 12];
    let proof = Proof{0: proof_bytes};

    let res = proof.verify_with_vk_from_path::<BaseCircuitBuilder<Fr>>(verification_key_path.to_string(), &params, concrete_params, &[&pub_inputs]);

    println!("res: {:?}", res);
    assert!(res);
}

#[test]
fn test_read()  {
    let verification_key_path = "verification_key.bin";
    let mut vk_slice: &[u8] = &std::fs::read(verification_key_path).unwrap();
    println!("vk: {:?}", vk_slice);
    println!("vk len: {:?}", vk_slice.len());
}

#[test]
fn test_read_2()  {
    let path = "./params/kzg_bn254_12.srs";
    let mut kzg_slice: &[u8] = &std::fs::read(path).unwrap();
    println!("kzg: {:?}", kzg_slice);
    println!("kzg len: {:?}", kzg_slice.len());
}

#[test]
fn test_read_3()  {
    let proof_key_path = "proof_key.bin";
    let mut pk_slice: &[u8] = &std::fs::read(proof_key_path).unwrap();
    println!("pk: {:?}", pk_slice);
    println!("pk len: {:?}", pk_slice.len());
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

    /*let mut vk1_buf: Vec<u8> = Vec::new();
    vk
        .write(&mut vk1_buf, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    std::fs::write("verification_key.bin".to_string(), vk1_buf).unwrap();*/

    let mut vk_bytes: Vec<u8> = std::fs::read("verification_key.bin".to_string()).unwrap();
    let mut vk_slice: &[u8] = &vk_bytes;
    let vk_unknown: VerifyingKey<G1Affine> = VerifyingKey::read::<_, BaseCircuitBuilder<Fr>>(&mut vk_slice, SerdeFormat::RawBytesUnchecked, builder.params()).expect("Reading vkey should not fail");


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

    let mut pub_inputs_: Vec<Fr> = vec![private_note_sum_, digest_, token_type_];

    check_proof_with_instances(&params, &vk_unknown, &proof, &[&pub_inputs],  true);
}


#[test]
fn full_test_more() {
    let k = 12u32;
    let lookup_bits = k as usize - 1;
    let unusable_rows = 9;
    let use_instance_columns = true;
    let num_instance_columns  = 1;
    let params = gen_srs(k); 
    let verification_key_path = "verification_key.bin";
    let proof_key_path = "proof_key.bin";
    let break_points_path = "break_points.bin";
    let config_params_path = "config_params.bin";

    /*let f = |core: &mut SinglePhaseCoreManager<Fr>, range: &RangeChip<Fr>| -> Vec<Vec<AssignedValue<Fr>>>{
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
    );*/

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



    let proof = generate_dark_dex_proof(
        k,
        unusable_rows,
        &params,
        token_type_,
        private_note_sum_,
        sk_u_,
        sk_u_commitment_,
        break_points_path.to_string(), 
        config_params_path.to_string(), 
        proof_key_path.to_string()
    ).unwrap();

    let mut file = File::open(config_params_path.to_string()).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let concrete_params:  BaseCircuitParams = serde_json::from_str(&contents).expect("JSON was not well-formatted");
    println!("config_params: {:?}", concrete_params);

    let res = proof.verify_with_vk_from_path::<BaseCircuitBuilder<Fr>>(verification_key_path.to_string(), &params, concrete_params.clone(), &[&pub_inputs]);

    println!("res: {:?}", res);
    assert!(res);
}