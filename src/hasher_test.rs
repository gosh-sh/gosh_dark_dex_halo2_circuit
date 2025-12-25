use crate::hasher::*;
use crate::sha256::*;
use crate::prover::*;
use crate::verifier::*;
use rand::rngs::OsRng;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};

use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    circuit::Layouter,
    circuit::Value,
    dev::MockProver,
    plonk::{self, Advice, ConstraintSystem, Circuit, Column, Instance, Expression, Selector},
};
use halo2_ecc::fields::PrimeField;
use halo2_gadgets::sha256::{table16::*, Sha256Instructions, BLOCK_SIZE};
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    
    plonk::{
        Any, Constraints, Error,  TableColumn,
    },
    poly::Rotation,
};
use rand::random;
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
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer, Blake2bRead, Blake2bWrite, Challenge255},
};

use std::marker::PhantomData;
#[derive(Default, Debug, Clone)]
struct HashCircuit<F: PrimeField>{
    input: Vec<u8>, 
    _marker: PhantomData<F>,
}

impl<F: PrimeField> HashCircuit<F> {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            _marker: PhantomData,
        }
    }
}

const CAP_BLK: usize = 24;

 #[derive(Clone)]
pub struct MyCircuitConfig<F: PrimeField> {
    base_config: CircuitConfig<F>,
    public_inputs: Column<Instance>,
}

impl<F: PrimeField> Circuit<F> for HashCircuit<F> {
    type Config = MyCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let public_inputs = meta.instance_column();
        meta.enable_equality(public_inputs);

        struct DevTable {
		    s_enable: Column<Fixed>,
            input_rlc: Column<Advice>,
            input_len: Column<Advice>,
            hashes_rlc: Column<Advice>,
            is_effect: Column<Advice>,
		}

        impl SHA256Table for DevTable {
            fn cols(&self) -> [Column<Any>; 5] {
                [
                    self.s_enable.into(),
                    self.input_rlc.into(),
                    self.input_len.into(),
                    self.hashes_rlc.into(),
                    self.is_effect.into(),
                ]
			}
		}
		
		let dev_table = DevTable {
            s_enable: meta.fixed_column(),
            input_rlc: meta.advice_column(),
            input_len: meta.advice_column(),
            hashes_rlc: meta.advice_column(),
            is_effect: meta.advice_column(),
        };
		
		let chng = Expression::Constant(F::from(0x1000u64));
        let base_config = CircuitConfig::configure(meta, dev_table, chng);
        MyCircuitConfig {
            base_config,
            public_inputs
        }
	}

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
		let chng_v = Value::known(F::from(0x1000u64));
        let mut hasher = Hasher::new(config.base_config, &mut layouter)?;

        let input = &self.input;
        println!("input: {:?}", input);

        hasher.update(&mut layouter, chng_v, input)?;
        let ret_digest = hasher.finalize(&mut layouter, chng_v)?;

        for (i, cell) in ret_digest.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.public_inputs, i)?;
        }

        println!("hasher.blocks() : {:?}", hasher.blocks());
        //Handle Padding stuff, otherwise kzg stuff mat faul during verification
        for i in hasher.blocks()..CAP_BLK {
            println!("i : {:?}", i);
            hasher.update(&mut layouter, chng_v, &[])?;
            let ret_digest = hasher.finalize(&mut layouter, chng_v)?;
            for d in ret_digest {
                println!("digest word (padding): {:?}", d.value());
                
            }
        }
		
		Ok(())
	}
}



const DIGEST_ABC: [u32; 8] = [
    0b10111010011110000001011010111111,
    0b10001111000000011100111111101010,
    0b01000001010000010100000011011110,
    0b01011101101011100010001000100011,
    0b10110000000000110110000110100011,
    0b10010110000101110111101010011100,
    0b10110100000100001111111101100001,
    0b11110010000000000001010110101101,
];


#[test]
fn simple_test() {
    let circuit: HashCircuit<Fr> = HashCircuit::<Fr>::new( vec![b'a', b'b', b'c']);
    let rr = sum256_32(&vec![b'a', b'b', b'c']);
    for val in rr {
        print!("{:#x}", val);
    }

    println!("");

    let mut pub_: Vec<Fr> = Vec::new();
    for val in DIGEST_ABC {
        print!("{:#x}", val);
        pub_.push(Fr::from(val as u64));
    }


	let prover = match MockProver::<Fr>::run(17, &circuit, vec![pub_]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };
    assert_eq!(prover.verify(), Ok(()));
}


#[test]
fn kzg_test_simple() {
    let input =  [b'a'; BLOCK_SIZE * 6]; 
    println!("input size = {:?}", input.len());

    let digest = sum256_32(&input);
    let mut pub_inputs: Vec<Fr> = Vec::new();
    for val in digest {
        println!("d@ = {:#x}", val);
        pub_inputs.push(Fr::from(val as u64));
    }

    let params: ParamsKZG<Bn256> = setup(17);
    let circuit: HashCircuit<Fr> = HashCircuit::<Fr>::new(input.to_vec());
    
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&pub_inputs]],
        // &[&[]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof: Vec<u8> = transcript.finalize();
    
    println!("proof len = {:?}", proof.len());

    let empty_circuit: HashCircuit<Fr> = HashCircuit::<Fr>::default();
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk_from_empty,
        strategy,
        &[&[&pub_inputs]],
        //&[&[]],
        &mut transcript,
    )
    .is_ok());
}

#[test]
fn kzg_test_with_real_data() {
    let sk_raw = random::<u64>();
    let token_type_raw = 1u64;
    let private_note_sum_raw = 1000u64;
    let vault_rand_val_raw = 111u64;

    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk_raw);
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let token_type = Fr::from(token_type_raw);
    let private_note_sum = Fr::from(private_note_sum_raw);
    let vault_rand_val = Fr::from(vault_rand_val_raw);
    
    let sk_bytes: [u8; 8]  = sk.to_bytes()[..8].try_into().unwrap();
    let mut private_note_sum_bytes: Vec<u8> = private_note_sum.to_bytes_le()[..8].try_into().unwrap();
    let mut token_type_bytes: Vec<u8> = token_type.to_bytes_le()[..8].try_into().unwrap();
    let mut vault_rand_val_bytes: Vec<u8> = vault_rand_val.to_bytes_le()[..8].try_into().unwrap();


    println!("pk.x.to_bytes().to_vec() = {:?}", pk.x.to_bytes().to_vec());
    println!("pk.x.to_bytes().to_vec() size = {:?}", pk.x.to_bytes().to_vec().len());
    println!("pk.y.to_bytes().to_vec() = {:?}", pk.y.to_bytes().to_vec());
    println!("pk.y.to_bytes().to_vec() size = {:?}", pk.y.to_bytes().to_vec().len());

    println!("sk_bytes = {:?}", sk_bytes);
    println!("token_type_bytes = {:?}", token_type_bytes);
    println!("vault_rand_val_bytes = {:?}", vault_rand_val_bytes);
    println!("private_note_sum_bytes = {:?}", private_note_sum_bytes);

    let mut deposit_identifier_bytes = sk_bytes.to_vec();
    deposit_identifier_bytes.append(&mut pk.x.to_bytes().to_vec());
    deposit_identifier_bytes.append(&mut pk.y.to_bytes().to_vec());
    deposit_identifier_bytes.append(&mut private_note_sum_bytes);
    deposit_identifier_bytes.append(&mut token_type_bytes);
    deposit_identifier_bytes.append(&mut vault_rand_val_bytes);

    let input =  deposit_identifier_bytes; 
    println!("input size = {:?}", input.len());

    let digest = sum256_32(&input);

    let mut digest_words: Vec<Fr> = Vec::new();

    for val in digest {
        println!("d@ = {:#x}", val);
        digest_words.push(Fr::from(val as u64));
    }

    let mut pub_inputs = vec![];
    pub_inputs.append(&mut digest_words);

    let params: ParamsKZG<Bn256> = setup(17);
    let circuit: HashCircuit<Fr> = HashCircuit::<Fr>::new( input );
    
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

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
    
    println!("proof len = {:?}", proof.len());

    let empty_circuit: HashCircuit<Fr> = HashCircuit::<Fr>::default();
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk_from_empty,
        strategy,
        &[&[&pub_inputs]],
        &mut transcript,
    )
    .is_ok());
}
