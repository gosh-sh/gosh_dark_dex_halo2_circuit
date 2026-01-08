use crate::hasher::*;
use crate::sha256::*;
use crate::prover::*;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;
use halo2_proofs::circuit::Value;
use crate::circuit::*;

use halo2_proofs::plonk::Expression;

//use crate::util::Challenges;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{Advice, Any, Column, Fixed, SecondPhase},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_ecc::fields::PrimeField;

const BLOCK_SIZE: usize = 16;

const CAP_BLK: usize = 24;

use std::marker::PhantomData;

#[derive(Default, Clone)]
struct MyCircuit<F: PrimeField> {
    input: Vec<u8>, 
    _marker: PhantomData<F>,
}

impl<F: PrimeField> MyCircuit<F> {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
    type Config = CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;


    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
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
            input_len: meta.advice_column(),
            input_rlc: meta.advice_column_in(SecondPhase),
            hashes_rlc: meta.advice_column_in(SecondPhase),
            is_effect: meta.advice_column(),
        };
        meta.enable_constant(dev_table.s_enable);

        let chng_v = Expression::Constant(F::from(0x1000u64));
        CircuitConfig::configure(meta, dev_table, chng_v)
    }

    
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
		let chng_v = Value::known(F::from(0x1000u64));
        let mut hasher = Hasher::new(config, &mut layouter)?;

        let input = &self.input;
        println!("input: {:?}", input);

        hasher.update(&mut layouter, chng_v, &self.input)?;

        println!("hasher.updated_size() : {:?}", hasher.updated_size());
        if hasher.updated_size() > 0 {
            println!("Start hasher.finalize");
            let ret_digest = hasher.finalize(&mut layouter, chng_v)?;
            for d in ret_digest {
                println!("digest word: {:?}", d.value());
                
            }
        }

        println!("hasher.blocks() : {:?}", hasher.blocks());
        //Padding stuff
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

#[test]
fn vk_stable_test() {
    let k = 17;
    println!("1");

    let params: ParamsKZG<Bn256> = ParamsKZG::new(k);

    println!("2");

    let empty_circuit: MyCircuit<Fr> = MyCircuit::<Fr>::default();

    
    println!("3");

    // Initialize the proving key
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    println!("4");
    let mut input = [b'a'; BLOCK_SIZE * 4].to_vec();
    input.append(&mut [b'c'; BLOCK_SIZE * 4].to_vec());
    input.append(&mut [b'd'; BLOCK_SIZE * 2].to_vec());

    let digest = sum256_32(&input);
    for val in digest {
        println!("d@ = {:#x}", val);
    }

    let circuit = MyCircuit::<Fr>::new(input.to_vec() );
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    println!("5");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    println!("6");
    // Create a proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    println!("7");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    println!("8");
    let proof: Vec<u8> = transcript.finalize();

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    println!("9");
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk_from_empty,
        strategy,
        &[&[]],
        &mut transcript,
    )
    .unwrap();
    println!("10");
}
