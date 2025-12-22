use crate::hasher::*;
use crate::sha256::*;

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
    halo2curves::bn256::Fr,
    plonk::{
        Any, Constraints, Error, Fixed, TableColumn,
    },
    poly::Rotation,
};

use std::marker::PhantomData;
#[derive(Debug, Clone)]
struct HashCircuit<F: PrimeField>{
    input: Vec<u8>, 
    digest: Option<[u32; 8]>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> HashCircuit<F> {
    pub fn new(input: Vec<u8>, digest: Option<[u32; 8]>) -> Self {
        Self {
            input,
            digest,
            _marker: PhantomData,
        }
    }
}

 #[derive(Clone)]
pub struct MyCircuitConfig<F: PrimeField> {
    base_config: CircuitConfig<F>,
    public_inputs: Column<Instance>,
}

impl<F: PrimeField> Circuit<F> for HashCircuit<F> {
    type Config = MyCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
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
        let digest = &self.digest;

        hasher.update(&mut layouter, chng_v, input)?;
        let ret_digest = hasher.finalize(&mut layouter, chng_v)?;
        //println!("{:#x?}", ret_digest);
        /*if let Some(check_digest) = digest {
            for (w, check) in ret_digest.into_iter().zip(*check_digest) {
                w.0.assert_if_known(|digest_word| *digest_word == check);
            }
        }*/

        for (i, cell) in ret_digest.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public_inputs, i)?;
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

const DIGEST_ABD: [u32; 8] = [
    0xa52d159f, 0x262b2c6d, 0xdb724a61, 0x840befc3, 0x6eb30c88, 0x877a4030, 0xb65cbe86,
    0x298449c9,
];

const DIGEST_BLOCK: [u32; 8] = [
    0xffe054fe, 0x7ae0cb6d, 0xc65c3af9, 0xb61d5209, 0xf439851d, 0xb43d0ba5, 0x997337df,
    0x154668eb,
];

const DIGEST_AX65: [u32; 8] = [
    0x635361c4, 0x8bb9eab1, 0x4198e76e, 0xa8ab7f1a, 0x41685d6a, 0xd62aa914, 0x6d301d4f,
    0x17eb0ae0,
];

const DIGEST_NIL: [u32; 8] = [
    0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
    0x7852b855,
];

#[test]
fn simple_test() {
    let circuit: HashCircuit<Fr> = HashCircuit::<Fr>::new( vec![b'a', b'b', b'c'],  Some(DIGEST_ABC));

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