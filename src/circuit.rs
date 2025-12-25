use std::marker::PhantomData;
use crate::hasher::*;
use crate::sha256::*;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};

use halo2_base::utils::ScalarField;
use rand::random;

use std::fs::File;

use serde::Serialize;
use serde::Deserialize;

use halo2_ecc::fields::PrimeField;
use halo2_ecc::ecc::scalar_multiply;
use halo2_ecc::fields::fp;

use halo2_ecc::{
    ecc::{EccChip},
    fields::{fp::FpStrategy, FieldChip},
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    plonk::{Any, create_proof, keygen_pk, keygen_vk, verify_proof, Error},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer, Blake2bRead, Blake2bWrite, Challenge255},
};


use halo2_base::{
    utils::{CurveAffineExt},
};

use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    circuit::Layouter,
    circuit::Value,
    dev::MockProver,
    halo2curves::secp256k1,
    halo2curves::bn256,
    plonk::{self, Advice, ConstraintSystem, Circuit, Column, Instance, Expression, Selector},
};

use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};

use std::time::Instant;
use std::thread;
use std::time::Duration;

use rand::rngs::OsRng;

type FpChip<F> = fp::FpConfig<F, Fp>;

#[derive(Serialize, Deserialize)]
pub struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

#[derive(Default, Debug, Clone)]
pub struct DarkDexCircuit<F: PrimeField> {
    pub token_type: Option<F>,
    pub private_note_sum: Option<F>,
    pub vault_rand_val: Option<F>,
    pub sk: Option<Fq>,
    pub pk: Option<Secp256k1Affine>,
    pub g: Option<Secp256k1Affine>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> DarkDexCircuit<F> {
    pub fn new(token_type: Option<F>, private_note_sum: Option<F>, vault_rand_val: Option<F>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>) -> Self {
        Self {
            token_type,
            private_note_sum,
            vault_rand_val,
            sk,
            pk,
            g,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct DarkDexConfig<F: PrimeField> {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Fixed>,
    token_type_id_internal: Column<Advice>,
    private_note_sum_internal: Column<Advice>,
    public_inputs: Column<Instance>, /** token_type_id_public_val, private_note_sum_public_val, deposit_identifier_digest (8 words) */
    fp_chip: FpChip::<F>,
    hash_base_config: CircuitConfig<F>,
}

const CAP_BLK: usize = 24;

impl<F: PrimeField> Circuit<F> for DarkDexCircuit<F> {
    type Config = DarkDexConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;


    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<F>) -> Self::Config {
        let path = "config/circuit.config".to_string();
        let params: CircuitParams = serde_json::from_reader(
            File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        )
        .unwrap();

        let fp_chip = FpChip::<F>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            modulus::<Fp>(),
            0,
            params.degree as usize,
        );

        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.fixed_column();
        let token_type_id_internal = meta.advice_column();
        let private_note_sum_internal = meta.advice_column();
        let public_inputs = meta.instance_column();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(token_type_id_internal);
        meta.enable_equality(private_note_sum_internal);
        meta.enable_equality(public_inputs);

        //// Sha256 part
        
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
        let hash_base_config = CircuitConfig::configure(meta, dev_table, chng);
        
        /// 
        /// 
        DarkDexConfig{ a, b, c,  token_type_id_internal, private_note_sum_internal, public_inputs, fp_chip, hash_base_config}
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>
    ) -> Result<(), plonk::Error> {

        let fp_chip = config.fp_chip;
        fp_chip.range.load_lookup_table(&mut layouter)?;

        let limb_bits = fp_chip.limb_bits;
        let num_limbs = fp_chip.num_limbs;
        let _num_fixed = fp_chip.range.gate.constants.len();
        let _lookup_bits = fp_chip.range.lookup_bits;
        let _num_advice = fp_chip.range.gate.num_advice;

        let res = layouter.assign_region(
            || "check key pair",
            |region| {
                let mut aux = fp_chip.new_context(region);
                let ctx = &mut aux;
                let ecc_chip = EccChip::<F, FpChip<F>>::construct(fp_chip.clone());

                let pk_assigned = ecc_chip.load_private(
                    ctx,
                    (
                        self.pk.map_or(Value::unknown(), |pt| Value::known(pt.x)),
                        self.pk.map_or(Value::unknown(), |pt| Value::known(pt.y)),
                    ),
                );

                let g_assigned = ecc_chip.load_private(
                    ctx,
                    (
                        self.g.map_or(Value::unknown(), |pt| Value::known(pt.x)),
                        self.g.map_or(Value::unknown(), |pt| Value::known(pt.y))
                    ),
                );

                let base_chip = ecc_chip.field_chip;

                let fq_chip = fp::FpConfig::<F, Fq>::construct(
                    base_chip.range.clone(),
                    base_chip.limb_bits,
                    base_chip.num_limbs,
                    modulus::<Fq>(),
                );

                let sk_assigned = fq_chip.load_private(
                    ctx,
                    fp::FpConfig::<F, Fq>::fe_to_witness(
                        &self.sk.map_or(Value::unknown(), Value::known),
                    ),
                );
                

                let var_window_bits: usize = 4;

                let mul = scalar_multiply::<F, _, Secp256k1Affine>(
                    &base_chip,
                    ctx,
                    &g_assigned,
                    &sk_assigned.truncation.limbs,
                    base_chip.limb_bits,
                    var_window_bits,
                );

                let x_eq = base_chip.is_equal(ctx, &pk_assigned.x, &mul.x);
                let y_eq = base_chip.is_equal(ctx, &pk_assigned.y, &mul.y);

                Ok((x_eq, y_eq))
            }
        ).unwrap();

        layouter.assign_region(
            || "check final equality result",
            |mut region| {


                let cell_x = region
                    .assign_advice(|| "", config.a, 0, || res.0.value)
                    .expect("assign copy advice should not fail")
                    .cell();

                let cell_y = region
                    .assign_advice(|| "", config.b, 0, || res.1.value)
                    .expect("assign copy advice should not fail")
                    .cell();

                let fix = region.assign_fixed( || "", config.c, 0,  || Value::known(F::ONE)).unwrap().cell();

                let  _ = region.constrain_equal(cell_x, fix).unwrap();
                let _ = region.constrain_equal(cell_y, fix).unwrap();
                

                Ok(())
            }
        ).unwrap();

        let instances = layouter.assign_region(
            || "check token type & private note sum",
            |mut region| {
                let cell_token_type = region
                    .assign_advice(|| "", config.token_type_id_internal, 0, || self.token_type.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail")
                    .cell();

                let cell_private_note_sum = region
                    .assign_advice(|| "", config.private_note_sum_internal, 0, || self.private_note_sum.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail")
                    .cell();


                Ok([cell_token_type, cell_private_note_sum])
            }
        ).unwrap();

        for (i, cell) in instances.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public_inputs, i)?;
        }

        let mut input: Vec<u8> = vec![];

        if let (Some(pk), Some(sk), Some(private_note_sum), Some(token_type), Some(vault_rand_val)) = (self.pk, self.sk, self.private_note_sum, self.token_type, self.vault_rand_val) {
            let sk_bytes: Vec<u8> = sk.to_bytes()[..8].try_into().unwrap();

            let mut private_note_sum_bytes  = private_note_sum.to_bytes_le()[..8].try_into().unwrap();
            println!("private_note_sum_bytes_ = {:?}", private_note_sum_bytes);

            let mut token_type_bytes  = token_type.to_bytes_le()[..8].try_into().unwrap();
            println!("token_type_bytes_ = {:?}", token_type_bytes);

            let mut vault_rand_val_bytes  = vault_rand_val.to_bytes_le()[..8].try_into().unwrap();
            println!("vault_rand_val_bytes_ = {:?}", vault_rand_val_bytes);
        
            let mut deposit_identifier_bytes = sk_bytes;
        
            deposit_identifier_bytes.append(&mut pk.x.to_bytes().to_vec());
            deposit_identifier_bytes.append(&mut pk.y.to_bytes().to_vec());
            deposit_identifier_bytes.append(&mut private_note_sum_bytes);
            deposit_identifier_bytes.append(&mut token_type_bytes);
            deposit_identifier_bytes.append(&mut vault_rand_val_bytes);

            input.append(&mut deposit_identifier_bytes);

        }

        println!("input: {:?}", input);
        println!("input.len() = {:?}", input.len());

        let chng_v = Value::known(F::from(0x1000u64));
        let mut hasher = Hasher::new(config.hash_base_config, &mut layouter)?;

        hasher.update(&mut layouter, chng_v, &input)?;

        println!("hasher.updated_size() : {:?}", hasher.updated_size());

        let ret_digest = hasher.finalize(&mut layouter, chng_v)?;
        for d in ret_digest.clone() {
            println!("digest word : {:?}", d.value());
                
        }
        
        for (i, cell) in ret_digest.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.public_inputs, i + 2)?;
        }

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
fn simple_test() {
    let sk_raw = random::<u64>();
    let token_type_raw = 1u64;
    let private_note_sum_raw = 1000u64;
    let vault_rand_val_raw = 111u64;

    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk_raw);
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let g = Secp256k1Affine::generator();
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

    let mut pub_inputs = vec![token_type, private_note_sum];
    pub_inputs.append(&mut digest_words);

    let circuit: DarkDexCircuit<Fr> = DarkDexCircuit::<Fr>::new(Some(token_type), Some(private_note_sum), Some(vault_rand_val), Some(sk), Some(pk), Some(g));

    let prover = MockProver::run(18, &circuit, vec![pub_inputs]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
