use std::marker::PhantomData;

use halo2_base::AssignedValue;
use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};
use halo2_proofs::poly::Rotation;
use halo2_base::utils::ScalarField;
use rand::random;

use std::fs::File;

use serde::Serialize;
use serde::Deserialize;
 use halo2_proofs::circuit::AssignedCell;
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

use poseidon_base::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3, P128Pow5T3Compact, Spec,  CachedSpec};

use poseidon_circuit::{
    poseidon::{
        //primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3},
        Hash,
    },
    Hashable,
};
use rand::thread_rng;
pub use poseidon_circuit::poseidon::{Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig};

use rand::SeedableRng;

use crate::utils::*;

pub type P128Pow5T3Fr = P128Pow5T3<Fr>;

type FpChip<F> = fp::FpConfig<F, Fp>;

pub fn poseidon_hash_gadget<const L: usize>(
    config: PoseidonConfig<Fr, 3, 2>,
    mut layouter: impl Layouter<Fr>,
    messages: [AssignedCell<Fr, Fr>; L],
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let chip = PoseidonChip::construct(config);
    let hasher = Hash::<_, _, P128Pow5T3<Fr>, ConstantLength<L>, 3, 2>::init(
        chip,
        layouter.namespace(|| "init poseidon hasher"),
    )?;

    hasher.hash(layouter.namespace(|| "hash"), messages)
}

// TODO: make Element Hashable
pub fn poseidon_hash<const L: usize>(message: [Fr; L]) -> Fr {
   PoseidonHash::<Fr, P128Pow5T3Compact<Fr>, ConstantLength<L>, 3, 2>::init().hash(message)
}

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
pub struct DarkDexCircuit {
    pub token_type: Option<Fr>,
    pub private_note_sum: Option<Fr>,
    pub vault_rand_val: Option<Fr>,
    pub sk: Option<Fq>,
    pub pk: Option<Secp256k1Affine>,
    pub g: Option<Secp256k1Affine>,
    _marker: PhantomData<Fr>,
}

impl DarkDexCircuit {
    pub fn new(token_type: Option<Fr>, private_note_sum: Option<Fr>, vault_rand_val: Option<Fr>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>) -> Self {
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
pub struct DarkDexConfig{
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Fixed>,
    advices: [Column<Advice>; 5],
    key_data: Column<Advice>,
    deposit_identifier_data: Column<Advice>,
    q_enable: Selector,
    q_enable_2: Selector,
    public_inputs: Column<Instance>, /**  private_note_sum_public_val, token_type_id_public_val, deposit_identifier_digest (8 words) */
    fp_chip: FpChip::<Fr>,
    poseidon_config: PoseidonConfig<Fr, 3, 2>,
}


impl Circuit<Fr> for DarkDexCircuit {
    type Config = DarkDexConfig;
    type FloorPlanner = SimpleFloorPlanner;


    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        let path = "config/circuit.config".to_string();
        let params: CircuitParams = serde_json::from_reader(
            File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        )
        .unwrap();

        let fp_chip = FpChip::<Fr>::configure(
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
        let deposit_identifier_data = meta.advice_column();
        let key_data = meta.advice_column();
        let public_inputs = meta.instance_column();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(key_data);
        meta.enable_equality(deposit_identifier_data);
        meta.enable_equality(public_inputs);

        let q_enable = meta.complex_selector();
        let q_enable_2 = meta.complex_selector();

        meta.create_gate("vertical-add", |meta| {
            let w0 = meta.query_advice(deposit_identifier_data, Rotation(0));
            let w1 = meta.query_advice(deposit_identifier_data, Rotation(1));
            let w2 = meta.query_advice(deposit_identifier_data, Rotation(2));
            let w3 = meta.query_advice(deposit_identifier_data, Rotation(3));
            let q_enable = meta.query_selector(q_enable);
            vec![q_enable * ((w0 + w1 + w2) - w3)]
        });
        // ANCHOR: new_gate

        meta.create_gate("big-vertical-add", |meta| {
            let w0 = meta.query_advice(key_data, Rotation(0));
            let w1 = meta.query_advice(key_data, Rotation(1));
            let w2 = meta.query_advice(key_data, Rotation(2));
            let w3 = meta.query_advice(key_data, Rotation(3));
            let w4 = meta.query_advice(key_data, Rotation(4));
            let w5 = meta.query_advice(key_data, Rotation(5));
            let w6 = meta.query_advice(key_data, Rotation(6));
            let w7 = meta.query_advice(key_data, Rotation(7));
            let w8 = meta.query_advice(key_data, Rotation(8));
            let w9 = meta.query_advice(key_data, Rotation(9));
            let q_enable_2 = meta.query_selector(q_enable_2);
            vec![q_enable_2 * ((w0 + w1 + w2 + w3 + w4 + w5 + w6 + w7 + w8) - w9)]
        });

        /// Poseidon config
        /// 
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        meta.enable_constant(lagrange_coeffs[0]);

        let poseidon_config = PoseidonChip::configure::<P128Pow5T3Fr>(
            meta,
            advices[1..4].try_into().unwrap(),
            advices[0],
            lagrange_coeffs[0..3].try_into().unwrap(),
            lagrange_coeffs[3..6].try_into().unwrap(),
        );
         
        ////
        
        DarkDexConfig{ a, b, c, advices, key_data, deposit_identifier_data, q_enable, q_enable_2, public_inputs, fp_chip, poseidon_config}
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>
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
                let ecc_chip = EccChip::<Fr, FpChip<Fr>>::construct(fp_chip.clone());

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

                let fq_chip = fp::FpConfig::<Fr, Fq>::construct(
                    base_chip.range.clone(),
                    base_chip.limb_bits,
                    base_chip.num_limbs,
                    modulus::<Fq>(),
                );

                let sk_assigned = fq_chip.load_private(
                    ctx,
                    fp::FpConfig::<Fr, Fq>::fe_to_witness(
                        &self.sk.map_or(Value::unknown(), Value::known),
                    ),
                );

                let var_window_bits: usize = 4;

                let mul = scalar_multiply::<Fr, _, Secp256k1Affine>(
                    &base_chip,
                    ctx,
                    &g_assigned,
                    &sk_assigned.truncation.limbs,
                    base_chip.limb_bits,
                    var_window_bits,
                );
                
                let x_eq = base_chip.is_equal(ctx, &pk_assigned.x, &mul.x);
                let y_eq = base_chip.is_equal(ctx, &pk_assigned.y, &mul.y);


                let mut key_limbs_data: Vec<AssignedValue<Fr>> = sk_assigned.truncation.limbs.clone();
                let mut pk_x_limbs_data: Vec<AssignedValue<Fr>> = pk_assigned.x.truncation.limbs.clone();
                key_limbs_data.append(&mut pk_x_limbs_data);
                let mut pk_y_limbs_data: Vec<AssignedValue<Fr>> = pk_assigned.y.truncation.limbs.clone();
                key_limbs_data.append(&mut pk_y_limbs_data);

                Ok((x_eq, y_eq, key_limbs_data))
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

                let fix = region.assign_fixed( || "", config.c, 0,  || Value::known(Fr::one())).unwrap().cell();

                let _ = region.constrain_equal(cell_x, res.0.cell()).unwrap();
                let _ = region.constrain_equal(cell_y, res.1.cell()).unwrap();
                let _ = region.constrain_equal(cell_x, fix).unwrap();
                let _ = region.constrain_equal(cell_y, fix).unwrap();
                Ok(())
            }
        ).unwrap();


        let key_limbs_data = res.2;
        let key_elements_sum = layouter.assign_region(
            || "asssign key data and sum limbs",
            |mut region| {

                let mut assigned_cells: Vec<AssignedCell<Fr, Fr>> =  Vec::new();

                for i in 0..9 {
                    let val = key_limbs_data[i].value.clone();
                    let cell_ = region
                    .assign_advice(|| "", config.key_data, i, || val)
                    .expect("assign copy advice should not fail");
                    assigned_cells.push(cell_);
                }

                for i in 0..9 {
                    let _ = region.constrain_equal(key_limbs_data[i].cell, assigned_cells[i].cell()).unwrap();
                }

                let w0 = assigned_cells[0].value();
                let w1 = assigned_cells[1].value();
                let mut sum = w0.and_then(|w0| w1.and_then(|w1| Value::known((*w0) + (*w1))));
                for i in 2..9 {
                    let w3 = assigned_cells[i].value();
                    sum = sum.and_then(|sum| w3.and_then(|w3| Value::known(sum + (*w3))));
                }

                let cell_sum = region
                    .assign_advice(|| "", config.key_data, 9, || sum)
                    .expect("assign copy advice should not fail");

                
                config.q_enable_2.enable(&mut region, 0)?;

                Ok(cell_sum)
            }
        ).unwrap();

        let deposit_identifier_data = layouter.assign_region(
            || "asssign private note sum & token type & vault rand val",
            |mut region| {
                
                let cell_private_note_sum = region
                    .assign_advice(|| "", config.deposit_identifier_data, 0, || self.private_note_sum.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");

                let cell_token_type = region
                    .assign_advice(|| "", config.deposit_identifier_data, 1, || self.token_type.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");

                let cell_vault_rand_val = region
                    .assign_advice(|| "", config.deposit_identifier_data, 2, || self.vault_rand_val.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");

                let w0 = cell_private_note_sum.value();
                let w1 = cell_token_type.value();
                let w2 = cell_vault_rand_val.value();

                let w3 = w0.and_then(|w0| w1.and_then(|w1| Value::known((*w0) + (*w1))));
                let w4 = w2.and_then(|w2| w3.and_then(|w3| Value::known((*w2) + w3)));

                let cell_sum = region
                    .assign_advice(|| "", config.deposit_identifier_data, 3, || w4)
                    .expect("assign copy advice should not fail");

                config.q_enable.enable(&mut region, 0)?;

                Ok(([cell_private_note_sum.cell(), cell_token_type.cell()], cell_sum))
            }
        ).unwrap();

        let deposit_identifier_data_sum: AssignedCell<Fr, Fr> = deposit_identifier_data.1;

        let hash = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "poseidon check"),
            [key_elements_sum, deposit_identifier_data_sum],
        )?;

        for i in 0..2 {
            layouter.constrain_instance(deposit_identifier_data.0[i], config.public_inputs, i)?;
        }

        layouter.constrain_instance(hash.cell(), config.public_inputs, 2)?;

        
        Ok(())
    }
}


#[test]
fn simple_test() {
    let sk_raw = random::<u64>();
    let token_type_raw = 1u64;
    let private_note_sum_raw = 1000u64;
    let vault_rand_val_raw = 111u64;

    //println!("sk_raw = {:#x}", sk_raw);

    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk_raw);
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let g = Secp256k1Affine::generator();
    
    let token_type = Fr::from(token_type_raw);
    let private_note_sum = Fr::from(private_note_sum_raw);
    let vault_rand_val = Fr::from(vault_rand_val_raw);

    let deposit_identifier_data_sum  = token_type + private_note_sum + vault_rand_val;

    /*for val in  pk.x.to_bytes() {
        println!("d@ = {:#x}", val);
    }*/

    let pk_x_limb_0 = consume_uint128_11(&pk.x.to_bytes().to_vec()[0..11]);
    let pk_x_limb_1 = consume_uint128_11(&pk.x.to_bytes().to_vec()[11..22]);
    let pk_x_limb_2 = consume_uint128_10(&pk.x.to_bytes().to_vec()[22..]);

    let pk_y_limb_0 = consume_uint128_11(&pk.y.to_bytes().to_vec()[0..11]);
    let pk_y_limb_1 = consume_uint128_11(&pk.y.to_bytes().to_vec()[11..22]);
    let pk_y_limb_2 = consume_uint128_10(&pk.y.to_bytes().to_vec()[22..]);


    let key_data_sum = (sk_raw as u128) + pk_x_limb_0 + pk_x_limb_1 + pk_x_limb_2 + pk_y_limb_0 + pk_y_limb_1 + pk_y_limb_2;

    let key_data_sum = Fr::from_u128(key_data_sum);


    let digest = poseidon_hash([key_data_sum, deposit_identifier_data_sum]);


    let mut pub_inputs = vec![private_note_sum, token_type, digest];
    

    let circuit: DarkDexCircuit = DarkDexCircuit::new(Some(token_type), Some(private_note_sum), Some(vault_rand_val), Some(sk), Some(pk), Some(g));

    let prover = MockProver::run(18, &circuit, vec![pub_inputs]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
