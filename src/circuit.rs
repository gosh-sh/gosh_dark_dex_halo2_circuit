use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{bn256::Fr, secp256k1::{Fp, Fq, Secp256k1Affine}},
    plonk::Fixed,
};

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
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Error},
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

#[derive(Default)]
pub struct DarkDexCircuit<F: PrimeField> {
    pub token_type: Option<F>,
    pub private_note_sum: Option<F>,
    pub sk: Option<Fq>,
    pub pk: Option<Secp256k1Affine>,
    pub g: Option<Secp256k1Affine>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> DarkDexCircuit<F> {
    pub fn new(token_type: Option<F>, private_note_sum: Option<F>, sk: Option<Fq>, pk: Option<Secp256k1Affine>, g: Option<Secp256k1Affine>) -> Self {
        Self {
            token_type,
            private_note_sum,
            sk,
            pk,
            g,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DarkDexConfig<F: PrimeField> {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Fixed>,
    token_type_id_internal: Column<Advice>,
    private_note_sum_internal: Column<Advice>,
    public_inputs: Column<Instance>, /** token_type_id_public_val, private_note_sum_public_val */
    fp_chip: FpChip::<F>

}

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
        DarkDexConfig{ a, b, c,  token_type_id_internal, private_note_sum_internal, public_inputs, fp_chip}
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

        Ok(())
    }
}


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
