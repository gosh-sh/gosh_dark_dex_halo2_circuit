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
    //pub vault_rand_val: Option<Fr>,
    pub sk: Option<Fr>,
    pub sk_commitment: Option<Fr>,
    _marker: PhantomData<Fr>,
}

impl DarkDexCircuit {
    pub fn new(token_type: Option<Fr>, private_note_sum: Option<Fr>, /*vault_rand_val: Option<Fr>,*/ sk: Option<Fr>, sk_commitment: Option<Fr>) -> Self {
        Self {
            token_type,
            private_note_sum,
            //vault_rand_val,
            sk,
            sk_commitment,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct DarkDexConfig{
    advices: [Column<Advice>; 5],
    key_data: Column<Advice>,
    deposit_identifier_data: Column<Advice>,
    public_inputs: Column<Instance>, /**  private_note_sum_public_val, token_type_id_public_val, deposit_identifier_digest (8 words) */
    poseidon_config: PoseidonConfig<Fr, 3, 2>,
}


impl Circuit<Fr> for DarkDexCircuit {
    type Config = DarkDexConfig;
    type FloorPlanner = SimpleFloorPlanner;


    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        let deposit_identifier_data = meta.advice_column();
        let key_data = meta.advice_column();
        let public_inputs = meta.instance_column();
        meta.enable_equality(key_data);
        meta.enable_equality(deposit_identifier_data);
        meta.enable_equality(public_inputs);

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
         
        DarkDexConfig{ advices, key_data, deposit_identifier_data, public_inputs, poseidon_config}
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>
    ) -> Result<(), plonk::Error> {

        let key_cell = layouter.assign_region(
            || "asssign sk key data",
            |mut region| {
                let cell_sk = region
                    .assign_advice(|| "", config.key_data, 0, || self.sk.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");
                let cell_padd = region
                    .assign_advice(|| "", config.key_data, 1, || Value::known(Fr::zero()))
                    .expect("assign copy advice should not fail");
                Ok((cell_sk, cell_padd))
            }
        ).unwrap();

        let hash = poseidon_hash_gadget(
            config.poseidon_config.clone(),
            layouter.namespace(|| "poseidon check (sk_commitment)"),
            [key_cell.0.clone(), key_cell.1],
        )?;

        let deposit_identifier_cells = layouter.assign_region(
            || "asssign sk_commitment & private note sum & token type & vault rand val",
            |mut region| {

                let cell_sk_commitment = region
                    .assign_advice(|| "", config.deposit_identifier_data, 0, || self.sk_commitment.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");
                
                let cell_private_note_sum = region
                    .assign_advice(|| "", config.deposit_identifier_data, 1, || self.private_note_sum.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");

                let cell_token_type = region
                    .assign_advice(|| "", config.deposit_identifier_data, 2, || self.token_type.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");

                /*let cell_vault_rand_val = region
                    .assign_advice(|| "", config.deposit_identifier_data, 3, || self.vault_rand_val.map_or(Value::unknown(), Value::known))
                    .expect("assign copy advice should not fail");*/

                region.constrain_equal(cell_sk_commitment.cell(), hash.cell()).unwrap();

                Ok([cell_sk_commitment, cell_private_note_sum, cell_token_type/*, cell_vault_rand_val*/])
            }
        ).unwrap();

        for i in 1..3 {
            layouter.constrain_instance(deposit_identifier_cells[i].cell(), config.public_inputs, i - 1)?;
        }

        let data_to_hash: [AssignedCell<Fr, Fr>; 4] = [deposit_identifier_cells[0].clone(), deposit_identifier_cells[1].clone(), deposit_identifier_cells[2].clone(), key_cell.0.clone()];


        let final_hash = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "final poseidon check"),
            data_to_hash,
        )?;

        
        layouter.constrain_instance(final_hash.cell(), config.public_inputs, 2)?;

        
        Ok(())
    }
}


#[test]
fn simple_test() {
    let sk_u_raw = random::<u64>();
    let token_type_raw = 1u64;
    let private_note_sum_raw = 1000u64;
    //let vault_rand_val_raw = 111u64;

    println!("sk_u_raw = {:#x}", sk_u_raw);

    let sk_u = Fr::from(sk_u_raw);
    let token_type = Fr::from(token_type_raw);
    let private_note_sum = Fr::from(private_note_sum_raw);
    //let vault_rand_val = Fr::from(vault_rand_val_raw);

    let sk_u_commitment = poseidon_hash([sk_u, Fr::zero()]);

    let data_to_hash = [sk_u_commitment, private_note_sum, token_type/*, vault_rand_val*/, sk_u];

    let digest = poseidon_hash(data_to_hash);

    let mut pub_inputs = vec![private_note_sum, token_type, digest];

    let circuit: DarkDexCircuit = DarkDexCircuit::new(Some(token_type), Some(private_note_sum), /*Some(vault_rand_val),*/ Some(sk_u), Some(sk_u_commitment));

    let prover = MockProver::run(8, &circuit, vec![pub_inputs]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

}
