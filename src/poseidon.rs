use halo2_proofs::dev::MockProver;
use rand_chacha::ChaCha8Rng;
use std::time::{Duration, Instant};

use halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr, G1Affine},
    group::ff::PrimeField,
};

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG as Params, ParamsVerifierKZG as ParamsVerifier,
};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};

use poseidon_base::primitives::{
    CachedSpec, ConstantLength, Hash as PoseidonHash, P128Pow5T3, P128Pow5T3Compact, Spec,
};

pub use poseidon_circuit::poseidon::{Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig};
use poseidon_circuit::{
    Hashable,
    poseidon::{
        //primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3},
        Hash,
    },
};
use rand::thread_rng;

use rand::SeedableRng;

pub type P128Pow5T3Fr = P128Pow5T3<Fr>;

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

#[derive(Clone, Default, Debug)]
pub struct Signature {
    /// Secret key for the address, required to spend a note
    pub secret_key: u64,
    /// Message to be signed
    pub message: u64,
}

impl Signature {
    pub fn new(secret_key: u64, message: u64) -> Self {
        Self {
            secret_key,
            message,
        }
    }

    pub fn enforce_constraints(
        &self,
        mut layouter: impl Layouter<Fr>,
        advice: Column<Advice>,
        instance: Column<Instance>,
        poseidon_config: PoseidonConfig<Fr, 3, 2>,
    ) -> Result<(), Error> {
        let message = layouter.namespace(|| "message witness").assign_region(
            || "message",
            |mut region| {
                region.assign_advice(
                    || "load advice",
                    advice,
                    0,
                    || Value::known(Fr::from(self.message)),
                )
            },
        )?;

        let secret_key = layouter.namespace(|| "secret key witness").assign_region(
            || "secret_key",
            |mut region| {
                region.assign_advice(
                    || "load advice",
                    advice,
                    0,
                    || Value::known(Fr::from(self.secret_key)),
                )
            },
        )?;

        let padding = layouter.namespace(|| "padding witness").assign_region(
            || "padding witness",
            |mut region| {
                region.assign_advice_from_constant(|| "load constant advice", advice, 0, Fr::zero())
            },
        )?;

        let address_from_private_key = poseidon_hash_gadget(
            poseidon_config,
            layouter.namespace(|| "address from pk"),
            [secret_key, padding],
        )?;

        // Constrain address to be the same as verified address
        layouter.constrain_instance(address_from_private_key.cell(), instance, 0)?;

        // Constrain message witness
        layouter.constrain_instance(message.cell(), instance, 1)?;

        Ok(())
    }

    pub(crate) fn address(&self) -> Fr {
        poseidon_hash([Fr::from(self.secret_key), Fr::zero()])
    }

    pub(crate) fn public_inputs(&self) -> Vec<Fr> {
        vec![self.address(), Fr::from(self.message)]
    }
}

#[derive(Clone, Debug)]
pub struct CircuitConfig {
    advices: [Column<Advice>; 5],
    instance: Column<Instance>,
    poseidon_config: PoseidonConfig<Fr, 3, 2>,
}

impl Circuit<Fr> for Signature {
    type FloorPlanner = SimpleFloorPlanner;
    type Config = CircuitConfig;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

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

        CircuitConfig {
            advices,
            instance,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        self.enforce_constraints(
            layouter.namespace(|| "signature"),
            config.advices[0],
            config.instance,
            config.poseidon_config,
        )?;

        Ok(())
    }
}

#[test]
fn poseidon_hash_snapshot() {
    let result = poseidon_hash([Fr::from_u128(2), Fr::from_u128(3)]);

    let v = [1u8; 32];

    // make sure the debug representation doesn't change so we can change the hash impl
    assert_eq!(
        format!("{result:?}"),
        "0x19014d18a3179c5731155fcb7b6da422f456bccbd6da9dbc7df0f8dc6d4938ed"
    );
}

#[test]
fn test() {
    let k = 6;

    let sk = 100u64;
    let message = 200u64;

    let circuit = Signature::new(sk, message);
    let instance_columns = vec![circuit.public_inputs()];

    // Prove mock
    let prover = MockProver::<Fr>::run(k, &circuit, instance_columns).unwrap();
    prover.assert_satisfied();

    let params = Params::<Bn256>::unsafe_setup(k);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk should not fail");

    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let now = Instant::now();

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

    let pub_ = circuit.public_inputs();

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&pub_]],
        os_rng,
        &mut transcript,
    )
    .unwrap();

    let proof_script = transcript.finalize();

    let end = now.elapsed().as_millis();
    println!("proof generation time: {:?}", end);

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier_params().clone();
    let strategy = SingleStrategy::new(&params);

    //let vk = keygen_vk(&params, &circuit).unwrap();

    let empty_circuit = Signature::default();
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let now = Instant::now();

    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &verifier_params,
            &vk_from_empty.clone(),
            strategy,
            &[&[&pub_]],
            &mut transcript
        )
        .is_ok()
    );

    let end = now.elapsed().as_millis();
    println!("verification time: {:?}", end);
}
