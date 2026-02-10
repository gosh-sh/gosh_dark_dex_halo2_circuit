use std::io::Cursor;

use halo2_base::halo2_proofs::{
    circuit::Value,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        pairing::Engine,
    },
    plonk::{self, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
        },
        kzg::{multiopen::ProverSHPLONK, strategy::SingleStrategy},
    },
    SerdeFormat,
    transcript::{Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use halo2_base::utils::testing::{gen_proof, gen_proof_with_instances, check_proof, check_proof_with_instances};
use std::panic;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Creates a proof for the given circuits and instances.
    #[allow(dead_code)]
    pub fn create<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        circuit: C,
        pub_inputs: &Vec<Fr>,
    ) -> Vec<u8> {
        gen_proof_with_instances(&params, &pk, circuit, &[pub_inputs])
    }

    pub fn verify_with_vk_from_bytes<C: Circuit<Fr>>(
        &self,
        mut vk_slice: &[u8],
        params: &ParamsKZG<Bn256>,
        concrete_params: C::Params,
        pub_inputs: &Vec<Fr>,
    ) -> bool  {
        let vk: VerifyingKey<G1Affine> = VerifyingKey::read::<_, C>(&mut vk_slice, SerdeFormat::RawBytesUnchecked, concrete_params).expect("Reading vkey should not fail");
        ;
        match panic::catch_unwind(|| {
            check_proof_with_instances(&params, &vk, &self.0.clone(), &[pub_inputs],  true);
        }) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

   pub fn verify_with_vk_from_path<C: Circuit<Fr>>(
        &self,
        vk_path: String,
        params: &ParamsKZG<Bn256>,
        concrete_params: C::Params,
        pub_inputs: &Vec<Fr>,
    ) -> bool {
        let mut vk_slice: &[u8] = &std::fs::read(vk_path).unwrap();
        self.verify_with_vk_from_bytes::<C>(vk_slice, params, concrete_params, pub_inputs)
    }


    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn value(&self) -> Value<&[u8]> {
        Value::known(self.as_bytes())
    }
}
