extern crate vb_accumulator;

use ark_ff::PrimeField;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{prelude::StdRng, SeedableRng};
use sha3::{Digest, Sha3_256};
use vb_accumulator::{
    positive::PositiveAccumulator,
    prelude::MembershipWitness,
    setup::Keypair,
    setup::PublicKey,
    setup::SetupParams,
};
use vb_accumulator::positive::Accumulator;
use base64;
use base64::Engine;
use crate::state::InMemoryState;


pub fn generate_params<C: Pairing>(param_seed: u64) -> SetupParams<C> {

    SetupParams::<C>::generate_using_rng(&mut StdRng::seed_from_u64(param_seed))

}

///
/// initialize_accumulator(seed: u64) -> (SetupParams<C>, Keypair<C>, PositiveAccumulator<C>, InMemoryState<Fr>)
///
/// This function uses a seed to initialize the accumulator and every single variable needed to add,
/// remove, generating witnesses and verifying them including, of course, the ecc key pair.
///

pub fn initialize_accumulator<C: Pairing>(key_seed: u64, param_seed: u64) -> (SetupParams<C>, Keypair<C>, PositiveAccumulator<C>, InMemoryState<C::ScalarField>) {

    let params = generate_params(param_seed);
    let keypair = Keypair::<C>::generate_using_rng(&mut StdRng::seed_from_u64(key_seed), &params);
    let accumulator = PositiveAccumulator::initialize(&params);
    let state: InMemoryState<C::ScalarField> = InMemoryState::new();

    (params, keypair, accumulator, state)

}

///
/// scalar_from_str(string: &str) -> Fr
///
/// This function takes in input a string and converts it into a scalar number that can be
/// accumulated into the accumulator by hashing using sha3_256 and treating the result as a 256 bit
/// number
///
pub fn scalar_from_str<S: Pairing>(string: &str) -> S::ScalarField {

    let mut hasher = Sha3_256::new();
    hasher.update(string);
    let result = hasher.finalize();

    S::ScalarField::from_be_bytes_mod_order(&result.as_slice())

}

///
/// serialize_accumulator(accumulator: PositiveAccumulator<C>) -> String
///
/// This function takes in input an accumulator and converts into a string value by mapping the
/// x and y coordinates of the point that represents the accumulator in the curve.
/// Specifically, both the BigNum employed to map these 384 bit coordinates are converted into an
/// array of 6 u64, parsed, concatenated with a ';' for separation.
/// Finally, the two coordinates are concatenated with a '|' for separation.
///
pub fn serialize_accumulator<C: Pairing>(accumulator: PositiveAccumulator<C>) -> String {

    let mut compressed_bytes = Vec::new();
    accumulator.serialize_compressed(&mut compressed_bytes).unwrap();
    base64::engine::general_purpose::STANDARD.encode(compressed_bytes)

}

pub fn serialize_witness<C: Pairing>(witness: MembershipWitness<C::G1Affine>) -> String {

    let mut compressed_bytes = Vec::new();
    witness.serialize_compressed(&mut compressed_bytes).unwrap();
    base64::engine::general_purpose::STANDARD.encode(compressed_bytes)

}

pub fn serialize_pk<C: Pairing>(pk: PublicKey<C>) -> String {

    let mut compressed_bytes = Vec::new();
    pk.serialize_compressed(&mut compressed_bytes).unwrap();
    base64::engine::general_purpose::STANDARD.encode(compressed_bytes)

}


///
/// deserialize_accumulator(coords: String) -> PositiveAccumulator<C>
///
/// This function takes in input a string containing the x and y coordinates of the point that
/// represents the accumulator in the curve. The string must be created previously through
/// serialize_accumulator.
///
pub fn deserialize_accumulator<C: Pairing>(coords: String) -> PositiveAccumulator<C> {

    let decoded = base64::engine::general_purpose::STANDARD.decode(coords).unwrap();
    PositiveAccumulator::deserialize_compressed(&*decoded).unwrap()

}

pub fn deserialize_witness<C: Pairing>(coords: String) -> MembershipWitness<C::G1Affine> {

    let decoded = base64::engine::general_purpose::STANDARD.decode(coords).unwrap();
    MembershipWitness::deserialize_compressed(&*decoded).unwrap()

}

pub fn deserialize_pk<C: Pairing>(coords: String) -> PublicKey<C> {

    let decoded = base64::engine::general_purpose::STANDARD.decode(coords).unwrap();
    PublicKey::deserialize_compressed(&*decoded).unwrap()

}


pub fn acc_demo<C: Pairing>() -> PositiveAccumulator<C> {
    let (params, keypair, accumulator, mut state) = initialize_accumulator::<C>(0u64, 0u64);
    assert!(params.is_valid());
    assert!(keypair.public_key.is_valid());

    let elem = scalar_from_str::<C>("name::Albert Einstein");

    let batch_elem: Vec<C::ScalarField> = vec![
        scalar_from_str::<C>("name::Albert Einstein"),
        scalar_from_str::<C>("address::112 Mercer Street, Princeton, Mercer County, New Jersey, United States"),
        scalar_from_str::<C>("birthdate::14/03/1879"),
        scalar_from_str::<C>("occupation::Theoretical physicist"),
    ];

    println!("New accumulator:\n{:?}\n", accumulator);
    let accumulator = accumulator.add(elem, &keypair.secret_key, &mut state).unwrap();
    println!("Post add accumulator:\n{:?}\n", accumulator);
    let accumulator = accumulator.remove(&elem, &keypair.secret_key, &mut state).unwrap();
    println!("Post remove accumulator (should be equal to new accumulator):\n{:?}\n", accumulator);

    let accumulator = accumulator.add_batch(batch_elem.clone(), &keypair.secret_key, &mut state).unwrap();
    println!("Post add batch accumulator:\n{:?}\n", accumulator);

    let m_wit = accumulator.get_membership_witness(&elem, &keypair.secret_key, &state).unwrap();
    let batch_wit = accumulator.get_membership_witnesses_for_batch(&batch_elem.as_slice(), &keypair.secret_key, &state).unwrap();
    assert!(accumulator.verify_membership(&elem, &m_wit, &keypair.public_key, &params));
    assert!(accumulator.verify_membership(&elem, &batch_wit[0], &keypair.public_key, &params));

    let coords = serialize_accumulator(accumulator.clone());
    println!("{coords}");
    let acc2 = deserialize_accumulator::<C>(coords);
    println!("Serialized accumulator:\n{:?}\n", accumulator);
    println!("Deserialized accumulator:\n{:?}\n", acc2);

    accumulator
}
