///
/// In order for the program to work, openssl needs to be installed and some environment variables
/// must be set up. For Windows 11, the environment variables to set up are:
/// - OPENSSL_DIR=C:\Program Files\OpenSSL-Win64
/// - OPENSSL_LIB_DIR=C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD
/// - OPENSSL_LIB_INCLUDE=C:\Program Files\OpenSSL-Win64\include
/// - OPENSSL_STATIC=no
///
/// For more information, check out rust-openssl crate.io page (https://crates.io/crates/openssl)
///

use std::error::Error;
use std::time::Instant;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use josekit::{
    jwk::Jwk,
    jwk::alg::ec::EcCurve,
    jws::ES256,
    jws::JwsHeader,
    jwt,
    jwt::JwtPayload
};
use sd_jwt_payload::{Disclosure, SdJwt, SdObjectDecoder, SdObjectEncoder};
use serde_json::{Map, Value};
use csd::csd_encoder::CsdEncoder;
use csd::csd_jwt::CsdJwt;
use csd::csd_decoder::CsdDecoder;

mod accumulator;
mod state;
mod csd;

///
/// Simulates CSD-JWT
///
fn accumulator_based<C: Pairing>(object: Value, concealments: Vec<&str>) -> Result<(), Box<dyn Error>> {

    let mut encoder: CsdEncoder<C> = object.try_into()?;
    for concealment in concealments {
        _ = encoder.conceal(concealment);
    }
    encoder.add_sd_alg_property();
    // println!("encoded object: \n{}\n", serde_json::to_string_pretty(encoder.object()?)?);

    let mut header = JwsHeader::new();
    header.set_token_type("csd-jwt");
    let payload = JwtPayload::from_map(encoder.object()?.clone())?;

    let jwk: Jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    let signer = ES256.signer_from_jwk(&jwk)?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    let sd_jwt: CsdJwt = CsdJwt::new(jwt.clone(), None);
    let sd_jwt: String = sd_jwt.presentation();

    let sd_jwt: CsdJwt = CsdJwt::parse(&sd_jwt)?;
    let verifier = ES256.verifier_from_jwk(&jwk)?;
    let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &verifier)?;

    let now = Instant::now();
    let decoder: CsdDecoder<C> = CsdDecoder::new();
    let decoded = decoder.decode(payload.claims_set())?;
    // println!("decoded object: \n{}\n", serde_json::to_string_pretty(&decoded)?);
    let result = decoder.validate_object(decoded.clone())?;
    let elapsed = now.elapsed().as_micros();
    println!("{:.2?}", elapsed);
    assert!(result);

    Ok(())
}


///
/// Simulates classical SD-JWT
///
fn hash_based(object: Value, concealments: Vec<&str>) -> Result<(), Box<dyn Error>> {

    let mut encoder: SdObjectEncoder = object.try_into()?;
    let disclosures: Vec<Disclosure> = concealments.iter().map(|concealment| {encoder.conceal(concealment, None)}.unwrap()).collect::<Vec<Disclosure>>();
    // encoder.add_sd_alg_property();
    // println!("encoded object: {}", serde_json::to_string_pretty(encoder.object()?)?);

    let mut header = JwsHeader::new();
    header.set_token_type("sd-jwt");
    let payload = JwtPayload::from_map(encoder.object()?.clone())?;

    let jwk: Jwk = Jwk::generate_ec_key(EcCurve::P256).unwrap();
    let signer = ES256.signer_from_jwk(&jwk)?;
    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;
    let disclosures: Vec<String> = disclosures
        .into_iter()
        .map(|disclosure| disclosure.to_string())
        .collect();
    let sd_jwt: SdJwt = SdJwt::new(jwt.clone(), disclosures.clone(), None);
    let sd_jwt: String = sd_jwt.presentation();

    let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt)?;
    let verifier = ES256.verifier_from_jwk(&jwk)?;
    let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &verifier)?;

    let decoder = SdObjectDecoder::new_with_sha256();
    let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures)?;
    // println!("decoded object: {}", serde_json::to_string_pretty(&decoded)?);

    Ok(())
}


///
/// Creates a map with dummy claims
///
fn populate_map(claim_map: &mut Map<String, Value>, n_claims: usize) {
    for i in 0..n_claims {
        claim_map.insert(
            String::from(format!("Claim Key {}", i)),
            Value::String(String::from(format!("Claim Value {}", i)))
        );
    }
}

///
/// Creates a map with dummy concealments
///
fn populate_concealments(concealments: &mut Vec<String>, n_conceals: usize) {
    for i in 0..n_conceals {
        concealments.insert(i, format!("/Claim Key {}", i));
    }
}

///
/// An element is disclosed by default, it can be concealed by putting the claim name in the conceals map
///
fn main() {

    type C = Bn254;

    println!("Parallel Verification Time in microseconds");
    println!("Claims\tVerification Time");
    for n_claims in 1..= 100 {
        print!("({:03})\t", n_claims);

        let mut claim_map: Map<String, Value> = Map::new();
        populate_map(&mut claim_map, n_claims);
        let claims: Value = Value::from(claim_map);

        let mut concealments: Vec<String> = vec![];
        populate_concealments(&mut concealments, 1);
        let concealments = concealments.iter().map(move |x| { x.as_str() }).collect::<Vec<&str>>();
        accumulator_based::<C>(claims.clone(), concealments.clone()).unwrap();

        // Doesn't work without everything undisclosed apparently
        hash_based(claims, concealments).unwrap()
    }
}