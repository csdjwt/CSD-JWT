# CSD-JWT
___
Proof of concept written in Rust for the paper **CSD-JWT: Compact and Selective Disclosure for
Verifiable Credentials** using the [`sd-jwt-payload`](https://crates.io/crates/sd-jwt-payload), and [`vb-accumulator`](https://crates.io/crates/vb_accumulator) crates.
The code grants high-level functions to create VCs and VPs using cryptographic accumulators instead of salted hashes.
___
The permitted operations are: 
* ***Encoding***: transformation of a set of claims expressed either as a Map or as a JSON Value into a VC and a VP.
* ***Decoding***: transformation of a VC or a VP into a set of claims. 
* ***Verification***: parallel verification of disclosed claims with accumulator's witnesses.
___
## Encoding
Just as in the `sd-jwt-payload` library any JSON object can be encoded. Another way to encode data in the CSD-JWT is 
by adding each key-value to a `serde_json::Map` via `insert`. In both cases, the encoder's creation has been kept
the same as in the library. The `CsdEncoder` object receives a Pairing type as generic type.
```
let map: Map<String, Value> = serde_json::Map::new()
map.insert(
    String::from(format!("Claim Key {}", i)),
    Value::String(String::from(format!("Claim Value {}", i)))
);
let object: Value = Value::from(map);
let mut encoder: CsdEncoder<Bn254> = object.try_into()?;
```
The encoder permits to conceal claims via:
```
_ = encoder.conceal(conceal)
```
where the concealment object is a vector of &str in the format `"/Claim Key {}"`
```
let payload = JwtPayload::from_map(encoder.object()?.clone())?
```
The jwt encoding is performed once again with the `josekit` library.
## Decoding
After having decoded the jwt object using the `josekit` library, it's possible to properly decode the map object using
`CsdDecoder`
The object decoder has been kept similar to the original implementation as well, but it's simplified since it doesn't 
need a hasher, but rather a pairing type. 
```
let decoder: CsdDecoder<Bn254> = CsdDecoder::new();
let decoded: Map<String,Value> = decoder.decode(payload.claims_set())?;
```

## Verification
After Decoding, it's possible to verify the decoded object by invoking CsdDecoder's `validate_object` function 
```
let result = decoder.validate_object(decoded.clone())?;
```

___
All the raw data gathered from tests is in the */results/* folder.