extern crate wasm_bindgen;

use data_encoding::BASE64;
use data_encoding::HEXUPPER;
use wasm_bindgen::prelude::*;
use uuid::Uuid;
use rand::Rng;
use serde::{Serialize, Deserialize};
use serde;
use web_sys;
use sha2::{Sha256, Digest};

use rsa::pkcs1v15::{SigningKey};
use rsa::RsaPrivateKey;
use pkcs8::DecodePrivateKey;
use rsa::signature::Signer;

struct CnonceGroup {
    uuid: uuid::Uuid,
    public_factor: i64,
    random_factor: i64
}
#[derive(Serialize, Deserialize)]
struct SignatureFactors {
    cnonce: String,
    signature: String
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

fn rsa_signature (private_key: String, data: &str) -> String {
    let der_encoded = private_key 
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    
    let der_bytes = BASE64.decode(&der_encoded.as_bytes()).expect("failed to decode base64 content");

    let rsa_private_key = match RsaPrivateKey::from_pkcs8_der(&der_bytes) {
        Ok(key) => key,
        Err(err) => return format!("failed to parse private key: {}", err)
    };

    let signing_key = SigningKey::<Sha256>::new(rsa_private_key);

    let signature = signing_key.sign(data.as_bytes());

    let signature_base64 = BASE64.encode(&signature);

    return signature_base64;
}

fn generate_cnonce() -> CnonceGroup {
    let uuid = Uuid::new_v4();
    let mut rng = rand::thread_rng();
    let random_factor: i64 = rng.gen_range(0..1000000);
    let public_factor: i64 = random_factor * 19801;
    // let obsfucated_factor: i64 = public_factor * 20201;

    return CnonceGroup {
        uuid: uuid,
        public_factor: public_factor,
        random_factor: random_factor
    };
}

#[wasm_bindgen]
pub fn valid_window_domain () -> bool {
    let location: web_sys::Location = web_sys::window().unwrap().location();
    let hostname: String = location.hostname().unwrap();
    let valid_hosts = std::env!("VALID_DOMAIN").split(",");
    let mut valid = false;
    for host in valid_hosts {
        if hostname.contains(host) {
            valid = true;
        }
    }
    return valid
}

#[wasm_bindgen]
pub fn ron_weasley_sign () -> Result<JsValue, JsError> {

    let valid_window: bool = valid_window_domain();

    if !valid_window {
        log("invalid window");
        return Err(JsError::new("invalid browser environment"))
    }

    const PRIVATE_KEY: &str = std::env!("PRIVATE_KEY");

    let cnonce_group = generate_cnonce();

    log(&format!("random_factor: {}", cnonce_group.random_factor.to_string()));

    // hash origin uuid, and random factor
    let mut hasher = Sha256::new();
    hasher.update(format!("{}|{}", cnonce_group.uuid.as_simple(), cnonce_group.random_factor.to_string()).as_bytes());
    let sha256_result = hasher.finalize();
    let sha256_result_str = format!("{}", HEXUPPER.encode(sha256_result.as_ref()));

    log(&format!("sha256_result_str: {}", sha256_result_str));

    // // rsa signature of rsa private key and sha256 hash as salt
    let b64_encoded_sig = rsa_signature(PRIVATE_KEY.to_string(), &sha256_result_str);

    // hmac sign by salt and sha256 hash
    let mut obfuscated_uuid_str = cnonce_group.uuid.as_simple().to_string();
    obfuscated_uuid_str.push_str(&(cnonce_group.public_factor.to_string()));
    let result = SignatureFactors {
        cnonce: obfuscated_uuid_str,
        signature: b64_encoded_sig
    };
    Ok(serde_wasm_bindgen::to_value(&result).unwrap())
}

#[cfg(test)]
mod tests {
    use super::ron_weasley_sign;
    #[test]
    fn it_works() {
        let cnonce: &str = "7e638f14-60d8-4ef3-adf7-fa789d072925";
        let message: &str = "hello world";
        let signature: String = ron_weasley_sign(message, cnonce);
        assert_eq!(signature, "CJG/FB6VXGTUDH4V3BVQFPLMY656GGID7/TYEFBMC2D1IUEANW/DK+0KFRRS6Y9PNVW6EL+PLJLFD8X91/JARG==");
    }
}
