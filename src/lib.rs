extern crate wasm_bindgen;

use ring::hmac;
use ring::digest::{Context, SHA256};
use data_encoding::BASE64;
use data_encoding::HEXUPPER;
use wasm_bindgen::prelude::*;
use web_sys;
use uuid::Uuid;

struct UUID_Group {
    uuid: str,
    obfuscated_uuid: str,
    random_factor: i64
}

struct Signature_factors {
    uuid: str,
    signature: str
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

    let der_bytes = Base64::decode(&der_encoded).expect("failed to decode base64 content");
    let keypair = PKey::private_key_from_der(&der_bytes).expect("failed to parse private key");

    let data = b"hello, world!";

    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(data).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let signature_base64 = Base64::encode(signature);
}

fn generate_cnonce() -> String {
    let uuid = Uuid::new_v4();
    let mut rng = rand::thread_rng();
    let random_factor: i64 = rng.gen_range(0..1000000);
    let public_factor: i64 = random_factor * 19801;
    let obsfucated_factor: i64 = public_factor * 20201;

    let mut uuid_str = uuid.to_simple().to_string();
    let public_factor_str = public_factor.to_string();
    uuid_str.push_str(&public_factor_str);
    return UUID_Group {
        uuid: uuid.to_simple().to_string(),
        obfuscated_uuid: uuid_str,
        random_factor: random_factor.to_string()
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
pub fn ron_weasley_sign (message: &str) -> Result<String, JsError> {

    let valid_window: bool = valid_window_domain();

    if !valid_window {
        log("invalid window");
        return Err(JsError::new("invalid browser environment"))
    }

    const private_key: &str = std::env!("PRIVATE_KEY");


    let cnonce_group = generate_cnonce();

    // hash message, origin uuid, and random factor
    let mut context = Context::new(&SHA256);
    context.update(format!("{}|{}|{}", cnonce_group.uuid, cnonce_group.random_factor, message).as_bytes());
    let sha256_result = context.finish();
    let sha256_result_str = format!("{}", HEXUPPER.encode(sha256_result.as_ref()));

    // rsa signature of rsa private key and sha256 hash as salt
    let salt = rsa_signature(private_key, sha256_result_str);

    // hmac sign by salt and sha256 hash
    let key = hmac::Key::new(hmac::HMAC_SHA512, salt.as_bytes());
    let mac = hmac::sign(&key, sha256_result_str.as_bytes());
    let b64_encoded_sig = BASE64.encode(mac.as_ref());
    Ok(Signature_factors {
        uuid: cnonce_group.obfuscated_uuid,
        signature: b64_encoded_sig.to_uppercase()
    })
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
