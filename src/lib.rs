extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;
use uuid::Uuid;
use rand::Rng;
use ring::{hmac};
use ring::digest::{Context, SHA256};
use serde::{Serialize, Deserialize};
use serde;
use web_sys;
use base64;

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

    const SECRET: &str = std::env!("SECRET");

    let cnonce_group = generate_cnonce();

    log(&format!("random_factor: {}", cnonce_group.random_factor.to_string()));

    // hash origin uuid, and random factor
    let mut context = Context::new(&SHA256);
    context.update(format!(
        "{}|{}",
        cnonce_group.uuid.as_simple(),
        cnonce_group.random_factor.to_string()
    ).as_bytes());
    let sha256_result = context.finish();
    let sha256_result_str = base64::encode(sha256_result.as_ref());

    log(&format!("sha256_result_str: {}", sha256_result_str));

    let key = hmac::Key::new(hmac::HMAC_SHA512, SECRET.as_bytes());
    let mac = hmac::sign(&key, sha256_result_str.as_bytes());
    let b64_encoded_sig = base64::encode(mac.as_ref());

    log(&format!("b64_encoded_sig: {}", b64_encoded_sig));


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
