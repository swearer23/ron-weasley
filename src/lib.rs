extern crate wasm_bindgen;

use ring::hmac;
use ring::digest::{Context, SHA256};
use data_encoding::BASE64;
use data_encoding::HEXUPPER;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn ron_weasley_sign (message: &str, cnonce: &str) -> String {
    const SECRET: &str = std::env!("SECRET");

    let mut context = Context::new(&SHA256);
    context.update(format!("{}|{}", cnonce, message).as_bytes());
    let sha256_result = context.finish();
    let sha256_result_str = format!("{}", HEXUPPER.encode(sha256_result.as_ref()));

    let key = hmac::Key::new(hmac::HMAC_SHA512, SECRET.as_bytes());
    let mac = hmac::sign(&key, sha256_result_str.as_bytes());
    let b64_encoded_sig = BASE64.encode(mac.as_ref());
    return b64_encoded_sig.to_uppercase();
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
