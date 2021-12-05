use ring::hmac;
use ring::digest::{Context, SHA256};
use data_encoding::BASE64;
use data_encoding::HEXUPPER;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

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
    return b64_encoded_sig;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
