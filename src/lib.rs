extern crate wasm_bindgen;

use ring::hmac;
use ring::digest::{Context, SHA256};
use data_encoding::BASE64;
use data_encoding::HEXUPPER;
use wasm_bindgen::prelude::*;
use web_sys;

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
pub fn ron_weasley_sign (message: &str, cnonce: &str) -> Result<String, JsError> {

    let valid_window: bool = valid_window_domain();

    if !valid_window {
        log("invalid window");
        return Err(JsError::new("invalid browser environment"))
    }

    const SECRET: &str = std::env!("SECRET");

    let mut context = Context::new(&SHA256);
    context.update(format!("{}|{}", cnonce, message).as_bytes());
    let sha256_result = context.finish();
    let sha256_result_str = format!("{}", HEXUPPER.encode(sha256_result.as_ref()));

    let key = hmac::Key::new(hmac::HMAC_SHA512, SECRET.as_bytes());
    let mac = hmac::sign(&key, sha256_result_str.as_bytes());
    let b64_encoded_sig = BASE64.encode(mac.as_ref());
    Ok(b64_encoded_sig.to_uppercase())
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
