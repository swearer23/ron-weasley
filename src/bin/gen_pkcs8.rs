use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};
use data_encoding::BASE64;
use rsa::pkcs8::EncodePrivateKey;

fn main () {
  let mut rng = rand::thread_rng();

  let bits = 2048;
  let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
  let private_key_der = private_key.to_pkcs8_der().unwrap();
  let private_key_base64 = BASE64.encode(private_key_der.as_bytes());
  println!("private_key_base64: {}", private_key_base64);
}