use data_encoding::BASE64;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;

fn main () {
  let private_key = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBsD9cej0UM9+Co1xKMb0m1Fh3b738VBppEq2bioAJmntVCFrO+Nx3aAAETqhmtg5QNP8hM5ivz8GbD5H/Dj0Dh64YWa42cKwlXpuJlTfqCcMlXsPdTkcEPmmppoTooz9HaQnWxe1MagZSxJBYxLDxU2uYDIW064LVfrV7CdSS2sR3PlsE1dPBDT3oEA4tkbuCdykrc25ngv0kNaGNhsRA/dSghbTzQEAW68sbxDr/afy5hkpzP7B5Px2vcRsyyC00gbgwMIDi1Vp3Rh82DZ+rTmwoUtNtwXo3RKrCYqZTYJwxwNOcJz470DEyJC/x2qM3QM7e5YSWeCvscXet6WMVAgMBAAECggEBAKqbU4Riy/BCrOsGeCGGZGWSf4Zc8A0WC9lnsXIjchqDb4V8AXjz7kZjXjhtDJrEXCE8PUqCh0i9iHzMHz55zTaRycD7JaAgaRHVns12mbTV+oWtTnteGuHbE/lyivnb6b4+AIOk/hvj/EPljnwSbQV1BH3+8btmA22I2dRR2WOsMmFe53i7kvP0m4bUdGNBXaJyM8OipHkoHnkHqSopJoj2cbFF3NPiIz7YJnz6MbDrdYWoX+yVDCjnyc9q/b1HRYCXj3f6zQvvRoM/jKN2rlW+4Rlrr+Q9fYD3JMqticg3nQpXnRzEyvbPnoh5mu7y8rlGI1Wdu3cnqacLwW350JUCgYEAxVUW1qnfLQrSIQTlBNu/7f/Pw+BNCRe0ItnE1oA4yQTcCoe2aEsA7y1nTml6DVRei/EUKnmK760hUf6c6/w5QnuKmkPmWDOb/UqhV/ieoxqMXj9fr9/zfH2OK5U8QEq86bbI9k8R3qx20zqffPkdG/RHmlPgjLiD3h/kh4zoG1sCgYEA+0XSNUF7T6y6t95ACbu6tkKfWaqk8EAw4NKH8zw7GZSwHNuga43+h4nZ5JLRfq4c4VEK+NOM4dX3TLG8AYRh1ueT6uU00baEhm/HoX32AV3GsZVTgdpeExby6Ux5mqt98HWd+wnNGAWMUL8oViSKxUeJj1AZoid+awLve6mXdk8CgYEAhpnexTgD+jZaVJmBGgpG5bHLZ2G1SlF31xnR8TpvAXcmHKyrmIIotfyzbcH2tebpwu0Dg2F6irf+dW6GXVWjPR0F0uoj0eAKNADXAymcE8dFHfh+bXoGHNGLy2C1Q2l3aLf8Zj5TAx+CwdxH87f8yhebS8KQ9YvarwX0HR3ZKOcCgYAJjPbXdVy1g5A5SuZOOGd5ZADgjJ7mTtpMwVPPh/uLFl63ShXH4MbK6g9xI694zC9m1QjAunHBZ7uVm6/Usu5xF65EoF+olPJmlbsVxU7jcGgL+ewJpH4s5ZNoELMSkPAhgqb1ksLL5fIWY52p4Iuxwe1VmCrRQgUJFjx6C9Eo+wKBgEQnL6qdoJrPKEju1zLbhteKrm26u01Xpv8V+2+Q/cqlr0NGfrvPQy8/ymE12djTnM6xn6mUbQD6swSeOu3scCpe5VvbbnV/JjYjRQa4DMcJ+oPRGwKsqvL0igr5yhHzibRgv7pydWblm7LBAlU19baIpG4yIiWk1bdHfmOiyD4T
-----END RSA PRIVATE KEY-----
"#;
  let der_encoded = private_key 
    .lines()
    .filter(|line| !line.starts_with("-"))
    .fold(String::new(), |mut data, line| {
        data.push_str(&line);
        data
    });

  let der_bytes = BASE64.decode(&der_encoded.as_bytes()).expect("failed to decode base64 content");

  let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&der_bytes).unwrap();

  let public_key = rsa_private_key.to_public_key();

  let public_key_der = public_key.to_pkcs1_der().unwrap();

  let public_key_base64 = BASE64.encode(public_key_der.as_bytes());

  println!("public key: {}", public_key_base64);
}