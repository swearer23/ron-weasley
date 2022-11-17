use std::env;

fn main() {
  println!("cargo:rustc-env=PRIVATE_KEY={}", env!("PRIVATE_KEY"));
}