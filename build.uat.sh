# !/bin/bash
SECRET="123456" VALID_DOMAIN="longfor.com,longhu.net" ENV="UAT" wasm-pack build --out-name "enigma-uat" --target=bundler --release
