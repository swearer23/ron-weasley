# !/bin/bash
SECRET="b890e313d295f063ab2bc0dda8bc8a6dee111c2d7ed58b75d5147358d0fa0643af429372ca664a175635f5fb9cd278bb29f5cdd59cf0bbffb7a5fa162fd77ce6" VALID_DOMAIN="localhost,zspxyi.xyz,vercel.app" ENV="PROD" wasm-pack build --out-name "enigma" --target=bundler --release
