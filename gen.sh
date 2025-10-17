#!/bin/bash

echo =========================================================pilout

cargo run --release --bin keccakf_fixed_gen
cargo run --release --bin arith_frops_fixed_gen
cargo run --release --bin binary_basic_frops_fixed_gen
cargo run --release --bin binary_extension_frops_fixed_gen

node ./pil2-compiler/src/pil.js pil/zisk.pil -I pil,./pil2-proofman/pil2-components/lib/std/pil,state-machines,precompiles -o pil/zisk.pilout -u tmp/fixed -O fixed-to-file

echo =========================================================rust helpers
(cd ./pil2-proofman; cargo run --bin proofman-cli pil-helpers --pilout ../pil/zisk.pilout --path ../pil/src/ -o)

echo =========================================================setup
node --max-old-space-size=131072 --stack-size=1500 ./pil2-proofman-js/src/main_setup.js -a ./pil/zisk.pilout -b build -t ../pil2-proofman/pil2-components/lib/std/pil -u tmp/fixed -r
