#!/bin/bash

echo =========================================================pilout

cargo run --release --bin keccakf_fixed_gen

node ./pil2-compiler/src/pil.js pil/zisk.pil -I pil,./pil2-proofman/pil2-components/lib/std/pil,state-machines,precompiles -o pil/zisk.pilout -u tmp/fixed -O fixed-to-file

echo =========================================================rust helpers
(cd ./pil2-proofman; cargo run --bin proofman-cli pil-helpers --pilout ../pil/zisk.pilout --path ../pil/src/ -o)

echo =========================================================setup
#node --max-old-space-size=131072 --stack-size=1500 ../pil2-proofman-js/src/main_setup.js -a pil/zisk_pre_040.pilout -b build/build_pre_040 -t ./pil2-proofman/pil2-stark/build/bctree -i ./precompiles/keccakf/src/keccakf_fixed.bin
#node ./pil2-proofman-js/src/main_setup.js -a ./pil/zisk.pilout -b build -t ./pil2-proofman/pil2-components/lib/std/pil -u tmp/fixed -r --max-old-space-size=131072 --stack-size=1500
#node --max-old-space-size=131072 --stack-size=1500 ./pil2-proofman-js/src/main_setup.js -a pil/zisk.pilout -b build -t ./pil2-proofman/pil2-stark/build/bctree
node --max-old-space-size=131072 --stack-size=1500 ./pil2-proofman-js/src/main_setup.js -a ./pil/zisk.pilout -b build -t ../pil2-proofman/pil2-components/lib/std/pil -u tmp/fixed -r
