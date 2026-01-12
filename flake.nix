{
  description = "A flake with project build dependencies";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.systems.url = "github:nix-systems/default";
  inputs.flake-utils = {
    url = "github:numtide/flake-utils";
    inputs.systems.follows = "systems";
  };

  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
          config.allowUnfreePredicate = pkg:
          builtins.elem (nixpkgs.lib.getName pkg) [ "mkl"
            "cuda-merged" "cuda_cuobjdump" "cuda_gdb" "cuda_nvcc" "cuda_nvdisasm" "cuda_nvprune" "cuda_cccl" "cuda_cudart" "cuda_cupti" "cuda_cuxxfilt" "cuda_nvml_dev" "cuda_nvrtc" "cuda_nvtx" "cuda_profiler_api" "cuda_sanitizer_api" "libcublas" "libcufft" "libcurand" "libcusolver" "libnvjitlink" "libcusparse" "libnpp"
          ];
        };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_24
            pkgs.grpc
            pkgs.gmp
            pkgs.jq
            pkgs.libsodium
            pkgs.libpqxx
            pkgs.libuuid
            pkgs.openssl
            pkgs.postgresql
            pkgs.protobuf
            pkgs.secp256k1
            pkgs.nlohmann_json
            pkgs.nasm
            pkgs.libgit2
          ] ++ (pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.mkl ])
            ++ (pkgs.lib.optionals pkgs.stdenv.isDarwin
              [ pkgs.darwin.apple_sdk.frameworks.Security ]);

          buildInputs = [
            pkgs.mpich
            pkgs.mpich-pmix
            pkgs.llvm
            pkgs.libclang.lib
            pkgs.clang
            pkgs.cargo
            pkgs.cargo-c
            #rust
            pkgs.rustc
            #pkgs.latest.rustChannels.stable.rust
            #pkgs.latest.rustChannels.stable.rust-src
            pkgs.rustup
            pkgs.mpi
            pkgs.cudaPackages.cudatoolkit
          ];

          RUST_SRC_PATH = "${rust.override {
              extensions = [ "rust-src" ];
          } }/lib/rustlib/src/rust/library";

          RUSTFLAGS = (builtins.map (a: "-L ${a}/lib") [ pkgs.libgit2 ]);

          shellHook = ''
            export LIBCLANG_PATH=${pkgs.libclang.lib}/lib
          '';
        };
      });
}
