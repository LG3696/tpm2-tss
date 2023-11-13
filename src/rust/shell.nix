with import <nixpkgs> {};

mkShell {
  buildInputs = [
    stdenv

    # TODO install these globally
    rustfmt
    clippy

    swtpm

    pkg-config
    tpm2-tss
    tpm2-tools
    glibc
  ];

  LIBCLANG_PATH = "${pkgs.llvmPackages_11.libclang.lib}/lib";
  TPM2_TSS_DIR = "${pkgs.tpm2-tss.dev}";
  C_INCLUDE_PATH = "${pkgs.glibc.dev}/include:${pkgs.llvmPackages_11.libclang.lib}/lib/clang/11.1.0/include";

  TCTI = "${pkgs.tpm2-tss.out}/lib/libtss2-tcti-swtpm.so";
}

