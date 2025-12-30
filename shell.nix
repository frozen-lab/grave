{ pkgs ? import <nixpkgs> { } }:

let
  isLinux  = builtins.match ".*-linux" pkgs.system != null;
in
pkgs.mkShell {
  name = "dev";
  buildInputs = with pkgs; [
    rustc
    cargo
    rustfmt
    clippy
    rust-analyzer
    cargo-show-asm
  ]
  ++ (if isLinux then [ pkgs.gcc pkgs.linuxPackages.perf pkgs.gdb ] else []);

  nativeBuildInputs = [ pkgs.pkg-config pkgs.cmake ];

  shellHook = ''
    export RUST_LOG=trace
    export RUST_BACKTRACE=1
    export CARGO_TERM_COLOR=always
  '';
}
