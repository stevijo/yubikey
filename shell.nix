let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
    buildInputs = with pkgs; [
        pcsclite
    ];
    nativeBuildInputs = with pkgs; [
        pkg-config
    ];
  }
