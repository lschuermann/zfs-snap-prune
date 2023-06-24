{ stdenv, lib, rustPlatform, pkg-config, zfs, makeWrapper }:

rustPlatform.buildRustPackage rec {
  pname = "zfs-snap-prune";
  version = "git";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "libzetta-0.5.0" = "sha256-rMqczap1/96mEWwhEKIGOHEuEfPMNi/HNbbCCFejmVA=";
    };
  };

  nativeBuildInputs = [ pkg-config makeWrapper ];
  buildInputs = [ zfs ];

  postInstall = ''
    wrapProgram "$out/bin/zfs-snap-prune" \
      --set PATH ${lib.makeBinPath [ zfs ]}
  '';
}
