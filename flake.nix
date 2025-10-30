{
  description = "zfs-snap-prune flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";

    treefmt-nix.url = "github:numtide/treefmt-nix";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        inherit (pkgs) lib;

      in
      {
        packages = {
          default = pkgs.callPackage ./default.nix { };
        };

        checks = {
          formatting = (treefmt-nix.lib.evalModule pkgs ./treefmt.nix).config.build.check self;
        };

        formatter = (treefmt-nix.lib.evalModule pkgs ./treefmt.nix).config.build.wrapper;

        devShells.default = pkgs.mkShell {
          name = "zfs-snap-prune-devshell";

          packages = with pkgs; [
            rustc
            cargo
          ];
        };
      }
    );
}
