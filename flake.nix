{
  description = "Podping.alpha - gossip-listener";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Only the gossip-listener source
        gossipListenerSrc = pkgs.lib.cleanSourceWith {
          src = ./gossip-listener;
          filter = path: type: (craneLib.filterCargoSources path type);
        };

        commonArgs = {
          src = gossipListenerSrc;
          strictDeps = true;

          # Git dependencies cause lock file drift after vendoring
          cargoExtraArgs = "--offline";

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs =
            with pkgs;
            [
              openssl
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        gossipListener = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
          }
        );
      in
      {
        packages = {
          gossip-listener = gossipListener;
          default = gossipListener;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = gossipListener;
          name = "gossip-listener";
        };

        devShells.default = craneLib.devShell {
          inputsFrom = [ gossipListener ];

          packages = with pkgs; [
            cargo-watch
            rust-analyzer
          ];
        };
      }
    );
}
