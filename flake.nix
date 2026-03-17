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

        # Include gossip-listener and dtt-fork (local path dependency).
        # dtt-fork uses include_str!("../README.md") so .md files must
        # survive filtering alongside normal Cargo sources.
        gossipListenerSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            let
              rel = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
              inScope =
                pkgs.lib.hasPrefix "gossip-listener/" rel
                || pkgs.lib.hasPrefix "dtt-fork/" rel
                || rel == "gossip-listener"
                || rel == "dtt-fork";
              isMarkdown = pkgs.lib.hasSuffix ".md" path;
            in
            inScope && ((craneLib.filterCargoSources path type) || isMarkdown);
        };

        # Vendor all dependencies (including the iroh-gossip git dep)
        # from the gossip-listener lockfile.
        cargoVendorDir = craneLib.vendorCargoDeps {
          src = gossipListenerSrc;
          cargoLock = ./gossip-listener/Cargo.lock;
          cargoToml = ./gossip-listener/Cargo.toml;
        };

        commonArgs = {
          src = gossipListenerSrc;
          inherit cargoVendorDir;

          # Crane needs these to locate the manifest and lockfile since
          # they are not at the source root.
          cargoToml = ./gossip-listener/Cargo.toml;
          cargoLock = ./gossip-listener/Cargo.lock;

          strictDeps = true;

          # Move the source root into gossip-listener/ so Crane's hooks
          # (build, check, install) find Cargo.toml at the root.
          # The path dependency `../dtt-fork` still resolves because
          # dtt-fork/ is a sibling directory one level up.
          # See: https://crane.dev/faq/workspace-not-at-source-root.html
          postUnpack = ''
            cd $sourceRoot/gossip-listener
            sourceRoot="."
          '';

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
