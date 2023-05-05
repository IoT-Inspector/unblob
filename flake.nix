{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.unblob-native = {
    url = "github:onekey-sec/unblob-native";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.pyperscan = {
    url = "git+https://github.com/vlaci/pyperscan/?ref=main&submodules=1";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.sasquatch = {
    url = "github:onekey-sec/sasquatch";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, filter, unblob-native, pyperscan, sasquatch }:
    let
      # System types to support.
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [
          self.overlays.default
        ];
      });
    in
    {
      overlays.default = nixpkgs.lib.composeManyExtensions [
        filter.overlays.default
        sasquatch.overlays.default
        (import ./overlay.nix {
          inherit pyperscan unblob-native;
        })
      ];
      packages = forAllSystems (system: rec {
        inherit (nixpkgsFor.${system}) unblob;
        default = unblob;
      });

      checks = forAllSystems (system: nixpkgsFor.${system}.unblob.tests);

      devShells = forAllSystems
        (system: {
          default = import ./shell.nix { pkgs = nixpkgsFor.${system}; };
        });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});
    };
}
