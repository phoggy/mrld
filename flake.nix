{
  description = "mrld - Password strength evaluator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "mrld";
            version = "0.1.4";
            src = self;
            cargoHash = "sha256-UZzPkkP7W87jvdL50M9a5I48sTn4/MPksPePYmfui+g=";
            meta = with pkgs.lib; {
              description = "Password strength evaluator";
              homepage = "https://github.com/phoggy/mrld";
              license = licenses.gpl3Only;
            };
          };
        };
      }
    );
}
