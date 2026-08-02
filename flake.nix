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
            version = "0.1.8";
            src = self;
            cargoHash = "sha256-PuO3x5XJXu5g47Fm76AsJ0x1Km7yKKMpKaG7LpGL9hA=";
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
