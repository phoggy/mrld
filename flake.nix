{
  description = "mrld - Password strength evaluator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
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
            version = "0.1.17";
            src = self;
            cargoHash = "sha256-y9g8WsqxhmV+nI53PxaDVOs6zbNYWMVv6ZMxm9cDXqI=";
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
