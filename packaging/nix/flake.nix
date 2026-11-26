{
  description = "netgraph: passive network map, server, sensor and optional host agent";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Bump with the release tag; the Go binaries carry it as their version.
      version = "0.1.0";

      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Everything is CGO_ENABLED=0, like the release binaries. The server
      # embeds web/dist, assembled from this repository's web/src; the ASN
      # table is downloaded at release time and is not in git, so a Nix build
      # has none and the server uses -asn-file, as a plain `go build` does.
      mkPackage = pkgs:
        { pname, subPackages, tags ? [ ], preBuild ? "" }:
        pkgs.buildGoModule {
          inherit pname version subPackages tags preBuild;
          src = ../..;
          env.CGO_ENABLED = "0";
          vendorHash = "sha256-HhQMWXjPZPbQdKXqC0HOBYovvc7RDisWUfkolks9Tco=";
          ldflags = [
            "-s"
            "-w"
            "-X github.com/xen0bit/netgraph/internal/buildinfo.Version=${version}"
          ];
        };
    in
    {
      packages = forAllSystems (pkgs:
        let
          netgraph = mkPackage pkgs {
            pname = "netgraph";
            subPackages = [ "./cmd/netgraph" ];
            tags = [ "embed_web" ];
            preBuild = "make web.build";
          };
          netgraph-sensor = mkPackage pkgs {
            pname = "netgraph-sensor";
            subPackages = [ "./cmd/netgraph-sensor" ];
          };
          netgraph-agent = mkPackage pkgs {
            pname = "netgraph-agent";
            subPackages = [ "./cmd/netgraph-agent" ];
          };
        in
        {
          inherit netgraph netgraph-sensor netgraph-agent;
          default = netgraph;
        });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gnumake
            golangci-lint
            gopls
            clang-tools
          ];
        };
      });
    };
}
