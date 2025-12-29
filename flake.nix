{
  description = "BitTorrent Blocker - High-performance DPI-based BitTorrent traffic blocker";

  # Binary cache configuration - users get pre-built binaries from Cachix
  # Nix will prompt to trust the cache on first use
  nixConfig = {
    extra-substituters = [
      "https://btblocker.cachix.org"
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = "0.4.2";
      in
      {
        packages = {
          default = self.packages.${system}.btblocker;

          btblocker = pkgs.buildGoModule {
            pname = "btblocker";
            inherit version;

            src = ./.;

            # Go module dependencies hash
            vendorHash = "sha256-kQfQXHJHGIPiKr5AFgmYr3M2m1NRdOUby5vm1qdu13s=";

            # Specify Go version
            buildInputs = with pkgs; [
              libnetfilter_queue
              libnfnetlink
            ];

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            # Build only the main binary
            subPackages = [ "cmd/btblocker" ];

            # CGO is automatically enabled when buildInputs contains C libraries
            # No need to set CGO_ENABLED explicitly

            # Build flags with version information
            ldflags = [
              "-s"
              "-w"
              "-X main.Version=${version}"
              "-X main.Commit=${self.rev or "dirty"}"
              "-X main.Date=${self.lastModifiedDate or "unknown"}"
            ];

            meta = with pkgs.lib; {
              description = "High-performance Go library and CLI tool for detecting and blocking BitTorrent traffic using Deep Packet Inspection";
              homepage = "https://github.com/spaiter/BitTorrentBlocker";
              license = licenses.mit;
              maintainers = [ ];
              platforms = platforms.linux;
              mainProgram = "btblocker";
            };
          };
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
            go-tools
            libnetfilter_queue
            libnfnetlink
            pkg-config
            ipset
            iptables
            golangci-lint
          ];

          shellHook = ''
            echo "BitTorrent Blocker development environment"
            echo "Go version: $(go version)"
            echo ""
            echo "Available commands:"
            echo "  make build  - Build the binary"
            echo "  make test   - Run tests"
            echo "  make run    - Run the blocker (requires root)"
          '';
        };
      }
    ) // {
      # NixOS module for easy system integration
      nixosModules.default = import ./test/e2e/nixos-module.nix;

      # Overlay for adding to your own NixOS configuration
      overlays.default = final: prev: {
        btblocker = self.packages.${prev.system}.btblocker;
      };
    };
}
