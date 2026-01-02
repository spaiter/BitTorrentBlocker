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
        # Automatically extract version from main.go
        version = builtins.head (builtins.match ''.*Version = "([0-9]+\.[0-9]+\.[0-9]+)".*'' (builtins.readFile ./cmd/btblocker/main.go));
      in
      {
        packages = {
          default = self.packages.${system}.btblocker;

          btblocker = pkgs.buildGoModule {
            pname = "btblocker";
            inherit version;

            src = ./.;

            # Vendor directory is committed, so no hash needed
            vendorHash = null;

            # Build inputs for libpcap
            buildInputs = with pkgs; [
              libpcap
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
            libpcap
            pkg-config
            ipset
            nftables
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
      nixosModules.default = import ./nix/module.nix;

      # Overlay for adding to your own NixOS configuration
      overlays.default = final: prev: {
        btblocker = self.packages.${prev.system}.btblocker;
      };
    };
}
