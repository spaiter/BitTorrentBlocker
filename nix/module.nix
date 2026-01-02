# NixOS Module for BitTorrent Blocker
# This can be imported into your NixOS configuration

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.btblocker;

in {
  options.services.btblocker = {
    enable = mkEnableOption "BitTorrent blocker service";

    package = mkOption {
      type = types.package;
      default = pkgs.btblocker or (throw ''
        The btblocker package is not available in pkgs.
        Please either:
          1. Apply the btblocker overlay: nixpkgs.overlays = [ inputs.bittorrent-blocker.overlays.default ];
          2. Set the package explicitly: services.btblocker.package = inputs.bittorrent-blocker.packages.''${system}.btblocker;
      '');
      defaultText = literalExpression "pkgs.btblocker";
      description = "The btblocker package to use";
    };

    interface = mkOption {
      type = types.str;
      default = "eth0";
      description = "Network interface to monitor";
    };

    entropyThreshold = mkOption {
      type = types.float;
      default = 7.6;
      description = "Entropy threshold for encrypted traffic detection";
    };

    minPayloadSize = mkOption {
      type = types.int;
      default = 60;
      description = "Minimum payload size for entropy analysis";
    };

    ipsetName = mkOption {
      type = types.str;
      default = "torrent_block";
      description = "Name of ipset for banned IPs";
    };

    banDuration = mkOption {
      type = types.int;
      default = 18000;
      description = "Ban duration in seconds (default: 5 hours)";
    };


    whitelistPorts = mkOption {
      type = types.listOf types.int;
      default = [ 22 53 80 443 853 5222 5269 ];
      description = "Ports to whitelist (never block)";
    };

    logLevel = mkOption {
      type = types.enum [ "error" "warn" "info" "debug" ];
      default = "info";
      description = "Logging level (error, warn, info, debug)";
    };
  };

  config = mkIf cfg.enable {
    # Load required kernel modules for ipset
    boot.kernelModules = [ "ip_set" "ip_set_hash_ip" ];

    # Ensure nftables and ipset are available
    environment.systemPackages = with pkgs; [
      ipset
      nftables
    ];

    # Create systemd service
    systemd.services.btblocker = {
      description = "BitTorrent Traffic Blocker";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      # Ensure ipset and other tools are available in the service's PATH
      path = with pkgs; [
        ipset
        nftables
      ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/btblocker";
        Restart = "on-failure";
        RestartSec = "5s";

        # Environment variables
        Environment = [
          "LOG_LEVEL=${cfg.logLevel}"
          "INTERFACE=${cfg.interface}"
          "BAN_DURATION=${toString cfg.banDuration}"
          "PATH=${pkgs.lib.makeBinPath [ pkgs.ipset pkgs.nftables ]}"
        ];

        # Security hardening
        NoNewPrivileges = false; # Required for CAP_NET_ADMIN
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ "/proc" "/sys" ];

        # Capabilities
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      };

      preStart = ''
        # Create ipset for banned IPs (ignore if exists)
        ${pkgs.ipset}/bin/ipset create ${cfg.ipsetName} hash:ip timeout ${toString cfg.banDuration} 2>/dev/null || true

        # Configure nftables rules to drop packets from banned IPs
        ${pkgs.nftables}/bin/nft add table inet btblocker 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add chain inet btblocker input { type filter hook input priority 0 \; policy accept \; } 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add chain inet btblocker forward { type filter hook forward priority 0 \; policy accept \; } 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add rule inet btblocker input ip saddr @${cfg.ipsetName} drop 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add rule inet btblocker forward ip saddr @${cfg.ipsetName} drop 2>/dev/null || true
      '';

      postStop = ''
        # Clean up nftables rules
        ${pkgs.nftables}/bin/nft delete table inet btblocker 2>/dev/null || true

        # Destroy ipset (optional - uncomment to remove banned IPs on stop)
        # ${pkgs.ipset}/bin/ipset destroy ${cfg.ipsetName} 2>/dev/null || true
      '';
    };

    # Create configuration file
    environment.etc."btblocker/config.json" = {
      text = builtins.toJSON {
        interface = cfg.interface;
        entropyThreshold = cfg.entropyThreshold;
        minPayloadSize = cfg.minPayloadSize;
        ipsetName = cfg.ipsetName;
        banDuration = cfg.banDuration;
      };
      mode = "0644";
    };
  };
}
