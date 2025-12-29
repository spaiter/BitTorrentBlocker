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
      default = pkgs.btblocker;
      defaultText = literalExpression "pkgs.btblocker";
      description = "The btblocker package to use";
    };

    queueNum = mkOption {
      type = types.int;
      default = 0;
      description = "Netfilter queue number to use";
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
      type = types.str;
      default = "18000";
      description = "Ban duration in seconds (default: 5 hours)";
    };

    interfaces = mkOption {
      type = types.listOf types.str;
      default = [ "eth0" ];
      description = "Network interfaces to monitor";
    };

    whitelistPorts = mkOption {
      type = types.listOf types.int;
      default = [ 22 53 80 443 853 5222 5269 ];
      description = "Ports to whitelist (never block)";
    };
  };

  config = mkIf cfg.enable {
    # Load required kernel modules
    boot.kernelModules = [ "nfnetlink_queue" "xt_NFQUEUE" "ip_set" "ip_set_hash_ip" ];

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

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/btblocker";
        Restart = "on-failure";
        RestartSec = "5s";

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
        # Create ipset for banned IPs
        ${pkgs.ipset}/bin/ipset create -exist ${cfg.ipsetName} hash:ip timeout ${cfg.banDuration}

        # Configure nftables rules
        ${pkgs.nftables}/bin/nft add table inet btblocker 2>/dev/null || true

        # Drop packets from banned IPs
        ${pkgs.nftables}/bin/nft add chain inet btblocker input { type filter hook input priority 0 \; policy accept \; } 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add chain inet btblocker forward { type filter hook forward priority 0 \; policy accept \; } 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add rule inet btblocker input ip saddr @${cfg.ipsetName} drop 2>/dev/null || true
        ${pkgs.nftables}/bin/nft add rule inet btblocker forward ip saddr @${cfg.ipsetName} drop 2>/dev/null || true

        # Send traffic to nfqueue for analysis
        ${pkgs.nftables}/bin/nft add chain inet btblocker prerouting { type filter hook prerouting priority -150 \; policy accept \; } 2>/dev/null || true
        ${lib.concatMapStringsSep "\n" (iface: ''
          ${pkgs.nftables}/bin/nft add rule inet btblocker prerouting iifname "${iface}" queue num ${toString cfg.queueNum} 2>/dev/null || true
        '') cfg.interfaces}
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
        queueNum = cfg.queueNum;
        entropyThreshold = cfg.entropyThreshold;
        minPayloadSize = cfg.minPayloadSize;
        ipsetName = cfg.ipsetName;
        banDuration = cfg.banDuration;
      };
      mode = "0644";
    };
  };
}
