# NixOS Module for BitTorrent Blocker
# This can be imported into your NixOS configuration

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.btblocker;

  btblocker = pkgs.buildGoModule {
    pname = "btblocker";
    version = "0.1.0";
    src = ../..;

    vendorHash = null;

    buildInputs = with pkgs; [
      libnetfilter_queue
      libnfnetlink
    ];

    nativeBuildInputs = with pkgs; [
      pkg-config
    ];

    meta = {
      description = "BitTorrent traffic blocker using Deep Packet Inspection";
      license = licenses.mit;
      platforms = platforms.linux;
    };
  };

in {
  options.services.btblocker = {
    enable = mkEnableOption "BitTorrent blocker service";

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
    boot.kernelModules = [ "nfnetlink_queue" "xt_NFQUEUE" ];

    # Ensure ipset is available
    environment.systemPackages = with pkgs; [
      ipset
      iptables
    ];

    # Create systemd service
    systemd.services.btblocker = {
      description = "BitTorrent Traffic Blocker";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${btblocker}/bin/btblocker";
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

        # Configure iptables rules
        ${pkgs.iptables}/bin/iptables -I INPUT -m set --match-set ${cfg.ipsetName} src -j DROP
        ${pkgs.iptables}/bin/iptables -I FORWARD -m set --match-set ${cfg.ipsetName} src -j DROP

        # Send traffic to nfqueue for analysis
        ${lib.concatMapStringsSep "\n" (iface: ''
          ${pkgs.iptables}/bin/iptables -t mangle -A PREROUTING -i ${iface} -j NFQUEUE --queue-num ${toString cfg.queueNum}
        '') cfg.interfaces}
      '';

      postStop = ''
        # Clean up iptables rules
        ${pkgs.iptables}/bin/iptables -D INPUT -m set --match-set ${cfg.ipsetName} src -j DROP 2>/dev/null || true
        ${pkgs.iptables}/bin/iptables -D FORWARD -m set --match-set ${cfg.ipsetName} src -j DROP 2>/dev/null || true

        ${lib.concatMapStringsSep "\n" (iface: ''
          ${pkgs.iptables}/bin/iptables -t mangle -D PREROUTING -i ${iface} -j NFQUEUE --queue-num ${toString cfg.queueNum} 2>/dev/null || true
        '') cfg.interfaces}

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
