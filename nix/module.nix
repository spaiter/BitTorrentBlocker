# NixOS Module for BitTorrent Blocker (NFQUEUE + XDP Architecture)
# This can be imported into your NixOS configuration

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.btblocker;

in {
  options.services.btblocker = {
    enable = mkEnableOption "BitTorrent blocker service (NFQUEUE + XDP inline packet filtering)";

    queueNum = mkOption {
      type = types.int;
      default = 0;
      description = ''
        NFQUEUE number for packet processing (0-65535).
        Must match the iptables --queue-num parameter.
      '';
    };

    chains = mkOption {
      type = types.listOf (types.enum [ "INPUT" "FORWARD" "OUTPUT" ]);
      default = [ "FORWARD" ];
      description = ''
        iptables chains to redirect to NFQUEUE.
        - INPUT: Traffic destined for this machine
        - FORWARD: Traffic being routed through this machine (VPN/router mode)
        - OUTPUT: Traffic originating from this machine

        Most users want FORWARD for router/VPN scenarios.
      '';
    };

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
      description = ''
        Network interface(s) to monitor. Can be a single interface or comma-separated
        list (e.g., "eth0" or "eth0,wg0,awg0").

        Note: XDP filter will be attached to the first interface in the list.
      '';
    };

    banDuration = mkOption {
      type = types.int;
      default = 18000;
      description = "Ban duration in seconds (default: 5 hours)";
    };

    xdpMode = mkOption {
      type = types.enum [ "generic" "native" ];
      default = "generic";
      description = ''
        XDP mode: "generic" (compatible with all drivers) or "native" (faster, requires driver support).
        Use "generic" for maximum compatibility. Use "native" if your network driver supports XDP natively.
      '';
    };

    cleanupInterval = mkOption {
      type = types.int;
      default = 300;
      description = "Cleanup interval for expired IPs in XDP map (in seconds, default: 5 minutes)";
    };

    logLevel = mkOption {
      type = types.enum [ "error" "warn" "info" "debug" ];
      default = "info";
      description = "Logging level (error, warn, info, debug)";
    };

    detectionLogPath = mkOption {
      type = types.str;
      default = "";
      description = ''
        Path to detection log file for detailed packet analysis (empty = disabled).
        Logs include timestamp, IP, protocol, detection method, and payload hex dump.
        Useful for false positive analysis and debugging.
      '';
    };

    monitorOnly = mkOption {
      type = types.bool;
      default = false;
      description = ''
        If true, only log detections without banning IPs.
        Perfect for testing and validation before enabling blocking.
      '';
    };
  };

  config = mkIf cfg.enable {
    # Ensure kernel version supports XDP (Linux 4.18+) and NFQUEUE
    assertions = [
      {
        assertion = versionAtLeast config.boot.kernelPackages.kernel.version "4.18";
        message = "BitTorrent Blocker requires Linux kernel 4.18 or later for XDP support. Current kernel: ${config.boot.kernelPackages.kernel.version}";
      }
      {
        assertion = cfg.queueNum >= 0 && cfg.queueNum <= 65535;
        message = "NFQUEUE number must be between 0 and 65535. Got: ${toString cfg.queueNum}";
      }
    ];

    # Configure iptables rules for NFQUEUE
    networking.firewall.extraCommands = mkIf (config.networking.firewall.enable) ''
      # BitTorrent Blocker: Redirect packets to NFQUEUE for DPI
      ${concatMapStringsSep "\n" (chain: ''
        iptables -I ${chain} -p tcp -j NFQUEUE --queue-num ${toString cfg.queueNum}
        iptables -I ${chain} -p udp -j NFQUEUE --queue-num ${toString cfg.queueNum}
      '') cfg.chains}
    '';

    networking.firewall.extraStopCommands = mkIf (config.networking.firewall.enable) ''
      # BitTorrent Blocker: Remove NFQUEUE rules on stop
      ${concatMapStringsSep "\n" (chain: ''
        iptables -D ${chain} -p tcp -j NFQUEUE --queue-num ${toString cfg.queueNum} 2>/dev/null || true
        iptables -D ${chain} -p udp -j NFQUEUE --queue-num ${toString cfg.queueNum} 2>/dev/null || true
      '') cfg.chains}
    '';

    # Create systemd service
    systemd.services.btblocker = {
      description = "BitTorrent Traffic Blocker (XDP + DPI)";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/btblocker";
        Restart = "on-failure";
        RestartSec = "5s";

        # Environment variables
        Environment = [
          "LOG_LEVEL=${cfg.logLevel}"
          "INTERFACE=${cfg.interface}"
          "QUEUE_NUM=${toString cfg.queueNum}"
          "BAN_DURATION=${toString cfg.banDuration}"
          "XDP_MODE=${cfg.xdpMode}"
          "XDP_CLEANUP_INTERVAL=${toString cfg.cleanupInterval}"
        ] ++ (if cfg.detectionLogPath != "" then [ "DETECTION_LOG=${cfg.detectionLogPath}" ] else [])
          ++ (if cfg.monitorOnly then [ "MONITOR_ONLY=true" ] else []);

        # Security hardening
        NoNewPrivileges = false; # Required for CAP_NET_ADMIN
        PrivateTmp = true;
        ProtectSystem = "strict"; # Strict is safe: eBPF only needs /sys/fs/bpf access (via CAP_BPF/CAP_SYS_ADMIN)
        ProtectHome = true;
        ProtectKernelModules = false; # Required for eBPF program loading
        ReadWritePaths = mkIf (cfg.detectionLogPath != "") [
          (dirOf cfg.detectionLogPath)
        ];

        # Capabilities for XDP (eBPF program loading and attachment)
        # CAP_NET_ADMIN: Required for XDP attachment and network configuration
        # CAP_NET_RAW: Required for raw packet processing
        # CAP_BPF: Required for eBPF program loading (Linux 5.8+)
        # CAP_SYS_ADMIN: Fallback for eBPF on older kernels (<5.8)
        AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_BPF" "CAP_SYS_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_BPF" "CAP_SYS_ADMIN" ];

        # eBPF/XDP requires unlimited memory locking for map creation
        LimitMEMLOCK = "infinity";
      };
    };

    # Create configuration file
    environment.etc."btblocker/config.json" = {
      text = builtins.toJSON {
        interface = cfg.interface;
        queueNum = cfg.queueNum;
        banDuration = cfg.banDuration;
        xdpMode = cfg.xdpMode;
        cleanupInterval = cfg.cleanupInterval;
      };
      mode = "0644";
    };
  };
}
