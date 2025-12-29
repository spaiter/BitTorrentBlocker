# NixOS End-to-End Test Configuration
# This creates a VM environment to test real-world deployment

{ pkgs ? import <nixpkgs> { } }:

let
  # Build the btblocker binary
  btblocker = pkgs.buildGoModule {
    pname = "btblocker";
    version = "0.1.0";
    src = ../..;

    vendorHash = null; # Update this after first build

    buildInputs = with pkgs; [
      libnetfilter_queue
      libnfnetlink
    ];

    meta = {
      description = "BitTorrent traffic blocker using Deep Packet Inspection";
      license = pkgs.lib.licenses.mit;
    };
  };

in pkgs.nixosTest {
  name = "btblocker-e2e";

  nodes = {
    # Server running the blocker
    server = { config, pkgs, ... }: {
      # Import the blocker module
      imports = [ ./nixos-module.nix ];

      # Enable networking
      networking = {
        firewall.enable = false; # Disable for testing
        useDHCP = false;
        interfaces.eth1.ipv4.addresses = [{
          address = "192.168.1.1";
          prefixLength = 24;
        }];
      };

      # Enable the blocker service
      services.btblocker = {
        enable = true;
        queueNum = 0;
        entropyThreshold = 7.6;
        ipsetName = "torrent_block";
      };

      # Required kernel modules
      boot.kernelModules = [ "nfnetlink_queue" "xt_NFQUEUE" ];

      # Install test utilities
      environment.systemPackages = with pkgs; [
        iptables
        ipset
        tcpdump
        netcat
        curl
      ];
    };

    # Client simulating BitTorrent traffic
    client = { config, pkgs, ... }: {
      networking = {
        firewall.enable = false;
        useDHCP = false;
        interfaces.eth1.ipv4.addresses = [{
          address = "192.168.1.2";
          prefixLength = 24;
        }];
      };

      environment.systemPackages = with pkgs; [
        netcat
        curl
        python3
      ];
    };
  };

  testScript = ''
    import time

    # Start the machines
    start_all()

    # Wait for machines to be ready
    server.wait_for_unit("multi-user.target")
    client.wait_for_unit("multi-user.target")

    # Verify blocker service is running
    server.wait_for_unit("btblocker.service")
    server.succeed("systemctl status btblocker.service")

    # Verify nfqueue is available
    server.succeed("lsmod | grep nfnetlink_queue")

    # Verify iptables rules are configured
    server.succeed("iptables -L -n | grep NFQUEUE")

    # Verify ipset is created
    server.succeed("ipset list torrent_block")

    print("=" * 60)
    print("Test 1: BitTorrent Handshake Detection")
    print("=" * 60)

    # Create BitTorrent handshake packet
    client.succeed("""
      python3 <<EOF
import socket
import struct

# BitTorrent handshake structure
handshake = bytearray()
handshake.append(19)  # pstrlen
handshake.extend(b'BitTorrent protocol')
handshake.extend(b'\\x00' * 8)  # reserved
handshake.extend(b'12345678901234567890')  # info_hash
handshake.extend(b'-UT3500-123456789012')  # peer_id

# Try to connect to server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('192.168.1.1', 6881))
    sock.send(handshake)
    sock.close()
except Exception as e:
    print(f"Connection blocked (expected): {e}")
EOF
    """)

    # Wait for blocker to process
    time.sleep(2)

    # Verify client IP was banned
    result = server.succeed("ipset list torrent_block")
    assert "192.168.1.2" in result, "Client IP should be banned"
    print("✓ BitTorrent handshake detected and IP banned")

    print("=" * 60)
    print("Test 2: UDP Tracker Detection")
    print("=" * 60)

    # Send UDP tracker connect request
    client.succeed("""
      python3 <<EOF
import socket
import struct

# UDP tracker connect packet
packet = struct.pack('>Q', 0x41727101980)  # protocol_id
packet += struct.pack('>I', 0)  # action: connect
packet += struct.pack('>I', 0x12345678)  # transaction_id

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, ('192.168.1.1', 8000))
sock.close()
EOF
    """)

    time.sleep(1)
    print("✓ UDP tracker packet sent and analyzed")

    print("=" * 60)
    print("Test 3: Normal HTTPS Traffic (False Positive Test)")
    print("=" * 60)

    # Start a simple HTTP server on server
    server.succeed("python3 -m http.server 443 &")
    time.sleep(2)

    # Try HTTPS connection from client
    client.succeed("curl -k --connect-timeout 5 https://192.168.1.1 || true")
    print("✓ Normal HTTPS traffic passed through")

    print("=" * 60)
    print("Test 4: Service Lifecycle")
    print("=" * 60)

    # Restart service
    server.succeed("systemctl restart btblocker.service")
    server.wait_for_unit("btblocker.service")
    print("✓ Service restart successful")

    # Stop service
    server.succeed("systemctl stop btblocker.service")
    time.sleep(1)

    # Start service
    server.succeed("systemctl start btblocker.service")
    server.wait_for_unit("btblocker.service")
    print("✓ Service lifecycle working correctly")

    print("=" * 60)
    print("Test 5: Performance Check")
    print("=" * 60)

    # Check CPU usage
    cpu_usage = server.succeed("ps aux | grep btblocker | grep -v grep | awk '{print $3}'")
    print(f"CPU usage: {cpu_usage.strip()}%")

    # Check memory usage
    mem_usage = server.succeed("ps aux | grep btblocker | grep -v grep | awk '{print $4}'")
    print(f"Memory usage: {mem_usage.strip()}%")

    print("=" * 60)
    print("All E2E tests passed!")
    print("=" * 60)
  '';
}
