# Test Data

This directory contains test data files used by integration tests.

## PCAP Files

The `pcap/` directory contains packet capture files for testing BitTorrent detection and false positive validation:

### BitTorrent Test Files

| File | Description | Packets | Source |
|------|-------------|---------|--------|
| `bittorrent.pcap` | Standard BitTorrent TCP traffic with 24 flows | 299 | nDPI |
| `bittorrent_tcp_miss.pcapng` | BitTorrent with missing TCP handshake | 100 | nDPI |
| `bittorrent_utp.pcap` | BitTorrent over uTP (UDP) | 92 | nDPI |
| `bt-dns.pcap` | BitTorrent DHT DNS queries | 2 | nDPI |
| `bt_search.pcap` | BitTorrent DHT peer search | 2 | nDPI |
| `tls_torrent.pcapng` | BitTorrent over TLS encryption | 7 | nDPI |
| `suricata-dht.pcap` | DHT protocol validation (ping, find_node, get_peers, announce_peer, errors) | 16 | Suricata-verify |

### False Positive Test Files

These files contain legitimate (non-BitTorrent) traffic to validate we don't have false positives:

| File | Description | Use Case | Source |
|------|-------------|----------|--------|
| `ndpi-dns.pcap` | Standard DNS queries and responses | Ensure DNS traffic is not blocked | nDPI |
| `ndpi-http.pcapng` | Plain HTTP traffic | Ensure HTTP traffic is not blocked | nDPI |
| `ndpi-ssh.pcap` | SSH encrypted connections | Validate SSH encryption is not detected as BitTorrent | nDPI |
| `ndpi-stun.pcap` | STUN protocol packets | Critical test - STUN can look like uTP, must not block | nDPI |
| `ndpi-quic.pcap` | QUIC/HTTP3 traffic | Ensure QUIC is not blocked | nDPI |
| `ndpi-rdp.pcap` | Remote Desktop Protocol | Ensure RDP is not blocked | nDPI |
| `ndpi-google-meet.pcapng` | Google Meet WebRTC/STUN | Validate video conferencing works | nDPI |
| `ndpi-wireguard.pcap` | WireGuard VPN traffic | Ensure modern VPN is not blocked | nDPI |
| `ndpi-openvpn.pcap` | OpenVPN encrypted traffic | Ensure most popular VPN is not blocked | nDPI |
| `ndpi-dtls.pcap` | DTLS encrypted UDP (WebRTC) | Critical test - DTLS can look like UDP tracker | nDPI |
| `ndpi-steam.pcapng` | Steam gaming platform | Ensure gaming platforms work | nDPI |
| `ndpi-kerberos.pcap` | Kerberos authentication | Ensure enterprise auth works | nDPI |
| `ndpi-mqtt.pcap` | MQTT IoT messaging | Ensure IoT protocols work | nDPI |
| `ndpi-whatsapp.pcap` | WhatsApp messaging | Ensure popular messaging app works | nDPI |
| `ndpi-discord.pcap` | Discord voice/text chat | Ensure gaming/community chat works | nDPI |
| `ndpi-tor.pcap` | Tor anonymity network | Ensure privacy tools work | nDPI |
| `ndpi-dropbox.pcap` | Dropbox cloud storage | Ensure cloud services work | nDPI |
| `ndpi-spotify.pcap` | Spotify music streaming | Ensure streaming services work | nDPI |

**Current false positive rate: 0.00%** (tested on 792 packets across 18 protocols)

### Known Limitations

**Telegram**: Telegram's MTProto UDP transport protocol has legitimate structural similarities to BitTorrent's uTP and UDP tracker protocols. This is due to both being UDP-based with similar header structures. If Telegram traffic is being blocked, add Telegram server IPs/ports to whitelist.

## Attribution

### nDPI Test Files
The pcap files from nDPI are originally from the [nDPI project](https://github.com/ntop/nDPI),
which is licensed under the LGPL-3.0 license. These files are used for testing purposes only.

nDPI Copyright (C) 2010-2024 ntop.org

### Suricata Test Files
The `suricata-dht.pcap` file is from the [Suricata-verify project](https://github.com/OISF/suricata-verify),
which provides reference test cases for the Suricata IDS/IPS. The file is used under the GPLv2 license.

Suricata Copyright (C) 2007-2024 Open Information Security Foundation (OISF)
