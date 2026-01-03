# Test Data

This directory contains test data files used by integration tests.

## PCAP Files

The `pcap/` directory contains packet capture files for testing BitTorrent detection:

| File | Description | Packets | Source |
|------|-------------|---------|--------|
| `bittorrent.pcap` | Standard BitTorrent TCP traffic with 24 flows | 299 | nDPI |
| `bittorrent_tcp_miss.pcapng` | BitTorrent with missing TCP handshake | 100 | nDPI |
| `bittorrent_utp.pcap` | BitTorrent over uTP (UDP) | 92 | nDPI |
| `bt-dns.pcap` | BitTorrent DHT DNS queries | 2 | nDPI |
| `bt_search.pcap` | BitTorrent DHT peer search | 2 | nDPI |
| `tls_torrent.pcapng` | BitTorrent over TLS encryption | 7 | nDPI |
| `suricata-dht.pcap` | DHT protocol validation (ping, find_node, get_peers, announce_peer, errors) | 16 | Suricata-verify |

## Attribution

### nDPI Test Files
The pcap files from nDPI are originally from the [nDPI project](https://github.com/ntop/nDPI),
which is licensed under the LGPL-3.0 license. These files are used for testing purposes only.

nDPI Copyright (C) 2010-2024 ntop.org

### Suricata Test Files
The `suricata-dht.pcap` file is from the [Suricata-verify project](https://github.com/OISF/suricata-verify),
which provides reference test cases for the Suricata IDS/IPS. The file is used under the GPLv2 license.

Suricata Copyright (C) 2007-2024 Open Information Security Foundation (OISF)
