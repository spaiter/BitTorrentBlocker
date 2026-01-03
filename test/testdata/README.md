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

## Attribution

The pcap files in this directory are originally from the [nDPI project](https://github.com/ntop/nDPI),
which is licensed under the LGPL-3.0 license. These files are used for testing purposes only.

nDPI Copyright (C) 2010-2024 ntop.org
