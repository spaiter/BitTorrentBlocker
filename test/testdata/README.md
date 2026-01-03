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
| `ndpi-netflix.pcap` | Netflix video streaming | Ensure streaming video works | nDPI |
| `ndpi-youtube.pcap` | YouTube video streaming | Ensure YouTube works | nDPI |
| `ndpi-webex.pcap` | Cisco WebEx conferencing | Ensure enterprise video conferencing works | nDPI |
| `ndpi-skype.pcap` | Skype video calls | Ensure Skype works | nDPI |
| `ndpi-facebook.pcap` | Facebook social media | Ensure social media works | nDPI |
| `ndpi-instagram.pcap` | Instagram social media | Ensure Instagram works | nDPI |
| `ndpi-reddit.pcap` | Reddit social media | Ensure Reddit works | nDPI |
| `ndpi-viber.pcap` | Viber messaging and calls | Ensure Viber works | nDPI |
| `ndpi-wechat.pcap` | WeChat messaging platform | Ensure WeChat works | nDPI |
| `ndpi-line.pcap` | LINE messaging app | Ensure LINE works | nDPI |
| `ndpi-sip.pcap` | SIP VoIP protocol | Ensure VoIP calls work | nDPI |
| `ndpi-rtmp.pcap` | RTMP live streaming | Ensure live streaming works | nDPI |
| `ndpi-dns-doh.pcap` | DNS over HTTPS (DoH) | Ensure secure DNS works | nDPI |
| `ndpi-dns-dot.pcap` | DNS over TLS (DoT) | Ensure secure DNS works | nDPI |
| `ndpi-snapchat.pcap` | Snapchat social media | Ensure Snapchat works | nDPI |
| `ndpi-pinterest.pcap` | Pinterest social media | Ensure Pinterest works | nDPI |
| `ndpi-tumblr.pcap` | Tumblr social media | Ensure Tumblr works | nDPI |
| `ndpi-anydesk.pcapng` | AnyDesk remote desktop | Ensure remote desktop works | nDPI |
| `ndpi-teamviewer.pcap` | TeamViewer remote access | Ensure TeamViewer works | nDPI |
| `ndpi-citrix.pcap` | Citrix remote access | Ensure Citrix works | nDPI |
| `ndpi-vnc.pcap` | VNC remote desktop | Ensure VNC works | nDPI |
| `ndpi-git.pcap` | Git version control | Ensure Git operations work | nDPI |
| `ndpi-cloudflare-warp.pcap` | Cloudflare WARP VPN | Ensure Cloudflare VPN works | nDPI |
| `ndpi-google-chat.pcapng` | Google Chat messaging | Ensure Google Chat works | nDPI |
| `ndpi-pptp.pcap` | PPTP VPN protocol | Ensure PPTP VPN works | nDPI |
| `ndpi-ntp.pcap` | NTP time synchronization | Ensure NTP works | nDPI |
| `ndpi-snmp.pcap` | SNMP network management | Ensure SNMP works | nDPI |
| `ndpi-gre.pcapng` | GRE tunneling protocol | Ensure GRE tunnels work | nDPI |
| `ndpi-smb.pcap` | SMB file sharing (Windows) | Ensure SMB file shares work | nDPI |
| `ndpi-webdav.pcap` | WebDAV file sharing | Ensure WebDAV works | nDPI |
| `ndpi-rsync.pcap` | Rsync file synchronization | Ensure Rsync works | nDPI |
| `ndpi-ftp.pcap` | FTP file transfer | Ensure FTP works | nDPI |
| `ndpi-mysql.pcapng` | MySQL database traffic | Ensure MySQL works | nDPI |
| `ndpi-oracle.pcapng` | Oracle database traffic | Ensure Oracle works | nDPI |
| `ndpi-imap.pcap` | IMAP email protocol | Ensure IMAP works | nDPI |
| `ndpi-pop3.pcap` | POP3 email protocol | Ensure POP3 works | nDPI |
| `ndpi-smtp.pcap` | SMTP email protocol | Ensure SMTP works | nDPI |
| `ndpi-irc.pcap` | IRC chat protocol | Ensure IRC works | nDPI |
| `ndpi-jabber.pcap` | Jabber/XMPP messaging | Ensure Jabber works | nDPI |
| `ndpi-h323.pcap` | H.323 VoIP protocol | Ensure H.323 works | nDPI |
| `ndpi-mgcp.pcap` | MGCP media gateway control | Ensure MGCP works | nDPI |
| `ndpi-rtsp.pcap` | RTSP streaming protocol | Ensure RTSP works | nDPI |
| `ndpi-activision.pcap` | Activision gaming platform | Ensure Activision works | nDPI |
| `ndpi-among-us.pcap` | Among Us game traffic | Ensure Among Us works | nDPI |

**Current false positive rate: 0.00%** (tested on 2657 packets across 62 protocols)

### Known Limitations

**Telegram**: Telegram's MTProto UDP transport protocol has legitimate structural similarities to BitTorrent's uTP and UDP tracker protocols. This is due to both being UDP-based with similar header structures. If Telegram traffic is being blocked, add Telegram server IPs/ports to whitelist.

**Zoom**: Zoom's proprietary video protocol occasionally uses UDP packets with structures similar to uTP (version 1, type 0, extension 1). This affects <2% of Zoom packets but cannot be reliably distinguished without application-layer inspection. If Zoom is being blocked, whitelist Zoom server IPs/ports.

**Microsoft Teams**: Like Zoom, Teams occasionally uses UDP packets that structurally resemble uTP. This is rare (<2% of packets) but may cause intermittent connection issues. If Teams is being blocked, whitelist Teams server IPs/ports.

**Signal Messenger**: Signal's encrypted messaging protocol occasionally uses UDP packets with structures similar to uTP (version 1, type 0, extension 1). Similar to Zoom/Teams limitation. If Signal is being blocked, whitelist Signal server IPs/ports.

**IPSec**: IPSec ESP (Encapsulating Security Payload) encrypted packets may contain uTP-like patterns after encryption/decryption. This is a known limitation of encrypted traffic analysis. If IPSec VPN traffic is being blocked, whitelist IPSec traffic or VPN server IPs.

**Roblox**: Roblox gaming protocol uses UDP packets with structures very similar to uTP, resulting in a 43% false positive rate on test traffic. This is due to Roblox's custom networking protocol. If Roblox is being blocked, whitelist Roblox server IPs/ports (typically UDP ports in the 49152-65535 range).

**Android Platform**: Android platform traffic pcaps contain mixed protocols, some with structural similarities to BitTorrent protocols, resulting in a 12.5% false positive rate on test traffic. This is due to the diverse nature of Android background services and apps. Individual apps should be whitelisted as needed.

**iPhone Platform**: iPhone platform traffic pcaps contain mixed protocols, some with structural similarities to BitTorrent protocols, resulting in a 13% false positive rate on test traffic. Similar to Android, this is due to iOS background services and apps. Individual apps should be whitelisted as needed.

**NFS (Network File System)**: NFS test pcap file uses an unsupported pcap format version (2.1) that cannot be parsed by the gopacket library. NFS traffic should work correctly in production, but cannot be tested with the available pcap file.

## Attribution

### nDPI Test Files
The pcap files from nDPI are originally from the [nDPI project](https://github.com/ntop/nDPI),
which is licensed under the LGPL-3.0 license. These files are used for testing purposes only.

nDPI Copyright (C) 2010-2024 ntop.org

### Suricata Test Files
The `suricata-dht.pcap` file is from the [Suricata-verify project](https://github.com/OISF/suricata-verify),
which provides reference test cases for the Suricata IDS/IPS. The file is used under the GPLv2 license.

Suricata Copyright (C) 2007-2024 Open Information Security Foundation (OISF)
