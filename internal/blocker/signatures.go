package blocker

// Protocol constants from libtorrent/sing-box sources
const (
	trackerProtocolID = 0x41727101980
	actionConnect     = 0
	actionAnnounce    = 1
	actionScrape      = 2
	minSizeConnect    = 16
	minSizeScrape     = 36
	minSizeAnnounce   = 98
)

// WhitelistPorts contains ports that should never be blocked
var WhitelistPorts = map[uint16]bool{
	22:   true, // SSH
	53:   true, // DNS
	80:   true, // HTTP
	443:  true, // HTTPS
	5222: true, // XMPP
	853:  true, // DNS over TLS
}

// BTSignatures contains global BitTorrent signatures from nDPI, libtorrent, and UDPGuard
var BTSignatures = [][]byte{
	// 1. Standard headers
	[]byte("\x13BitTorrent protocol"),
	[]byte("BitTorrent protocol"),

	// 2. Libtorrent specific (from dht_tracker.cpp / bt_peer_connection.cpp)
	[]byte("1:v4:LT"), // DHT version key
	[]byte("-LT20"),   // PeerID libtorrent 2.0
	[]byte("-LT12"),   // PeerID libtorrent 1.2

	// 3. PEX (Peer Exchange) Keys (from ut_pex.cpp) - CRITICAL
	[]byte("ut_pex"),    // Extension name
	[]byte("5:added"),   // Added peers list
	[]byte("7:added.f"), // Flags
	[]byte("7:dropped"), // Dropped peers
	[]byte("6:added6"),  // IPv6 peers
	[]byte("8:added6.f"), // IPv6 peer flags
	[]byte("8:dropped6"), // IPv6 dropped peers
	[]byte("1:m"),       // Extensions dictionary

	// 4. Extension Protocol (BEP 10)
	[]byte("ut_metadata"),    // Metadata extension
	[]byte("12:ut_holepunch"), // NAT hole punching
	[]byte("11:upload_only"),  // Upload-only mode
	[]byte("10:share_mode"),   // Share mode
	[]byte("9:lt_donthave"),   // Piece removal
	[]byte("11:LT_metadata"),  // Legacy metadata
	[]byte("6:yourip"),        // External IP
	[]byte("13:metadata_size"), // Metadata size
	[]byte("8:msg_type"),      // Metadata message type
	[]byte("10:total_size"),   // Total metadata size
	[]byte("4:reqq"),          // Request queue size

	// 5. Text / HTTP Trackers
	[]byte("magnet:?"),
	[]byte("magnet:?xt=urn:btih:"),  // v1 info hash
	[]byte("magnet:?xt=urn:btmh:"),  // v2 multihash
	[]byte("udp://tracker."),
	[]byte("announce.php?passkey="),
	[]byte("info_hash"),
	[]byte("peer_id="),
	[]byte("uploaded="),
	[]byte("downloaded="),
	[]byte("supportcrypto="),
	[]byte("requirecrypto="),
	[]byte("cryptoport="),

	// 6. DHT Bencode Keys (from suricata)
	[]byte("d1:ad2:id20:"),
	[]byte("d1:rd2:id20:"),
	[]byte("1:y1:q"), // Query Type
	[]byte("1:y1:r"), // Response Type
	[]byte("find_node"),
	[]byte("4:ping"),
	[]byte("9:get_peers"),
	[]byte("13:announce_peer"),
	[]byte("3:put"),
	[]byte("3:get"),
	[]byte("5:token"),
	[]byte("6:nodes6"),
	[]byte("6:target"),

	// 7. LSD (Local Service Discovery)
	[]byte("BT-SEARCH * HTTP/1.1"),
	[]byte("Host: 239.192.152.143:6771"),
	[]byte("Infohash: "),

	// 8. MSE/PE (Message Stream Encryption)
	[]byte("keyA"),
	[]byte("keyB"),
	[]byte("req1"),
	[]byte("req2"),

	// 9. BitTorrent v2
	[]byte("12:piece layers"),
	[]byte("9:file tree"),
	[]byte("12:pieces root"),

	// 10. HTTP-based BitTorrent (from nDPI)
	[]byte("GET /webseed?info_hash="),   // WebSeed protocol
	[]byte("GET /data?fid="),             // Bitcomet persistent seed
	[]byte("&size="),                     // Bitcomet size parameter
	[]byte("User-Agent: Azureus"),        // Azureus/Vuze client
	[]byte("User-Agent: BitTorrent"),     // Official BitTorrent client
	[]byte("User-Agent: BTWebClient"),    // BitTorrent web client
	[]byte("User-Agent: Shareaza"),       // Shareaza client
	[]byte("User-Agent: FlashGet"),       // FlashGet client
}

// PeerIDPrefixes contains known BitTorrent client PeerID prefixes
// Format: Azureus-style uses "-XX####-" where XX is client code, #### is version
var PeerIDPrefixes = [][]byte{
	// Original 6 (keep existing)
	[]byte("-qB"), // qBittorrent
	[]byte("-TR"), // Transmission
	[]byte("-UT"), // µTorrent
	[]byte("-LT"), // libtorrent (rTorrent, Deluge)
	[]byte("-DE"), // Deluge
	[]byte("-BM"), // BitComet

	// Major clients (high priority additions)
	[]byte("-AZ"), // Azureus/Vuze
	[]byte("-lt"), // libTorrent (rTorrent) - lowercase!
	[]byte("-KT"), // KTorrent
	[]byte("-FW"), // FrostWire
	[]byte("-XL"), // Xunlei (Thunder)
	[]byte("-SD"), // Thunder (Xunlei) - alternative
	[]byte("-UM"), // µTorrent Mac
	[]byte("-KG"), // KGet

	// Additional popular clients
	[]byte("-BB"), // BitBuddy
	[]byte("-BC"), // BitComet (alternative)
	[]byte("-BR"), // BitRocket
	[]byte("-BS"), // BTSlave
	[]byte("-BX"), // Bittorrent X
	[]byte("-CD"), // Enhanced CTorrent
	[]byte("-CT"), // CTorrent
	[]byte("-DP"), // Propagate Data Client
	[]byte("-EB"), // EBit
	[]byte("-ES"), // Electric Sheep
	[]byte("-FT"), // FoxTorrent
	[]byte("-FX"), // Freebox BitTorrent
	[]byte("-GS"), // GSTorrent
	[]byte("-HL"), // Halite
	[]byte("-HN"), // Hydranode
	[]byte("-LH"), // LH-ABC
	[]byte("-LP"), // Lphant
	[]byte("-LW"), // LimeWire
	[]byte("-MO"), // MonoTorrent
	[]byte("-MP"), // MooPolice
	[]byte("-MR"), // Miro
	[]byte("-MT"), // MoonlightTorrent
	[]byte("-NX"), // Net Transport
	[]byte("-PD"), // Pando
	[]byte("-QD"), // QQDownload
	[]byte("-QT"), // Qt 4 Torrent
	[]byte("-RT"), // Retriever
	[]byte("-SB"), // ~Swiftbit
	[]byte("-SS"), // SwarmScope
	[]byte("-ST"), // SymTorrent
	[]byte("-TN"), // TorrentDotNET
	[]byte("-TT"), // TuoTu
	[]byte("-UL"), // uLeecher
	[]byte("-WD"), // Web Downloader
	[]byte("-WY"), // FireTorrent
	[]byte("-XT"), // XanTorrent
	[]byte("-XX"), // Xtorrent
	[]byte("-ZT"), // ZipTorrent
	[]byte("-FG"), // FlashGet

	// Non-Azureus style prefixes
	[]byte("M4-"),    // Mainline (official BitTorrent)
	[]byte("T0"),     // BitTornado
	[]byte("OP"),     // Opera
	[]byte("XBT"),    // XBT Client
	[]byte("exbc"),   // BitComet (non-Azureus)
	[]byte("FUTB"),   // FuTorrent
	[]byte("Plus"),   // Plus! v2
	[]byte("turbo"),  // Turbo BT
	[]byte("btpd"),   // BT Protocol Daemon
}
