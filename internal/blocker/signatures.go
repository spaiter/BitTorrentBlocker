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
	[]byte("1:m"),       // Extensions dictionary

	// 4. Text / HTTP Trackers
	[]byte("magnet:?"),
	[]byte("udp://tracker."),
	[]byte("announce.php?passkey="),
	[]byte("info_hash"),
	[]byte("find_node"),

	// 5. DHT Bencode Keys (from suricata)
	[]byte("d1:ad2:id20:"),
	[]byte("d1:rd2:id20:"),
	[]byte("1:y1:q"), // Query Type
	[]byte("1:y1:r"), // Response Type
}

// PeerIDPrefixes contains known BitTorrent client PeerID prefixes
var PeerIDPrefixes = [][]byte{
	[]byte("-qB"), // qBittorrent
	[]byte("-TR"), // Transmission
	[]byte("-UT"), // uTorrent
	[]byte("-LT"), // Libtorrent (Deluge)
	[]byte("-DE"), // Deluge
	[]byte("-BM"), // BitComet
}
