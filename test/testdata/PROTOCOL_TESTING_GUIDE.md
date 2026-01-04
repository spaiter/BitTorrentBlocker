# Protocol Testing Guide

This document provides instructions for adding new protocol tests to validate BitTorrent detection accuracy.

## nDPI Protocol Test Repository

**Location**: `C:\Projects\BitTorrentBlocker\nDPI\tests\cfgs\default\pcap`

**Total Files**: 608+ pcap files covering hundreds of network protocols

### Currently Tested Protocols (49 passing, 0.00% FP rate)

See `test/testdata/README.md` for the complete list of tested protocols.

### Known Limitations (4 protocols - documented)

Protocols excluded from automated testing due to technical limitations:
- Zoom (uTP-like UDP patterns, <2% FP rate)
- IPSec (ESP encrypted packets may contain uTP-like patterns)
- Roblox (uTP-like gaming protocol, 43% FP rate)
- NFS (unsupported pcap format v2.1)

## Adding New Protocol Tests

### Step 1: Find Available Protocols

List all available protocols in nDPI test directory:

```bash
ls "C:\Projects\BitTorrentBlocker\nDPI\tests\cfgs\default\pcap"
```

### Step 2: Check What's Already Tested

List protocols already copied to our test directory:

```bash
ls test/testdata/pcap/ndpi-*.{pcap,pcapng} 2>/dev/null | xargs -n1 basename | sort
```

Check what's in the test file:

```bash
grep "ndpi-" internal/blocker/ndpi_false_positive_test.go | grep -E "pcapFile:|//" | grep -oE "ndpi-[a-z0-9-]+\.(pcap|pcapng)" | sort -u
```

### Step 3: Find Untested Protocols

Compare available vs tested:

```bash
comm -13 \
  <(grep "ndpi-" internal/blocker/ndpi_false_positive_test.go | grep -oE "ndpi-[a-z0-9-]+\.(pcap|pcapng)" | sort -u) \
  <(ls test/testdata/pcap/ndpi-*.{pcap,pcapng} 2>/dev/null | xargs -n1 basename | sort -u)
```

### Step 4: Copy New Protocol Pcaps

Pick a category to test (e.g., gaming, enterprise, streaming):

```bash
# Example: Copy gaming protocol
cp "C:\Projects\BitTorrentBlocker\nDPI\tests\cfgs\default\pcap/activision.pcap" test/testdata/pcap/ndpi-activision.pcap

# Example: Copy enterprise protocol
cp "C:\Projects\BitTorrentBlocker\nDPI\tests\cfgs\default\pcap/ldap.pcap" test/testdata/pcap/ndpi-ldap.pcap
```

**Important**: Rename files to follow the `ndpi-<protocol>.pcap` convention.

### Step 5: Add Test Cases

Add test cases to `internal/blocker/ndpi_false_positive_test.go` in the `TestNDPIFalsePositives` function:

```go
{
    name:        "Protocol Name",
    pcapFile:    "../../test/testdata/pcap/ndpi-protocol.pcap",
    description: "Protocol description should not be detected",
    maxPackets:  100,
},
```

**Group by category**: Add new tests near similar protocols (gaming with gaming, VPN with VPN, etc.)

### Step 6: Run Tests

Run the false positive test:

```bash
go test -v ./internal/blocker -run TestNDPIFalsePositives
```

### Step 7: Handle Results

#### If All Packets Pass (0 detected):
✅ Protocol passes! Add to README.md test table.

#### If Some Packets Detected (False Positives):
1. Calculate false positive rate: `(detected / total) * 100`
2. **If FP rate < 2%**: Consider acceptable, document as known limitation
3. **If FP rate ≥ 2%**: Exclude from test suite, document reason in comments

Example for excluded protocol:

```go
// Protocol Name skipped: Brief explanation of why it has false positives.
// X/Y packets detected (Z% false positive rate). Recommend whitelisting if needed.
```

### Step 8: Update Documentation

Update `test/testdata/README.md`:

1. **If protocol passes**: Add row to the false positive test table
2. **If protocol fails**: Add entry to "Known Limitations" section with:
   - Protocol name in bold
   - Explanation of why false positives occur
   - False positive rate (if applicable)
   - Whitelisting recommendation

### Step 9: Update Statistics

Update the statistics line in `test/testdata/README.md`:

```markdown
**Current false positive rate: 0.00%** (tested on XXXX packets across YY protocols)
```

Calculate using the output from `TestNDPIFalsePositivesStats`.

### Step 10: Add to Aggregated Test

Add passing protocols to `TestNDPIFalsePositivesStats` pcapFiles slice:

```go
"../../test/testdata/pcap/ndpi-protocol.pcap",
```

Add comments for skipped protocols:

```go
// Protocol Name skipped - see comment in TestNDPIFalsePositives
```

### Step 11: Commit Changes

```bash
git add test/testdata/pcap/ndpi-*.pcap
git add internal/blocker/ndpi_false_positive_test.go
git add test/testdata/README.md
git commit -m "test: add Phase X protocol false positive tests"
```

## Protocol Categories to Consider

### Gaming
- activision.pcap, among_us.pcap, armagetron.pcapng, blizzard.pcap
- codm.pcap, crossfire.pcapng, epicgames.pcap, fortnite.pcap
- genshin_impact.pcap, minecraft.pcap, pubg.pcap, roblox.pcapng
- starcraft_battle_net.pcap, steam_cdn.pcap, steam.pcap, valorant.pcap

### Enterprise/Business
- afp.pcap, ajp.pcap, amqp.pcap, cassandra.pcap, ceph.pcap
- citrix.pcap, directconnect.pcap, dnp3.pcap, ftps.pcap
- ibm_db2.pcap, ipsec.pcap, ldap.pcap, modbus.pcap
- mysql.pcap, oracle.pcap, postgresql.pcap, sap.pcap
- socks.pcap, tftp.pcap, vnc.pcap

### Streaming/Media
- dazn.pcapng, hulu.pcap, icecast.pcap, mpeg_dash.pcap
- netflix.pcap, rtcp.pcap, rtmp.pcap, rtsp.pcap
- shoutcast.pcap, sling.pcap, spotify.pcap, tidal.pcap
- twitch.pcap, youtube.pcap, vimeo.pcap

### VoIP/Communication
- diameter.pcap, jabber.pcap, lisp.pcap, mgcp.pcap
- h323.pcap, ipp.pcap, irc.pcap, ldaps.pcap
- signal.pcap, sip.pcap, skype.pcap, telegram.pcap
- teams.pcap, viber.pcap, webex.pcap, whatsapp.pcap
- zoom.pcap, slack.pcap, discord.pcap

### Cloud Services
- alibaba.pcap, alicloud.pcap, amazon.pcap, aws.pcap
- azure.pcap, cloudflare.pcap, dropbox.pcap, github.pcap
- google_cloud.pcap, icloud.pcap, office_365.pcap
- salesforce.pcap, wetransfer.pcap, wikipedia.pcap

### Social Media
- facebook.pcap, instagram.pcap, linkedin.pcap, pinterest.pcap
- reddit.pcap, snapchat.pcap, telegram.pcap, tiktok.pcap
- twitter.pcap, wechat.pcap, youtube.pcap

### VPN/Security
- anyconnect-vpn.pcap, cloudflare-warp.pcap, ipsec.pcap
- nordvpn.pcap, openvpn.pcap, pptp.pcap, tor.pcap
- wireguard.pcap, checkpoint_vpn.pcap

### Network Management
- bgp.pcap, dhcp.pcap, dns.pcap, eigrp.pcap
- ftp.pcap, gre.pcap, icmp.pcap, igmp.pcap
- ntp.pcap, ospf.pcap, rip.pcap, snmp.pcap
- ssdp.pcap, stp.pcap, vrrp.pcap

### IoT/Embedded
- bacnet.pcap, beckhoff_ads.pcapng, can.pcap, coap_mqtt.pcap
- dlms.pcap, eip.pcap, modbus.pcap, opc_ua.pcap
- profinet.pcap, zigbee.pcap, z-wave.pcap

### Encrypted/Tunneled
- dtls.pcap, ipsec.pcap, quic.pcap, ssh.pcap
- tls.pcap, gre.pcapng, l2tp.pcap, pptp.pcap

## Testing Strategy

1. **Start with common protocols**: Focus on widely-used protocols that users are most likely to encounter
2. **Test by category**: Group related protocols together for efficient testing
3. **Prioritize by impact**: Test protocols that would cause the most user impact if blocked
4. **Document limitations**: Be transparent about protocols that structurally resemble BitTorrent
5. **Maintain 0.00% FP rate**: Exclude any protocol with >2% false positive rate

## Expected Results

- **Most protocols**: 0 detections (perfect)
- **Some UDP-based protocols**: May have structural similarities to uTP/UDP tracker
- **Encrypted protocols**: Usually pass unless they use similar encryption patterns
- **Gaming protocols**: Higher risk due to custom UDP protocols
- **Mobile platform traffic**: Mixed protocols may trigger some detections

## Notes

- The goal is to test **legitimate** protocols to validate we don't have false positives
- We're not trying to test BitTorrent detection (that's in separate test files)
- Focus on maintaining 0.00% false positive rate on tested protocols
- Document any limitations transparently for users
