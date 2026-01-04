//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to store blocked IPs (key: IPv4 address as __u32, value: expiration timestamp as __u64)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100000);  // Support up to 100k blocked IPs
	__type(key, __u32);           // IPv4 address
	__type(value, __u64);         // Expiration timestamp (seconds since epoch)
} blocked_ips SEC(".maps");

// XDP program to filter blocked IPs
SEC("xdp")
int xdp_blocker(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// Parse Ethernet header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;  // Invalid packet, pass to network stack

	// Only process IPv4 packets
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	// Parse IP header
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;  // Invalid packet, pass to network stack

	// Extract source IP address (already in network byte order)
	__u32 src_ip = ip->saddr;

	// Look up source IP in blocked_ips map
	__u64 *expires_at = bpf_map_lookup_elem(&blocked_ips, &src_ip);
	if (expires_at != NULL) {
		// IP is in blocklist - check if ban has expired
		__u64 now = bpf_ktime_get_ns() / 1000000000;  // Convert nanoseconds to seconds

		if (now < *expires_at) {
			// Ban still active - DROP the packet
			return XDP_DROP;
		}

		// Ban expired, but we'll let user-space cleanup handle removal
		// For now, pass the packet to avoid blocking legitimate traffic
		return XDP_PASS;
	}

	// IP not in blocklist - pass to network stack (will go to NFQUEUE for DPI)
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
