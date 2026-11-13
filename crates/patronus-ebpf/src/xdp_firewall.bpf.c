// Patronus XDP firewall. Compiled at runtime by XdpFirewall::compile_bpf_program
// (clang -g -O2 -target bpf) and by the netlab lane ci/netlab/lane-j-xdp.sh.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maps
struct conn_info {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);  // IP address
    __type(value, __u8); // Block flag
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000000);
    __uint(map_flags, BPF_F_NO_PREALLOC);  // 10M entries preallocated would pin ~1 GB at load time
    __type(key, __u64);  // Connection 5-tuple hash
    __type(value, struct conn_info);
} conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Main XDP program
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Only handle IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Update statistics
    __u32 stats_key = 0;
    __u64 *packets = bpf_map_lookup_elem(&stats, &stats_key);
    if (packets)
        __sync_fetch_and_add(packets, 1);

    stats_key = 1;
    __u64 *bytes = bpf_map_lookup_elem(&stats, &stats_key);
    if (bytes)
        __sync_fetch_and_add(bytes, bpf_ntohs(ip->tot_len));

    // Check blocklist
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked && *blocked) {
        // Update dropped counter
        stats_key = 2;
        __u64 *dropped = bpf_map_lookup_elem(&stats, &stats_key);
        if (dropped)
            __sync_fetch_and_add(dropped, 1);

        return XDP_DROP;  // Blocked IP - drop at wire speed!
    }

    // SYN flood protection
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        // Check for SYN packets
        if (tcp->syn && !tcp->ack) {
            // Could implement SYN cookie here
            // Or rate limit SYN packets per source
        }
    }

    // Connection tracking
    __u64 conn_hash = (__u64)src_ip << 32 | (__u64)bpf_ntohl(ip->daddr);
    struct conn_info *conn = bpf_map_lookup_elem(&conntrack, &conn_hash);

    if (conn) {
        __sync_fetch_and_add(&conn->packets, 1);
        __sync_fetch_and_add(&conn->bytes, bpf_ntohs(ip->tot_len));
        conn->last_seen = bpf_ktime_get_ns();
    } else {
        struct conn_info new_conn = {
            .packets = 1,
            .bytes = bpf_ntohs(ip->tot_len),
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&conntrack, &conn_hash, &new_conn, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
