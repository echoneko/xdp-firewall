//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Define a BPF map to store the blocked IP address
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); // Map type is an array
    __uint(max_entries, 1);           // Only one entry in the map
    __type(key, __u32);               // Key type is a 32-bit unsigned integer
    __type(value, __u32);             // Value type is a 32-bit unsigned integer
} blocked_ip_map SEC(".maps");        // Place the map in the ".maps" section

// Define the XDP program
SEC("xdp")
int xdp_drop_ip(struct xdp_md *ctx) {
    // Pointers to the start and end of the packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data; // Ethernet header
    struct iphdr *ip;          // IP header
    __u32 key = 0;             // Key to access the blocked IP map
    __u32 *blocked_ip;         // Pointer to the blocked IP address

    // Check if the packet is an Ethernet packet and if the Ethernet header is complete
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Pass the packet if the Ethernet header is incomplete

    // Check if the packet is an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS; // Pass the packet if it is not an IP packet

    ip = (struct iphdr *)(eth + 1); // Point to the IP header

    // Check if the packet is a complete IP packet
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // Pass the packet if the IP header is incomplete

    // Read the blocked IP address from the map
    blocked_ip = bpf_map_lookup_elem(&blocked_ip_map, &key);
    if (!blocked_ip) {
        bpf_printk("Blocked IP not found in map\n");
        return XDP_PASS; // Pass the packet if the blocked IP is not found in the map
    }

    // Convert the blocked IP address to network byte order
    __u32 blocked_ip_network_order = __constant_htonl(*blocked_ip);

    // Drop the packet if it matches the blocked IP address
    if (ip->saddr == blocked_ip_network_order) {
        // Extract each byte of the IP address for logging
        unsigned char *ip_bytes = (unsigned char *)&ip->saddr;
        bpf_printk("Dropping packet from IP: %d.%d.%d.%d\n",
                   ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        return XDP_DROP; // Drop the packet
    }

    return XDP_PASS; // Pass the packet if it does not match the blocked IP address
}

// Define the license for the eBPF program
char LICENSE[] SEC("license") = "GPL";
