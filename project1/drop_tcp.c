#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port SEC(".maps");

SEC("cgroup/skb")
int drop_tcp_port(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return 1; 

    if (iph->protocol != 6)
        return 1; 

    struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return 1;

    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&blocked_port, &key);
    if (!port)
        return 1;

    if (tcph->dest == bpf_htons(*port))
        return 0;

    return 1; 
}

char _license[] SEC("license") = "GPL";
