#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ALLOWED_PORT 4040

SEC("cgroup/connect4")
int allow_tcp_for_process(struct bpf_sock_addr *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    const char target[] = "myprocess";
    int i;
    #pragma unroll
    for (i = 0; i < sizeof(target) - 1; i++) {
        if (comm[i] != target[i])
            return 1; 
    }
    if (comm[i] != '\0')
        return 1;

    if (ctx->user_port == bpf_htons(ALLOWED_PORT)) {
        return 1; 
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
