// Netlab helper for lane-j-xdp.sh: what the Patronus XDP loader does (libbpf
// open + load of the compiled xdp_firewall.bpf.c, attach to an interface),
// plus a line protocol on stdin to change the blocklist and read the counters.
//   xdp-loader OBJECT.o IFACE   commands: block A.B.C.D | unblock A.B.C.D | stats | quit
// The blocklist key is the source address in host byte order (the program
// does bpf_ntohl(ip->saddr)).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int attach(int ifindex, int fd) {
#if LIBBPF_MAJOR_VERSION >= 1
    return bpf_xdp_attach(ifindex, fd, XDP_FLAGS_SKB_MODE, NULL);
#else
    return bpf_set_link_xdp_fd(ifindex, fd, XDP_FLAGS_SKB_MODE);
#endif
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: xdp-loader obj.o iface\n"); return 2; }
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "open %s failed\n", argv[1]); return 1; }
    if (bpf_object__load(obj)) { perror("bpf_object__load"); return 1; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_firewall");
    struct bpf_map *bl = bpf_object__find_map_by_name(obj, "blocklist");
    struct bpf_map *st = bpf_object__find_map_by_name(obj, "stats");
    struct bpf_map *ct = bpf_object__find_map_by_name(obj, "conntrack");
    if (!prog || !bl || !st || !ct) { fprintf(stderr, "program or maps missing in object\n"); return 1; }
    int ifindex = if_nametoindex(argv[2]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }
    if (attach(ifindex, bpf_program__fd(prog))) { perror("attach xdp"); return 1; }
    printf("attached %s generic\n", argv[2]);
    fflush(stdout);
    char line[256];
    while (fgets(line, sizeof line, stdin)) {
        char cmd[32] = "", arg[64] = "";
        sscanf(line, "%31s %63s", cmd, arg);
        if (!strcmp(cmd, "block") || !strcmp(cmd, "unblock")) {
            struct in_addr a;
            if (inet_pton(AF_INET, arg, &a) != 1) { printf("err bad-ip\n"); fflush(stdout); continue; }
            __u32 key = ntohl(a.s_addr);
            __u8 one = 1;
            int rc = !strcmp(cmd, "block") ? bpf_map_update_elem(bpf_map__fd(bl), &key, &one, BPF_ANY)
                                           : bpf_map_delete_elem(bpf_map__fd(bl), &key);
            printf("%s %s rc=%d\n", cmd, arg, rc);
        } else if (!strcmp(cmd, "stats")) {
            __u64 v[3] = {0, 0, 0};
            for (__u32 k = 0; k < 3; k++) bpf_map_lookup_elem(bpf_map__fd(st), &k, &v[k]);
            int n = 0; __u64 key, next; int have = bpf_map_get_next_key(bpf_map__fd(ct), NULL, &next) == 0;
            while (have) { n++; key = next; have = bpf_map_get_next_key(bpf_map__fd(ct), &key, &next) == 0; }
            printf("stats packets=%llu bytes=%llu dropped=%llu conntrack=%d\n",
                   (unsigned long long)v[0], (unsigned long long)v[1], (unsigned long long)v[2], n);
        } else if (!strcmp(cmd, "quit")) {
            break;
        }
        fflush(stdout);
    }
    attach(ifindex, -1);
    return 0;
}
