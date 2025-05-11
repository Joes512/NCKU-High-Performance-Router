#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PREFIXES 1000000
#define INET6_ADDR_LEN 128

/* rdtsc for measuring execution time */
static __inline__ unsigned long long rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

typedef struct Prefix {
    struct in6_addr addr;
    int prefix_len;
    char cidr[INET6_ADDR_LEN];
    struct Prefix* fastlink;
} Prefix;

typedef struct TrieNode {
    int is_prefix;
    Prefix* prefix_info;
    struct TrieNode* child[2];
    struct TrieNode* parent;
} TrieNode;

Prefix layer0[MAX_PREFIXES];
int layer0_size = 0;
TrieNode* root = NULL;

TrieNode* create_trie_node(TrieNode* parent) {
    TrieNode* node = (TrieNode*)calloc(1, sizeof(TrieNode));
    node->parent = parent;
    return node;
}

int get_bit(const struct in6_addr* addr, int bit_index) {
    int byte_index = bit_index / 8;
    int bit_in_byte = 7 - (bit_index % 8);
    return (addr->s6_addr[byte_index] >> bit_in_byte) & 1;
}

void insert_prefix_into_trie(Prefix* p) {
    TrieNode* curr = root;
    for (int i = 0; i < p->prefix_len; ++i) {
        int bit = get_bit(&p->addr, i);
        if (!curr->child[bit])
            curr->child[bit] = create_trie_node(curr);
        curr = curr->child[bit];
    }
    curr->is_prefix = 1;
    curr->prefix_info = p;

    TrieNode* ancestor = curr->parent;
    while (ancestor && !ancestor->is_prefix) ancestor = ancestor->parent;
    if (ancestor && ancestor->is_prefix)
        p->fastlink = ancestor->prefix_info;
}

void parse_cidr(const char* cidr_str, Prefix* p) {
    char ip_str[INET6_ADDRSTRLEN];
    int prefix_len;

    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET6, ip_str, &p->addr);
    p->prefix_len = prefix_len;
    snprintf(p->cidr, sizeof(p->cidr), "%s", cidr_str);
    p->fastlink = NULL;

    insert_prefix_into_trie(p);
}

int compare_prefixes(const void* a, const void* b) {
    return memcmp(&((Prefix*)a)->addr, &((Prefix*)b)->addr, sizeof(struct in6_addr));
}

int match_prefix(const struct in6_addr* addr, const Prefix* p) {
    for (int i = 0; i < p->prefix_len; ++i) {
        int a = get_bit(addr, i);
        int b = get_bit(&p->addr, i);
        if (a != b) return 0;
    }
    return 1;
}

const char* search_fastlink(Prefix* node, const struct in6_addr* ip) {
    while (node) {
        if (match_prefix(ip, node)) return node->cidr;
        node = node->fastlink;
    }
    return NULL;
}

Prefix* get_lca(Prefix* a, Prefix* b) {
    int common = 0;
    for (int i = 0; i < 128; ++i) {
        if (get_bit(&a->addr, i) != get_bit(&b->addr, i)) break;
        common++;
    }
    static Prefix lca;
    lca = *a;
    for (int i = common; i < 128; ++i) {
        int byte = i / 8;
        int bit = 7 - (i % 8);
        lca.addr.s6_addr[byte] &= ~(1 << bit);
    }
    lca.prefix_len = common;
    return &lca;
}

const char* multilayer_lookup(struct in6_addr* ip) {
    int left = 0, right = layer0_size - 1;

    while (left <= right) {
        int mid = (left + right) / 2;
        if (match_prefix(ip, &layer0[mid])) {
            return layer0[mid].cidr;
        } else if (memcmp(ip, &layer0[mid].addr, sizeof(struct in6_addr)) < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    if (right < 0 || right + 1 >= layer0_size) return NULL;
    Prefix* l = &layer0[right];
    Prefix* r = &layer0[right + 1];
    Prefix* lca = get_lca(l, r);

    if (match_prefix(ip, lca)) {
        return search_fastlink(l, ip);
    } else {
        return search_fastlink(r, ip);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <routing_table.txt> <ipv6-address>\n", argv[0]);
        return 1;
    }

    root = create_trie_node(NULL);

    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Failed to open routing table");
        return 1;
    }

    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        if (layer0_size >= MAX_PREFIXES) {
            fprintf(stderr, "Too many prefixes\n");
            return 1;
        }
        line[strcspn(line, "\n")] = 0;
        parse_cidr(line, &layer0[layer0_size++]);
    }
    fclose(fp);

    qsort(layer0, layer0_size, sizeof(Prefix), compare_prefixes);

    struct in6_addr query_ip;
    if (inet_pton(AF_INET6, argv[2], &query_ip) != 1) {
        fprintf(stderr, "Invalid IPv6 address\n");
        return 1;
    }

    unsigned long long begin = rdtsc();
    const char* result = multilayer_lookup(&query_ip);
    unsigned long long end = rdtsc();

    if (result) {
        printf("Matched prefix: %s\n", result);
        printf("Execution time: %llu cycles\n", end - begin);
    } else {
        printf("No match found.\n");
    }
    return 0;
}
