#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PREFIXES 1000000
#define INET_ADDR_LEN 32

/* rdtsc for measuring execution time */
static __inline__ unsigned long long rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

typedef struct Prefix {
    uint32_t b_minus_1;
    uint32_t f;
    int prefix_len;
    char cidr[INET_ADDR_LEN];
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

// Insert prefix into binary trie and set fastlink
void insert_prefix_into_trie(Prefix* p, uint32_t ip) {
    TrieNode* curr = root;
    for (int i = 31; i >= 32 - p->prefix_len; --i) {
        int bit = (ip >> i) & 1;
        if (!curr->child[bit])
            curr->child[bit] = create_trie_node(curr);
        curr = curr->child[bit];
    }
    curr->is_prefix = 1;
    curr->prefix_info = p;

    // Set fastlink to nearest ancestor prefix
    TrieNode* ancestor = curr->parent;
    while (ancestor && !ancestor->is_prefix) ancestor = ancestor->parent;
    if (ancestor && ancestor->is_prefix)
        p->fastlink = ancestor->prefix_info;
}

void parse_cidr(const char* cidr_str, Prefix* p) {
    char ip_str[INET_ADDRSTRLEN];
    int prefix_len;
    uint32_t ip, mask, b, f;

    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET, ip_str, &ip);
    ip = ntohl(ip);
    mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    b = ip & mask;
    f = b | ~mask;

    p->b_minus_1 = (b == 0) ? 0 : b - 1;
    p->f = f;
    p->prefix_len = prefix_len;
    snprintf(p->cidr, sizeof(p->cidr), "%s", cidr_str);
    p->fastlink = NULL;

    insert_prefix_into_trie(p, ip);
}

int compare_prefixes(const void* a, const void* b) {
    uint32_t a_b1 = ((Prefix*)a)->b_minus_1;
    uint32_t b_b1 = ((Prefix*)b)->b_minus_1;
    return (a_b1 > b_b1) - (a_b1 < b_b1);
}

const char* search_fastlink(Prefix* node, uint32_t ip) {
    while (node) {
        if (node->b_minus_1 < ip && ip <= node->f) return node->cidr;
        node = node->fastlink;
    }
    return NULL;
}

Prefix* get_lca(Prefix* a, Prefix* b) {
    return (a->b_minus_1 < b->b_minus_1) ? a : b; // simplified fallback
}

const char* multilayer_lookup(uint32_t ip) {
    int left = 0, right = layer0_size - 1;

    while (left <= right) {
        int mid = (left + right) / 2;
        if (layer0[mid].b_minus_1 < ip && ip <= layer0[mid].f) {
            return layer0[mid].cidr;
        } else if (ip <= layer0[mid].b_minus_1) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    if (right < 0 || right + 1 >= layer0_size) return NULL;
    Prefix* l = &layer0[right];
    Prefix* r = &layer0[right + 1];
    Prefix* lca = get_lca(l, r);
    if (ip <= (lca->b_minus_1 + lca->f) / 2) {
        return search_fastlink(l, ip);
    } else {
        return search_fastlink(r, ip);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <routing_table.txt> <ip>\n", argv[0]);
        return 1;
    }

    root = create_trie_node(NULL);

    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Failed to open routing table");
        return 1;
    }

    char line[64];
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

    uint32_t query_ip;
    if (inet_pton(AF_INET, argv[2], &query_ip) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return 1;
    }
    query_ip = ntohl(query_ip);

    unsigned long long begin = rdtsc();
    const char* result = multilayer_lookup(query_ip);
    unsigned long long end = rdtsc();

    if (result) {
        printf("Matched prefix: %s\n", result);
        printf("Execution time: %llu cycles\n", end - begin);
    } else {
        printf("No match found.\n");
    }
    return 0;
}
