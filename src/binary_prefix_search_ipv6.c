#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LEN 128
#define MAX_TABLE_SIZE 1000000

static __inline__ unsigned long long rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

typedef struct {
    struct in6_addr prefix;
    uint8_t length;
    char cidr[64];
    int is_auxiliary;
} PrefixEntry;

PrefixEntry table[MAX_TABLE_SIZE];
int table_size = 0;

void mask_prefix(struct in6_addr* addr, uint8_t length) {
    int full_bytes = length / 8;
    int remaining_bits = length % 8;
    for (int i = 0; i < 16; i++) {
        if (i < full_bytes) continue;
        else if (i == full_bytes && remaining_bits > 0) {
            uint8_t mask = ~((1 << (8 - remaining_bits)) - 1);
            addr->s6_addr[i] &= mask;
        } else {
            addr->s6_addr[i] = 0;
        }
    }
}

void parse_cidr(const char* cidr_str, PrefixEntry* entry) {
    char ip_str[INET6_ADDRSTRLEN];
    int prefix_len;
    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET6, ip_str, &entry->prefix);
    mask_prefix(&entry->prefix, prefix_len);
    entry->length = prefix_len;
    entry->is_auxiliary = 0;
    snprintf(entry->cidr, sizeof(entry->cidr), "%s", cidr_str);
}

int compare_prefixes(const void* a, const void* b) {
    const PrefixEntry* pa = (const PrefixEntry*)a;
    const PrefixEntry* pb = (const PrefixEntry*)b;
    int cmp = memcmp(&pa->prefix, &pb->prefix, sizeof(struct in6_addr));
    return (cmp != 0) ? cmp : (pb->length - pa->length);
}

int match(struct in6_addr* ip, struct in6_addr* prefix, uint8_t length) {
    int full_bytes = length / 8;
    int remaining_bits = length % 8;
    for (int i = 0; i < full_bytes; i++) {
        if (ip->s6_addr[i] != prefix->s6_addr[i]) return 0;
    }
    if (remaining_bits > 0) {
        uint8_t mask = ~((1 << (8 - remaining_bits)) - 1);
        if ((ip->s6_addr[full_bytes] & mask) != (prefix->s6_addr[full_bytes] & mask)) return 0;
    }
    return 1;
}

void insert_auxiliary_prefix(struct in6_addr prefix, uint8_t length, const char* source_cidr) {
    if (table_size >= MAX_TABLE_SIZE) return;
    table[table_size].prefix = prefix;
    table[table_size].length = length;
    table[table_size].is_auxiliary = 1;
    snprintf(table[table_size].cidr, sizeof(table[table_size].cidr), "%s (aux)", source_cidr);
    table_size++;
}

void full_tree_expand_and_merge() {
    int original_size = table_size;
    for (int i = 0; i < original_size; i++) {
        if (table[i].length >= 128) continue;
        struct in6_addr aux = table[i].prefix;
        int byte_index = table[i].length / 8;
        int bit_offset = 7 - (table[i].length % 8);
        aux.s6_addr[byte_index] |= (1 << bit_offset);
        mask_prefix(&aux, table[i].length + 1);
        insert_auxiliary_prefix(aux, table[i].length + 1, table[i].cidr);
    }
}

const char* binary_prefix_search_enclosure(struct in6_addr* ip, int L, int R) {
    if (L == R) {
        return match(ip, &table[L].prefix, table[L].length) ? table[L].cidr : NULL;
    }
    if (L + 1 == R) {
        if (table[L].length >= table[R].length) {
            if (match(ip, &table[L].prefix, table[L].length)) return table[L].cidr;
            if (match(ip, &table[R].prefix, table[R].length)) return table[R].cidr;
        } else {
            if (match(ip, &table[R].prefix, table[R].length)) return table[R].cidr;
            if (match(ip, &table[L].prefix, table[L].length)) return table[L].cidr;
        }
        return NULL;
    }
    int M = (L + R) / 2;
    if (match(ip, &table[M].prefix, table[M].length)) return table[M].cidr;
    else if (memcmp(ip, &table[M].prefix, sizeof(struct in6_addr)) < 0)
        return binary_prefix_search_enclosure(ip, L, M);
    else
        return binary_prefix_search_enclosure(ip, M, R);
}

int main(int argc, char* argv[]) {
    unsigned long long build_begin, build_end, insert_total = 0, search_total = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <routing_table.txt> <ipv6>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Failed to open routing table");
        return 1;
    }

    char line[MAX_LINE_LEN];
    int line_number = 0;

    build_begin = rdtsc();
    while (fgets(line, sizeof(line), fp)) {
        line_number++;
        if (table_size >= MAX_TABLE_SIZE) {
            fprintf(stderr, "Table too big\n");
            return 1;
        }
        line[strcspn(line, "\n")] = 0;
        unsigned long long t1 = rdtsc();
        parse_cidr(line, &table[table_size++]);
        unsigned long long t2 = rdtsc();
        insert_total += (t2 - t1);
    }
    fclose(fp);

    full_tree_expand_and_merge();
    qsort(table, table_size, sizeof(PrefixEntry), compare_prefixes);
    build_end = rdtsc();

    printf("Average Build Time: %.2f cycles\n", (double)(build_end - build_begin));
    printf("Average Insert Time: %.2f cycles\n", (table_size > 0) ? (double)insert_total / table_size : 0);

    srand(time(NULL));
    int sample_count = table_size < 100 ? table_size : 100;
    for (int i = 0; i < sample_count; i++) {
        struct in6_addr sample_ip = table[rand() % table_size].prefix;
        sample_ip.s6_addr[15] += 1;  // 確保在 prefix 內部

        unsigned long long s1 = rdtsc();
        binary_prefix_search_enclosure(&sample_ip, 0, table_size - 1);
        unsigned long long s2 = rdtsc();
        search_total += (s2 - s1);
    }
    printf("Average Search Time: %.2f cycles\n", (sample_count > 0) ? (double)search_total / sample_count : 0);
    printf("Number Of Nodes: %d\n", table_size);
    printf("Total memory requirement: %.2f KB\n", (double)(table_size * sizeof(PrefixEntry)) / 1024.0);

    // 真正查詢
    struct in6_addr query_ip;
    if (inet_pton(AF_INET6, argv[2], &query_ip) != 1) {
        fprintf(stderr, "Invalid IPv6 address\n");
        return 1;
    }

    unsigned long long q1 = rdtsc();
    const char* result = binary_prefix_search_enclosure(&query_ip, 0, table_size - 1);
    unsigned long long q2 = rdtsc();

    if (result) {
        printf("Matched prefix: %s\n", result);
    } else {
        printf("No match found.\n");
    }
    printf("Query Execution Time: %llu cycles\n", q2 - q1);

    return 0;
}
