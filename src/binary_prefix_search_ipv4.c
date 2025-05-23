#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LEN 64
#define MAX_TABLE_SIZE 1000000

static __inline__ unsigned long long rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

typedef struct {
    uint32_t prefix;
    uint8_t length;
    char cidr[32];
    int is_auxiliary;
} PrefixEntry;

PrefixEntry table[MAX_TABLE_SIZE];
int table_size = 0;

// Mask a prefix to its valid bits
uint32_t mask_prefix(uint32_t prefix, uint8_t length) {
    return length == 0 ? 0 : (prefix & (~0U << (32 - length)));
}

// Parse CIDR and encode prefix
void parse_cidr(const char* cidr_str, PrefixEntry* entry) {
    char ip_str[INET_ADDRSTRLEN];
    int prefix_len;
    uint32_t ip;

    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET, ip_str, &ip);
    ip = ntohl(ip);

    entry->prefix = mask_prefix(ip, prefix_len);
    entry->length = prefix_len;
    entry->is_auxiliary = 0;
    snprintf(entry->cidr, sizeof(entry->cidr), "%s", cidr_str);
}

// Comparator based on prefix and length (LPM priority)
int compare_prefixes(const void* a, const void* b) {
    const PrefixEntry* pa = (const PrefixEntry*)a;
    const PrefixEntry* pb = (const PrefixEntry*)b;

    if (pa->prefix == pb->prefix) {
        return pb->length - pa->length;
    }
    return (pa->prefix > pb->prefix) - (pa->prefix < pb->prefix);
}

// Check if a prefix matches IP
int match(uint32_t ip, uint32_t prefix, uint8_t length) {
    return mask_prefix(ip, length) == prefix;
}

// Insert auxiliary prefix
void insert_auxiliary_prefix(uint32_t prefix, uint8_t length, const char* source_cidr) {
    if (table_size >= MAX_TABLE_SIZE) return;
    table[table_size].prefix = prefix;
    table[table_size].length = length;
    table[table_size].is_auxiliary = 1;
    snprintf(table[table_size].cidr, sizeof(table[table_size].cidr), "%s (aux)", source_cidr);
    table_size++;
}

// Full tree expansion
void full_tree_expand_and_merge() {
    int original_size = table_size;
    for (int i = 0; i < original_size; i++) {
        uint32_t prefix = table[i].prefix;
        uint8_t length = table[i].length;

        if (length == 32) continue;
        uint32_t range = 1U << (32 - length);
        uint32_t step = range >> 1;
        uint32_t aux_prefix = prefix + step;

        insert_auxiliary_prefix(mask_prefix(aux_prefix, length + 1), length + 1, table[i].cidr);
    }
}

// Binary Prefix Search with Enclosure
const char* binary_prefix_search_enclosure(uint32_t ip, int L, int R) {
    if (L == R) {
        return match(ip, table[L].prefix, table[L].length) ? table[L].cidr : NULL;
    }
    if (L + 1 == R) {
        if (table[L].length >= table[R].length) {
            if (match(ip, table[L].prefix, table[L].length)) return table[L].cidr;
            if (match(ip, table[R].prefix, table[R].length)) return table[R].cidr;
        } else {
            if (match(ip, table[R].prefix, table[R].length)) return table[R].cidr;
            if (match(ip, table[L].prefix, table[L].length)) return table[L].cidr;
        }
        return NULL;
    }

    int M = (L + R) / 2;
    if (match(ip, table[M].prefix, table[M].length)) {
        return table[M].cidr;
    } else if (ip < table[M].prefix) {
        return binary_prefix_search_enclosure(ip, L, M);
    } else {
        return binary_prefix_search_enclosure(ip, M, R);
    }
}

int main(int argc, char* argv[]) {
    unsigned long long insert_total = 0, build_begin, build_end, search_total = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <routing_table.txt> <ip>\n", argv[0]);
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

        char ip_str[INET_ADDRSTRLEN];
        int prefix_len;
        if (sscanf(line, "%[^/]/%d", ip_str, &prefix_len) != 2) {
            fprintf(stderr, "Error at line %d: Invalid CIDR format\n", line_number);
            fclose(fp);
            return 1;
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            fprintf(stderr, "Error at line %d: Invalid IPv4 address\n", line_number);
            fclose(fp);
            return 1;
        }

        if (prefix_len < 0 || prefix_len > 32) {
            fprintf(stderr, "Error at line %d: Invalid prefix length\n", line_number);
            fclose(fp);
            return 1;
        }

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
    printf("Average Insert Time: %.2f cycles\n", table_size > 0 ? (double)insert_total / table_size : 0);

    srand(time(NULL));
    int sample_count = table_size < 100 ? table_size : 100;
    for (int i = 0; i < sample_count; ++i) {
        uint32_t rand_ip = table[rand() % table_size].prefix + 1;
        unsigned long long s1 = rdtsc();
        binary_prefix_search_enclosure(rand_ip, 0, table_size - 1);
        unsigned long long s2 = rdtsc();
        search_total += (s2 - s1);
    }

    printf("Average Search Time: %.2f cycles\n", sample_count > 0 ? (double)search_total / sample_count : 0);
    printf("Number Of Nodes: %d\n", table_size);
    printf("Total memory requirement: %.2f KB\n", (double)(table_size * sizeof(PrefixEntry)) / 1024.0);

    uint32_t query_ip;
    if (inet_pton(AF_INET, argv[2], &query_ip) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return 1;
    }
    query_ip = ntohl(query_ip);

    unsigned long long q1 = rdtsc();
    const char* result = binary_prefix_search_enclosure(query_ip, 0, table_size - 1);
    unsigned long long q2 = rdtsc();

    if (result) {
        printf("Matched prefix: %s\n", result);
    } else {
        printf("No match found.\n");
    }
    printf("Query Execution Time: %llu cycles\n", q2 - q1);

    return 0;
}
