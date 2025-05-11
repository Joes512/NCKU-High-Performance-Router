#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LEN 128
#define MAX_TABLE_SIZE 1000000

typedef struct {
    struct in6_addr prefix;  // IPv6 address
    uint8_t length;          // Prefix length (0-128)
    char cidr[64];           // Original CIDR string
} PrefixEntry;

PrefixEntry table[MAX_TABLE_SIZE];
int table_size = 0;

// Apply IPv6 mask
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

// Compare two IPv6 addresses
int compare_ipv6(const struct in6_addr* a, const struct in6_addr* b) {
    return memcmp(a->s6_addr, b->s6_addr, 16);
}

// Parse CIDR and encode prefix
void parse_cidr(const char* cidr_str, PrefixEntry* entry) {
    char ip_str[INET6_ADDRSTRLEN];
    int prefix_len;

    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET6, ip_str, &entry->prefix);
    mask_prefix(&entry->prefix, prefix_len);

    entry->length = prefix_len;
    snprintf(entry->cidr, sizeof(entry->cidr), "%s", cidr_str);
}

// Comparator based on prefix and length (LPM priority)
int compare_prefixes(const void* a, const void* b) {
    const PrefixEntry* pa = (const PrefixEntry*)a;
    const PrefixEntry* pb = (const PrefixEntry*)b;

    int cmp = compare_ipv6(&pa->prefix, &pb->prefix);
    if (cmp == 0) return pb->length - pa->length; // Longer prefix first
    return cmp;
}

// Check match
int ipv6_match(const struct in6_addr* ip, const struct in6_addr* prefix, uint8_t length) {
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

// Binary Prefix Search
const char* binary_prefix_search(struct in6_addr* ip) {
    int left = 0, right = table_size - 1;
    const char* best_match = NULL;

    while (left <= right) {
        int mid = (left + right) / 2;
        if (ipv6_match(ip, &table[mid].prefix, table[mid].length)) {
            best_match = table[mid].cidr;
            left = mid + 1;
        } else if (compare_ipv6(ip, &table[mid].prefix) < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return best_match;
}

int main(int argc, char* argv[]) {
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
    while (fgets(line, sizeof(line), fp)) {
        line_number++;
        if (table_size >= MAX_TABLE_SIZE) {
            fprintf(stderr, "Table too big\n");
            return 1;
        }
        line[strcspn(line, "\n")] = 0;

        char ip_str[INET6_ADDRSTRLEN];
        int prefix_len;
        if (sscanf(line, "%[^/]/%d", ip_str, &prefix_len) != 2) {
            fprintf(stderr, "Error at line %d: Invalid CIDR format\n", line_number);
            fclose(fp);
            return 1;
        }

        struct in6_addr addr;
        if (inet_pton(AF_INET6, ip_str, &addr) != 1) {
            fprintf(stderr, "Error at line %d: Invalid IPv6 address\n", line_number);
            fclose(fp);
            return 1;
        }

        if (prefix_len < 0 || prefix_len > 128) {
            fprintf(stderr, "Error at line %d: Invalid prefix length\n", line_number);
            fclose(fp);
            return 1;
        }

        parse_cidr(line, &table[table_size++]);
    }
    fclose(fp);

    qsort(table, table_size, sizeof(PrefixEntry), compare_prefixes);

    struct in6_addr query_ip;
    if (inet_pton(AF_INET6, argv[2], &query_ip) != 1) {
        fprintf(stderr, "Invalid IPv6 address\n");
        return 1;
    }

    const char* result = binary_prefix_search(&query_ip);
    if (result) {
        printf("Matched prefix: %s\n", result);
    } else {
        printf("No match found.\n");
    }

    return 0;
}
