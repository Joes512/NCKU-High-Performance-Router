#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LEN 128
#define MAX_TABLE_SIZE 1000000

typedef struct {
    struct in6_addr b_minus_1;
    struct in6_addr f;
    char cidr[64];
} RangeEntry;

RangeEntry table[MAX_TABLE_SIZE];
int table_size = 0;

// 將 mask 長度轉成 in6_addr
void prefix_to_mask(int prefix_len, struct in6_addr* mask) {
    memset(mask, 0, sizeof(struct in6_addr));
    for (int i = 0; i < 16 && prefix_len > 0; i++) {
        if (prefix_len >= 8) {
            mask->s6_addr[i] = 0xFF;
            prefix_len -= 8;
        } else {
            mask->s6_addr[i] = (0xFF << (8 - prefix_len)) & 0xFF;
            prefix_len = 0;
        }
    }
}

// b-1 helper
void decrement_ipv6(struct in6_addr* addr) {
    for (int i = 15; i >= 0; i--) {
        if (addr->s6_addr[i] > 0) {
            addr->s6_addr[i]--;
            break;
        } else {
            addr->s6_addr[i] = 0xFF;
        }
    }
}

// f helper
void bitwise_or_ipv6(struct in6_addr* result, const struct in6_addr* a, const struct in6_addr* b) {
    for (int i = 0; i < 16; i++) {
        result->s6_addr[i] = a->s6_addr[i] | b->s6_addr[i];
    }
}

// AND helper
void bitwise_and_ipv6(struct in6_addr* result, const struct in6_addr* a, const struct in6_addr* b) {
    for (int i = 0; i < 16; i++) {
        result->s6_addr[i] = a->s6_addr[i] & b->s6_addr[i];
    }
}

// CIDR to range (b-1, f]
void parse_cidr(const char* cidr_str, RangeEntry* entry) {
    char ip_str[INET6_ADDRSTRLEN];
    int prefix_len;
    struct in6_addr ip, mask, b, f, not_mask;

    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET6, ip_str, &ip);

    prefix_to_mask(prefix_len, &mask);
    bitwise_and_ipv6(&b, &ip, &mask);

    memcpy(&entry->b_minus_1, &b, sizeof(struct in6_addr));
    if (memcmp(&b, &(struct in6_addr){0}, 16) != 0) {
        decrement_ipv6(&entry->b_minus_1);
    }

    for (int i = 0; i < 16; i++) {
        not_mask.s6_addr[i] = ~mask.s6_addr[i];
    }
    bitwise_or_ipv6(&f, &b, &not_mask);
    memcpy(&entry->f, &f, sizeof(struct in6_addr));

    snprintf(entry->cidr, sizeof(entry->cidr), "%s", cidr_str);
}

// 比較 function
int compare_entries(const void* a, const void* b) {
    return memcmp(&((RangeEntry*)a)->b_minus_1, &((RangeEntry*)b)->b_minus_1, sizeof(struct in6_addr));
}

// Binary Range Search
const char* binary_range_search(struct in6_addr* ip) {
    int left = 0, right = table_size - 1;
    const char* best_match = NULL;

    while (left <= right) {
        int mid = (left + right) / 2;
        if (memcmp(&table[mid].b_minus_1, ip, sizeof(struct in6_addr)) < 0 &&
            memcmp(ip, &table[mid].f, sizeof(struct in6_addr)) <= 0) {
            best_match = table[mid].cidr;
            left = mid + 1;
        } else if (memcmp(ip, &table[mid].b_minus_1, sizeof(struct in6_addr)) <= 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return best_match;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <routing_table.txt> <IPv6_address>\n", argv[0]);
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
        if (inet_pton(AF_INET6, ip_str, &addr) != 1 || strchr(ip_str, '.') != NULL) {
            fprintf(stderr, "Error at line %d: Invalid IPv6 address\n", line_number);
            fclose(fp);
            return 1;
        }

        if (prefix_len < 0 || prefix_len > 128) {
            fprintf(stderr, "Error at line %d: Invalid prefix length (must be 0-128)\n", line_number);
            fclose(fp);
            return 1;
        }

        parse_cidr(line, &table[table_size++]);
    }
    fclose(fp);

    qsort(table, table_size, sizeof(RangeEntry), compare_entries);

    struct in6_addr query_ip;
    if (inet_pton(AF_INET6, argv[2], &query_ip) != 1 || strchr(argv[2], '.') != NULL) {
        fprintf(stderr, "Invalid IPv6 address input (IPv4 not allowed)\n");
        return 1;
    }

    const char* result = binary_range_search(&query_ip);
    if (result) {
        printf("Matched prefix: %s\n", result);
    } else {
        printf("No match found.\n");
    }

    return 0;
}
