#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LEN 64
#define MAX_TABLE_SIZE 1000000

/* To calculate execution time. */
static __inline__ unsigned long long rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

/* Data structure for binary range search. */
typedef struct {
    uint32_t b_minus_1;
    uint32_t f;
    char cidr[32];  // CIDR
} RangeEntry;

RangeEntry table[MAX_TABLE_SIZE];
int table_size = 0;

// Convert CIDR to range (b-1, f]
void parse_cidr(const char* cidr_str, RangeEntry* entry) {
    char ip_str[INET_ADDRSTRLEN];
    int prefix_len;
    uint32_t ip, mask, b, f;

    sscanf(cidr_str, "%[^/]/%d", ip_str, &prefix_len);
    inet_pton(AF_INET, ip_str, &ip);
    ip = ntohl(ip);

    mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    b = ip & mask;
    f = b | ~mask;

    entry->b_minus_1 = (b == 0) ? 0 : b - 1;
    entry->f = f;
    snprintf(entry->cidr, sizeof(entry->cidr), "%s", cidr_str);
}

// Compare function for qsort
int compare_entries(const void* a, const void* b) {
    uint32_t a_b1 = ((RangeEntry*)a)->b_minus_1;
    uint32_t b_b1 = ((RangeEntry*)b)->b_minus_1;
    return (a_b1 > b_b1) - (a_b1 < b_b1);
}

// Binary range search
const char* binary_range_search(uint32_t ip) {
    int left = 0, right = table_size - 1;
    const char* best_match = NULL;

    while (left <= right) {
        int mid = (left + right) / 2;
        if (table[mid].b_minus_1 < ip && ip <= table[mid].f) {
            best_match = table[mid].cidr;
            left = mid + 1;
        } else if (ip <= table[mid].b_minus_1) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }

    return best_match;
}

int main(int argc, char* argv[]) {
    unsigned long long insert_total = 0;
    unsigned long long build_begin, build_end;
    unsigned long long search_total = 0;

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

        // Validate CIDR
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
            fprintf(stderr, "Error at line %d: Invalid prefix length (must be 0-32)\n", line_number);
            fclose(fp);
            return 1;
        }

        unsigned long long t1 = rdtsc();
        parse_cidr(line, &table[table_size++]);
        unsigned long long t2 = rdtsc();
        insert_total += (t2 - t1);
    }
    fclose(fp);
    build_end = rdtsc();

    qsort(table, table_size, sizeof(RangeEntry), compare_entries);

    // Display build and insert time
    printf("Average Build Time: %.2f cycles\n", (double)(build_end - build_begin));
    printf("Average Insert Time: %.2f cycles\n", table_size > 0 ? (double)insert_total / table_size : 0);

    // Convert IP to search
    uint32_t query_ip;
    if (inet_pton(AF_INET, argv[2], &query_ip) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return 1;
    }
    query_ip = ntohl(query_ip);

    // Average Search Time (100 random samples)
    srand(time(NULL));
    int sample_count = table_size < 100 ? table_size : 100;
    for (int i = 0; i < sample_count; ++i) {
        uint32_t random_ip = table[rand() % table_size].b_minus_1 + 1;
        unsigned long long s1 = rdtsc();
        binary_range_search(random_ip);
        unsigned long long s2 = rdtsc();
        search_total += (s2 - s1);
    }

    printf("Average Search Time: %.2f cycles\n", sample_count > 0 ? (double)search_total / sample_count : 0);
    printf("Number Of Nodes: %d\n", table_size);
    printf("Total memory requirement: %.2f KB\n", (double)(table_size * sizeof(RangeEntry)) / 1024.0);

    // Execute user query IP
    unsigned long long q1 = rdtsc();
    const char* result = binary_range_search(query_ip);
    unsigned long long q2 = rdtsc();

    if (result) {
        printf("Matched prefix: %s\n", result);
    } else {
        printf("No match found.\n");
    }
    printf("Query Execution Time: %llu cycles\n", q2 - q1);

    return 0;
}
