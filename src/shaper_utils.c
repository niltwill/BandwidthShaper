// shaper_utils.c
// Miscellaneous helper functions
// See shaper_utils.h for the public API

#include "common.h"
#include "shaper_utils.h"

// -----------------------------------------------------------------------
// Rate parsing / printing
// -----------------------------------------------------------------------

double parse_rate_with_units(const char *rate_str) {
    char unit[3] = {0};
    double value = 0;

    if (sscanf(rate_str, "%lf%2s", &value, unit) < 1) {
        fprintf(stderr, "Failed to parse rate '%s'. Defaulting to 0.\n", rate_str);
        return 0;
    }

    if (value < 0 || !isfinite(value)) {
        fprintf(stderr, "Error: Rate value must be non-negative and finite. Got: %f\n", value);
        return 0;
    }

    const double MAX_RATE = 1e15;
    double multiplier = 1.0;
    const char *unit_name = "bytes";

    if      (strcmp(unit, "b")  == 0) { multiplier = 1.0;                unit_name = "bytes"; }
    else if (strcmp(unit, "KB") == 0) { multiplier = 1000.0;             unit_name = "KB"; }
    else if (strcmp(unit, "MB") == 0) { multiplier = 1000000.0;          unit_name = "MB"; }
    else if (strcmp(unit, "GB") == 0) { multiplier = 1000000000.0;       unit_name = "GB"; }
    else if (strcmp(unit, "Kb") == 0) { multiplier = 1000.0 / 8.0;       unit_name = "Kb"; }
    else if (strcmp(unit, "Mb") == 0) { multiplier = 1000000.0 / 8.0;    unit_name = "Mb"; }
    else if (strcmp(unit, "Gb") == 0) { multiplier = 1000000000.0 / 8.0; unit_name = "Gb"; }
    else if (unit[0] == '\0')         { multiplier = 1000.0;             unit_name = "KB (default)"; }
    else {
        fprintf(stderr, "Invalid unit '%s' in rate '%s'. Defaulting to kilobytes.\n", unit, rate_str);
        multiplier = 1000.0;
        unit_name  = "KB (default)";
    }

    if (value > MAX_RATE / multiplier) {
        fprintf(stderr, "Error: Rate value too large (%f %s).\n", value, unit_name);
        return MAX_RATE;
    }

    double result = value * multiplier;
    if (!isfinite(result) || result < 0) {
        fprintf(stderr, "Error: Rate calculation overflow.\n");
        return MAX_RATE;
    }
    return result;
}

void print_rate_with_units(const char *label, double rate_bps) {
    if      (rate_bps >= 1e9) printf("%s: %.2f Gbps (%.2f GBps)\n", label, rate_bps/1e9,  rate_bps/(1e9*8));
    else if (rate_bps >= 1e6) printf("%s: %.2f Mbps (%.2f MBps)\n", label, rate_bps/1e6,  rate_bps/(1e6*8));
    else if (rate_bps >= 1e3) printf("%s: %.2f Kbps (%.2f KBps)\n", label, rate_bps/1e3,  rate_bps/(1e3*8));
    else                      printf("%s: %.2f bps (%.2f Bps)\n",   label, rate_bps,      rate_bps/8.0);
}

// -----------------------------------------------------------------------
// NIC helpers
// -----------------------------------------------------------------------

void list_network_interfaces(void) {
    PIP_ADAPTER_ADDRESSES addrs = NULL;
    ULONG buf_len = 0;
    DWORD ret;

    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &buf_len);
    if (ret != ERROR_BUFFER_OVERFLOW) {
        fprintf(stderr, "GetAdaptersAddresses failed: %lu\n", ret);
        return;
    }

    addrs = malloc(buf_len);
    if (!addrs) { fprintf(stderr, "Memory allocation failed\n"); return; }

    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &buf_len);
    if (ret != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed: %lu\n", ret);
        free(addrs);
        return;
    }

    printf("Available Network Interfaces:\n============================\n");

    static const struct { IF_OPER_STATUS code; const char *label; } status_map[] = {
        {IfOperStatusUp,             "Up (Operational)"},
        {IfOperStatusDown,           "Down"},
        {IfOperStatusTesting,        "Testing"},
        {IfOperStatusUnknown,        "Unknown"},
        {IfOperStatusDormant,        "Dormant"},
        {IfOperStatusNotPresent,     "Not Present"},
        {IfOperStatusLowerLayerDown, "Lower Layer Down"},
    };

    for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
        const char *status_str = "Unknown";
        for (int i = 0; i < (int)(sizeof(status_map)/sizeof(status_map[0])); i++) {
            if (a->OperStatus == status_map[i].code) { status_str = status_map[i].label; break; }
        }
        printf("Interface Index: %u\n", a->IfIndex);
        printf("Interface Name: %s\n", a->AdapterName);
        printf("Description: %ws\n", a->Description);
        printf("Status: %s\n", status_str);
        if (a->OperStatus == IfOperStatusUp) printf(">> Available for throttling <<\n");
        printf("\n");
    }
    free(addrs);
}

bool get_valid_nic_indices(unsigned int **valid_indices, unsigned int *count) {
    PIP_ADAPTER_ADDRESSES addrs = NULL;
    ULONG buf_len = 0;
    DWORD ret;

    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &buf_len);
    if (ret != ERROR_BUFFER_OVERFLOW) {
        fprintf(stderr, "GetAdaptersAddresses failed: %lu\n", ret);
        return false;
    }

    addrs = malloc(buf_len);
    if (!addrs) { fprintf(stderr, "Memory allocation failed\n"); return false; }

    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &buf_len);
    if (ret != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed: %lu\n", ret);
        free(addrs);
        return false;
    }

    *count = 0;
    for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next)
        if (a->OperStatus == IfOperStatusUp) (*count)++;

    if (*count == 0) {
        fprintf(stderr, "No operational network interfaces found\n");
        free(addrs); return false;
    }

    *valid_indices = malloc(*count * sizeof(unsigned int));
    if (!*valid_indices) {
        fprintf(stderr, "Memory allocation failed\n");
        free(addrs); return false;
    }

    unsigned int idx = 0;
    for (PIP_ADAPTER_ADDRESSES a = addrs; a && idx < *count; a = a->Next)
        if (a->OperStatus == IfOperStatusUp) (*valid_indices)[idx++] = a->IfIndex;

    free(addrs);
    return true;
}

bool is_valid_nic_index(unsigned int nic_index,
                        unsigned int *valid_indices, unsigned int valid_count) {
    for (unsigned int i = 0; i < valid_count; i++)
        if (valid_indices[i] == nic_index) return true;
    return false;
}

unsigned int *parse_nic_indices(const char *input, ThrottlingParams *params) {
    unsigned int *valid_indices = NULL;
    unsigned int valid_count = 0;

    if (!get_valid_nic_indices(&valid_indices, &valid_count)) {
        fprintf(stderr, "Failed to get valid network interface indices\n");
        exit(EXIT_FAILURE);
    }

    printf("Valid network interface indices: ");
    for (unsigned int i = 0; i < valid_count; i++) {
        if (i > 0) printf(", ");
        printf("%u", valid_indices[i]);
    }
    printf("\n\n");

    char *copy = strdup(input);
    if (!copy) { fprintf(stderr, "Memory allocation failed\n"); free(valid_indices); exit(EXIT_FAILURE); }

    int capacity = 16;
    unsigned int *nic_indices = malloc(capacity * sizeof(unsigned int));
    double *dl_limits = malloc(capacity * sizeof(double));
    double *ul_limits = malloc(capacity * sizeof(double));
    if (!nic_indices || !dl_limits || !ul_limits) {
        free(nic_indices); free(dl_limits); free(ul_limits);
        free(copy); free(valid_indices);
        fprintf(stderr, "Memory allocation failed\n"); exit(EXIT_FAILURE);
    }

    params->download_limits = dl_limits;
    params->upload_limits = ul_limits;
    params->nic_count = 0;

    char *token = strtok(copy, ",");
    while (token) {
        if ((int)params->nic_count >= capacity) {
            capacity *= 2;
            unsigned int *ti = realloc(nic_indices, capacity * sizeof(unsigned int));
            double *td = realloc(params->download_limits, capacity * sizeof(double));
            double *tu = realloc(params->upload_limits, capacity * sizeof(double));
            if (!ti || !td || !tu) {
                free(ti); free(td); free(tu);
                free(nic_indices); free(params->download_limits); free(params->upload_limits);
                free(copy); free(valid_indices);
                fprintf(stderr, "Memory reallocation failed\n"); exit(EXIT_FAILURE);
            }
            nic_indices = ti;
            params->download_limits = td;
            params->upload_limits = tu;
        }

        char *entry = strdup(token);
        if (!entry) {
            free(copy); free(nic_indices);
            free(params->download_limits); free(params->upload_limits);
            free(valid_indices);
            fprintf(stderr, "Memory allocation failed\n"); exit(EXIT_FAILURE);
        }

        char *nic_part = strtok(entry, ":");
        char *dl_part  = strtok(NULL,  ":");
        char *ul_part  = strtok(NULL,  ":");

        if (!nic_part) {
            fprintf(stderr, "Invalid NIC format in token '%s'\n", token);
            free(entry);
            token = strtok(NULL, ",");
            continue;
        }

        unsigned int nic_index = (unsigned int)atoi(nic_part);
        if (!is_valid_nic_index(nic_index, valid_indices, valid_count)) {
            fprintf(stderr, "Error: NIC index %u is not valid or not operational.\n", nic_index);
            fprintf(stderr, "Use --list-nics to see available interfaces.\n");
            free(entry); free(copy); free(nic_indices);
            free(params->download_limits); free(params->upload_limits);
            free(valid_indices);
            exit(EXIT_FAILURE);
        }

        nic_indices[params->nic_count] = nic_index;
        params->download_limits[params->nic_count] = dl_part ? parse_rate_with_units(dl_part) : 0;
        params->upload_limits[params->nic_count] = ul_part ? parse_rate_with_units(ul_part) : 0;
        params->nic_count++;
        free(entry);

        token = strtok(NULL, ",");
    }

    free(copy);
    free(valid_indices);
    params->nic_indices = nic_indices;
    return nic_indices;
}

// -----------------------------------------------------------------------
// Packet helpers
// -----------------------------------------------------------------------

bool parse_packet_headers(const char *packet, UINT packet_len, bool outbound,
                          char *local_ip_str, char *remote_ip_str,
                          UINT *local_port, UINT *remote_port,
                          BYTE *protocol, size_t ip_buffer_size) {
    PWINDIVERT_IPHDR ip_hdr = NULL;
    PWINDIVERT_IPV6HDR ipv6_hdr = NULL;
    PWINDIVERT_TCPHDR tcp_hdr = NULL;
    PWINDIVERT_UDPHDR udp_hdr = NULL;

    if (ip_buffer_size < INET6_ADDRSTRLEN) {
        fprintf(stderr, "parse_packet_headers: IP buffer too small\n");
        return false;
    }

    if (!WinDivertHelperParsePacket((PVOID)packet, packet_len,
                                    &ip_hdr, &ipv6_hdr, NULL, NULL, NULL,
                                    &tcp_hdr, &udp_hdr, NULL, NULL, NULL, NULL)) {
        return false;
    }

    *protocol = 0;
    *local_port = *remote_port = 0;

    if (ipv6_hdr) {
        if (!inet_ntop(AF_INET6, &ipv6_hdr->SrcAddr, local_ip_str, (socklen_t)ip_buffer_size))
            strncpy(local_ip_str, "invalid", ip_buffer_size);
        if (!inet_ntop(AF_INET6, &ipv6_hdr->DstAddr, remote_ip_str, (socklen_t)ip_buffer_size))
            strncpy(remote_ip_str, "invalid", ip_buffer_size);
        *protocol = ipv6_hdr->NextHdr;
    } else if (ip_hdr) {
        struct in_addr src = {.S_un.S_addr = ip_hdr->SrcAddr};
        struct in_addr dst = {.S_un.S_addr = ip_hdr->DstAddr};
        if (!inet_ntop(AF_INET, &src, local_ip_str, (socklen_t)ip_buffer_size))
            strncpy(local_ip_str, "invalid", ip_buffer_size);
        if (!inet_ntop(AF_INET, &dst, remote_ip_str, (socklen_t)ip_buffer_size))
            strncpy(remote_ip_str, "invalid", ip_buffer_size);
        *protocol = ip_hdr->Protocol;
    }

    UINT src_port = 0, dst_port = 0;
    if (tcp_hdr) { src_port = ntohs(tcp_hdr->SrcPort); dst_port = ntohs(tcp_hdr->DstPort); }
    else if (udp_hdr) { src_port = ntohs(udp_hdr->SrcPort); dst_port = ntohs(udp_hdr->DstPort); }

    if (!outbound) {
        // Inbound: swap so local_ip_str holds the local (destination) address
        char tmp[INET6_ADDRSTRLEN];

        // Ensure both strings are properly null-terminated before swapping
        local_ip_str[ip_buffer_size - 1] = '\0';
        remote_ip_str[ip_buffer_size - 1] = '\0';

        // Safe copy using strcpy_s or explicit bounds checking
        strncpy(tmp, local_ip_str, INET6_ADDRSTRLEN - 1);
        tmp[INET6_ADDRSTRLEN - 1] = '\0';

        strncpy(local_ip_str, remote_ip_str, ip_buffer_size - 1);
        local_ip_str[ip_buffer_size - 1] = '\0';

        strncpy(remote_ip_str, tmp, ip_buffer_size - 1);
        remote_ip_str[ip_buffer_size - 1] = '\0';
    }

    *local_port  = outbound ? src_port : dst_port;
    *remote_port = outbound ? dst_port : src_port;
    return true;
}

bool validate_packet(const char *packet, UINT packet_len, PacketStats *stats) {
    if (!packet || packet_len == 0 || packet_len > MAX_PACKET_SIZE) {
        if (stats) InterlockedIncrement(&stats->invalid_packets);
        return false;
    }

    PWINDIVERT_IPHDR ip_hdr = NULL;
    PWINDIVERT_IPV6HDR ipv6_hdr = NULL;
    PWINDIVERT_TCPHDR tcp_hdr = NULL;
    PWINDIVERT_UDPHDR udp_hdr = NULL;
    UINT8 ip_proto = 0;
    BYTE proto = 0;

    if (!WinDivertHelperParsePacket((PVOID)packet, packet_len, &ip_hdr, &ipv6_hdr,
                                    &ip_proto, NULL, NULL, &tcp_hdr, &udp_hdr,
                                    NULL, NULL, NULL, NULL)) {
        if (stats) InterlockedIncrement(&stats->invalid_packets);
        return false;
    }

    if (ip_hdr) proto = ip_hdr->Protocol;
    else if (ipv6_hdr) proto = ipv6_hdr->NextHdr;
    if (!proto && ip_proto) proto = (BYTE)ip_proto;

    if (ip_hdr) {
        if (ip_hdr->Version != 4 || ip_hdr->HdrLength < 5 || ip_hdr->HdrLength > 15) {
            if (stats) InterlockedIncrement(&stats->invalid_packets);
            return false;
        }
        UINT16 total = ntohs(ip_hdr->Length);
        if (total > packet_len || total < (UINT16)(ip_hdr->HdrLength * 4)) {
            if (stats) InterlockedIncrement(&stats->invalid_packets);
            return false;
        }
    }
    if (ipv6_hdr) {
        if (ipv6_hdr->Version != 6 ||
            (UINT)(ntohs(ipv6_hdr->Length) + 40) > packet_len) {
            if (stats) InterlockedIncrement(&stats->invalid_packets);
            return false;
        }
    }
    if (tcp_hdr && proto == IPPROTO_TCP) {
        if (tcp_hdr->HdrLength < 5 || tcp_hdr->HdrLength > 15 ||
            ntohs(tcp_hdr->SrcPort) == 0 || ntohs(tcp_hdr->DstPort) == 0) {
            if (stats) InterlockedIncrement(&stats->invalid_packets);
            return false;
        }
    }
    if (udp_hdr && proto == IPPROTO_UDP) {
        UINT16 udp_len = ntohs(udp_hdr->Length);
        UINT16 ip_hdr_sz = ip_hdr ? (ip_hdr->HdrLength * 4) : (ipv6_hdr ? 40 : 0);
        if (udp_len < 8 || (UINT)(ip_hdr_sz + udp_len) > packet_len ||
            ntohs(udp_hdr->SrcPort) == 0 || ntohs(udp_hdr->DstPort) == 0) {
            if (stats) InterlockedIncrement(&stats->invalid_packets);
            return false;
        }
    }
    return true;
}

bool reinject_packet(HANDLE handle, char *packet, UINT packet_len,
                     WINDIVERT_ADDRESS *addr, PacketStats *stats) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "reinject_packet: invalid handle\n");
        return false;
    }
    if (!packet || packet_len == 0 || packet_len > MAX_PACKET_SIZE) {
        fprintf(stderr, "reinject_packet: invalid packet (len=%u)\n", packet_len);
        if (stats) InterlockedIncrement(&stats->invalid_packets);
        return false;
    }
    if (!addr) {
        fprintf(stderr, "reinject_packet: NULL address\n");
        return false;
    }

    if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
        DWORD err = GetLastError();
        fprintf(stderr, "Failed to reinject packet: %lu\n", err);
        if (stats && (err == ERROR_INVALID_PARAMETER || err == ERROR_INVALID_DATA))
            InterlockedIncrement(&stats->invalid_packets);
        return false;
    }
    return true;
}

bool should_drop_packet(float packet_loss, PacketStats *stats) {
    if (packet_loss <= 0.0f) return false;
    unsigned int rand_val = 0;
    rand_s(&rand_val);
    float norm = (float)rand_val / (float)UINT_MAX;
    if (norm < (packet_loss / 100.0f)) {
        if (stats) InterlockedIncrement(&stats->packets_dropped_loss);
        return true;
    }
    return false;
}

// -----------------------------------------------------------------------
// Per-IP / per-port rate limiting
// -----------------------------------------------------------------------

bool check_packet_rate_limit(ProcessParams *processparams,
                              CRITICAL_SECTION *lock,
                              const char *ip, UINT port,
                              int max_packets) {
    char key[INET_ADDRSTRLEN + 7];
    snprintf(key, sizeof(key), "%s:%u", ip, port);

    ULONGLONG now = GetTickCount64();
    ConnectionRate *rate_entry = NULL;

    EnterCriticalSection(lock);

    HASH_FIND_STR(processparams->connection_rates, key, rate_entry);
    if (!rate_entry) {
        rate_entry = malloc(sizeof(ConnectionRate));
        if (!rate_entry) { LeaveCriticalSection(lock); return false; }
        strncpy(rate_entry->key, key, sizeof(rate_entry->key) - 1);
        rate_entry->key[sizeof(rate_entry->key) - 1] = '\0';
        rate_entry->packet_count = 1;
        rate_entry->last_reset = now;
        HASH_ADD_STR(processparams->connection_rates, key, rate_entry);
    } else {
        // Handle 64-bit wrap
        if (now < rate_entry->last_reset) {
            // 64-bit wrapped (won't happen in our lifetime, but handle anyway)
            if (now + (0xFFFFFFFFFFFFFFFFULL - rate_entry->last_reset) > 1000) {
                rate_entry->packet_count = 1;
                rate_entry->last_reset = now;
            } else {
                rate_entry->packet_count++;
            }
        } else if (now - rate_entry->last_reset > 1000) {
            rate_entry->packet_count = 1;
            rate_entry->last_reset = now;
        } else {
            rate_entry->packet_count++;
        }

        if (rate_entry->packet_count > max_packets) {
            LeaveCriticalSection(lock);
            return false;
        }
    }

    LeaveCriticalSection(lock);
    return true;
}

void cleanup_rate_limits(ProcessParams *processparams, CRITICAL_SECTION *lock) {
    ConnectionRate *cur, *tmp;
    int cleaned = 0;

    EnterCriticalSection(lock);
    HASH_ITER(hh, processparams->connection_rates, cur, tmp) {
        HASH_DELETE(hh, processparams->connection_rates, cur);
        free(cur);
        cleaned++;
    }
    processparams->connection_rates = NULL;
    LeaveCriticalSection(lock);

    if (cleaned > 0)
        printf("Cleaned up %d stale connection entries\n", cleaned);
}

// -----------------------------------------------------------------------
// Delay buffer
// -----------------------------------------------------------------------

bool delay_buffer_init(DelayBuffer *buffer, int capacity) {
    buffer->packets = calloc(capacity, sizeof(DelayedPacket));
    if (!buffer->packets) return false;
    buffer->head = buffer->tail = buffer->count = 0;
    buffer->capacity = capacity;
    return true;
}

void delay_buffer_cleanup(DelayBuffer *buffer) {
    if (buffer) {
        free(buffer->packets);
        memset(buffer, 0, sizeof(DelayBuffer));
    }
}

bool delay_buffer_add(DelayBuffer *buffer, CRITICAL_SECTION *lock,
                      const char *packet, UINT packet_len,
                      const WINDIVERT_ADDRESS *addr, LONGLONG delay_ticks,
                      PacketStats *stats) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONGLONG target_time = counter.QuadPart + delay_ticks;

    EnterCriticalSection(lock);
    if (buffer->count >= buffer->capacity) {
        LeaveCriticalSection(lock);
        return false;
    }

    DelayedPacket *slot = &buffer->packets[buffer->tail];
    memcpy(slot->packet, packet, packet_len);
    slot->packet_len = packet_len;
    slot->addr = *addr;
    slot->timestamp = target_time;
    slot->in_use = true;
    buffer->tail = (buffer->tail + 1) % buffer->capacity;
    buffer->count++;
    LeaveCriticalSection(lock);

    if (stats) InterlockedIncrement(&stats->packets_delayed);
    return true;
}

void delay_buffer_process(DelayBuffer *buffer, CRITICAL_SECTION *lock,
                          HANDLE handle) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONGLONG now = counter.QuadPart;

    while (1) {
        char temp_packet[MAX_PACKET_SIZE];
        UINT temp_len = 0;
        WINDIVERT_ADDRESS temp_addr;
        int current_head;

        EnterCriticalSection(lock);
        if (buffer->count <= 0) { LeaveCriticalSection(lock); break; }

        DelayedPacket *slot = &buffer->packets[buffer->head];
        if (!slot->in_use || slot->timestamp > now) { LeaveCriticalSection(lock); break; }

        temp_len = slot->packet_len;
        if (temp_len > MAX_PACKET_SIZE) {
            slot->in_use = false;
            buffer->head = (buffer->head + 1) % buffer->capacity;
            buffer->count--;
            LeaveCriticalSection(lock);
            continue;
        }

        memcpy(temp_packet, slot->packet, temp_len);
        temp_addr = slot->addr;
        current_head = buffer->head;
        buffer->head = (buffer->head + 1) % buffer->capacity;
        buffer->count--;
        LeaveCriticalSection(lock);

        WinDivertSend(handle, temp_packet, temp_len, NULL, &temp_addr);

        EnterCriticalSection(lock);
        buffer->packets[current_head].in_use = false;
        LeaveCriticalSection(lock);
    }
}

// -----------------------------------------------------------------------
// Process list helpers
// -----------------------------------------------------------------------

char **parse_processes(char *input, int *count) {
    int capacity = 16;
    char **processes = malloc(capacity * sizeof(char *));
    if (!processes) { fprintf(stderr, "Memory allocation failed\n"); exit(EXIT_FAILURE); }
    *count = 0;

    char *ctx = NULL;
    char *token = strtok_s(input, ",", &ctx);
    while (token) {
        if (*count >= capacity) {
            capacity *= 2;
            char **np = realloc(processes, capacity * sizeof(char *));
            if (!np) {
                for (int i = 0; i < *count; i++) free(processes[i]);
                free(processes);
                fprintf(stderr, "Memory allocation failed\n"); exit(EXIT_FAILURE);
            }
            processes = np;
        }
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') { *end = '\0'; end--; }

        processes[*count] = strdup(token);
        if (!processes[*count]) {
            for (int i = 0; i < *count; i++) free(processes[i]);
            free(processes);
            fprintf(stderr, "Memory allocation failed\n"); exit(EXIT_FAILURE);
        }
        (*count)++;
        token = strtok_s(NULL, ",", &ctx);
    }
    return processes;
}

int parse_process_update_interval(const char *input, ProcessParams *processparams) {
    if (strcmp(input, "0") == 0) {
        processparams->packet_threshold = 0;
        processparams->time_threshold_ms = 0;
        processparams->min_update_interval_ms = 0;
        return 0;
    }

    char *copy = strdup(input);
    if (!copy) { fprintf(stderr, "Memory allocation failed\n"); return 1; }

    char *main_part = strtok(copy, ",");
    char *cooldown_part = strtok(NULL, ",");

    if (!main_part) {
        fprintf(stderr, "Error: Invalid format for --process-update-interval.\n");
        free(copy); return 1;
    }

    size_t main_len = strlen(main_part);
    if (main_len < 2 || main_len >= MAX_INTERVAL_STR_LEN) {
        fprintf(stderr, "Error: Invalid --process-update-interval format.\n");
        free(copy); return 1;
    }

    char value_str[MAX_INTERVAL_STR_LEN];
    strncpy(value_str, main_part, main_len - 1);
    value_str[main_len - 1] = '\0';

    if (!isdigit((unsigned char)value_str[0])) {
        fprintf(stderr, "Error: Invalid numeric value for --process-update-interval.\n");
        free(copy); return 1;
    }

    unsigned int value = (unsigned int)atoi(value_str);
    char unit = (char)tolower((unsigned char)main_part[main_len - 1]);
    unsigned int cooldown_ms = 5000;

    if (cooldown_part) {
        while (isspace((unsigned char)*cooldown_part)) cooldown_part++;
        if (isdigit((unsigned char)*cooldown_part))
            cooldown_ms = (unsigned int)atoi(cooldown_part);
        else
            fprintf(stderr, "Warning: Invalid cooldown value '%s', using 5000ms\n", cooldown_part);
    }

    if (unit == 'p') {
        processparams->packet_threshold = value;
        processparams->time_threshold_ms = 0;
        processparams->min_update_interval_ms = cooldown_ms;
    } else if (unit == 't') {
        processparams->time_threshold_ms = value;
        processparams->packet_threshold = 0;
        processparams->min_update_interval_ms = cooldown_ms;
    } else {
        fprintf(stderr, "Error: Unknown unit '%c'. Use 'p' or 't'.\n", unit);
        free(copy); return 1;
    }

    free(copy);
    return 0;
}

void update_pid_map(ProcessParams *processparams, PidTableCache *pid_cache) {
    (void)pid_cache; // Available for future use; not needed here

    if (!processparams->process_list) return;

    clock_t now = clock();
    double elapsed_ms = ((double)(now - processparams->last_update_time) / CLOCKS_PER_SEC) * 1000.0;

    bool time_based = (processparams->time_threshold_ms > 0 && elapsed_ms >= processparams->time_threshold_ms);
    bool packet_based = (processparams->packet_threshold > 0 && ++processparams->packet_count >= processparams->packet_threshold);
    double since_last = ((double)(now - processparams->last_actual_update) / CLOCKS_PER_SEC) * 1000.0;

    if ((time_based || packet_based) && since_last >= processparams->min_update_interval_ms) {
        processparams->last_actual_update = now;
        processparams->packet_count = 0;
        processparams->last_update_time = now;
        processparams->needs_update = true;
    }

    if (!processparams->needs_update) return;
    processparams->needs_update = false;

    // Remove dead PIDs
    unsigned int map_sz = HASH_COUNT(processparams->pid_map);
    PIDEntry **to_remove = malloc(map_sz * sizeof(PIDEntry *));
    int remove_count = 0;

    PIDEntry *entry, *tmp;
    HASH_ITER(hh, processparams->pid_map, entry, tmp) {
        if (!is_process_alive(entry->pid) && remove_count < 1024)
            to_remove[remove_count++] = entry;
    }
    for (int i = 0; i < remove_count; i++) {
        printf("Stale PID %u removed.\n", to_remove[i]->pid);
        HASH_DEL(processparams->pid_map, to_remove[i]);
        free(to_remove[i]);
    }
    free(to_remove);

    // Add newly discovered PIDs
    char *list_copy = strdup(processparams->process_list);
    if (!list_copy) { fprintf(stderr, "Memory allocation failed\n"); exit(EXIT_FAILURE); }
    int proc_count = 0;
    char **procs = parse_processes(list_copy, &proc_count);
    free(list_copy);

    for (int i = 0; i < proc_count; i++) {
        int *pid_list = NULL;
        int pid_count = get_pids_from_name(procs[i], &pid_list);
        for (int j = 0; j < pid_count; j++) {
            HASH_FIND_INT(processparams->pid_map, &pid_list[j], entry);
            if (!entry && is_process_alive(pid_list[j])) {
                add_pid_to_map_pool(&processparams->pid_map, pid_list[j], &g_pid_pool);
                printf("Added PID %d for '%s'\n", pid_list[j], procs[i]);
            }
        }
        if (pid_list) free(pid_list);
        free(procs[i]);
    }
    free(procs);
}

// -----------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------

void print_statistics(bool enable_statistics, const PacketStats *stats) {
    if (!enable_statistics || !stats) return;

    LONG processed = InterlockedExchangeAdd((volatile LONG *)&stats->packets_processed, 0);
    LONG dropped_rate = InterlockedExchangeAdd((volatile LONG *)&stats->packets_dropped_rate_limit, 0);
    LONG dropped_loss = InterlockedExchangeAdd((volatile LONG *)&stats->packets_dropped_loss, 0);
    LONG delayed = InterlockedExchangeAdd((volatile LONG *)&stats->packets_delayed, 0);
    LONGLONG bytes = InterlockedCompareExchange64((volatile LONGLONG *)&stats->bytes_processed, 0, 0);
    LONG invalid = InterlockedExchangeAdd((volatile LONG *)&stats->invalid_packets, 0);

    printf("\n=== Bandwidth Shaper Statistics ===\n");
    printf("Packets processed:              %ld\n", processed);
    printf("Bytes processed:                %lld (%.2f MB)\n", bytes, bytes / 1048576.0);
    printf("Packets dropped (rate limit):   %ld\n", dropped_rate);
    printf("Packets dropped (loss sim):     %ld\n", dropped_loss);
    printf("Packets delayed:                %ld\n", delayed);
    printf("Invalid packets:                %ld\n", invalid);
    if (processed > 0)
        printf("Drop rate:                      %.2f%%\n",
               ((double)(dropped_rate + dropped_loss) / processed) * 100.0);
    printf("===================================\n\n");
}

void update_statistics(bool enable_statistics, PacketStats *stats,
                       double perf_frequency) {
    if (!enable_statistics || !stats) return;

    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);

    if ((counter.QuadPart - stats->last_stats_update) * 1000.0 / perf_frequency
            >= STATS_UPDATE_INTERVAL) {
        print_statistics(enable_statistics, stats);
        stats->last_stats_update = counter.QuadPart;
    }
}

// -----------------------------------------------------------------------
// WinDivert / admin helpers
// -----------------------------------------------------------------------

void stop_windivert(void) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { fprintf(stderr, "OpenSCManager failed (%lu)\n", GetLastError()); return; }

    SC_HANDLE hSvc = OpenService(hSCM, TEXT("WinDivert"),
                                 SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (!hSvc) {
        fprintf(stderr, "OpenService failed (%lu)\n", GetLastError());
        CloseServiceHandle(hSCM);
        return;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD needed;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&status, sizeof(status), &needed)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            printf("Stopping WinDivert service...\n");
            if (!ControlService(hSvc, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status))
                fprintf(stderr, "Failed to stop WinDivert: %lu\n", GetLastError());
            else
                printf("WinDivert service stopped.\n");
        } else {
            printf("WinDivert service is not running.\n");
        }
    } else {
        fprintf(stderr, "QueryServiceStatusEx failed (%lu)\n", GetLastError());
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
}

int is_admin(void) {
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;

    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &sid)) {
        if (!CheckTokenMembership(NULL, sid, &admin)) admin = FALSE;
        FreeSid(sid);
    }
    return admin;
}

// -----------------------------------------------------------------------
// String helpers
// -----------------------------------------------------------------------

const char *get_program_name_r(const char *path, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return "unknown";
    if (!path) { strncpy(buffer, "unknown", buffer_size - 1); buffer[buffer_size - 1] = '\0'; return buffer; }

    const char *name = strrchr(path, '\\');
    if (!name) name = strrchr(path, '/');
    if (name)  name++;
    else       name = path;

    size_t name_len = strlen(name);
    if (name_len >= 4 && _stricmp(name + name_len - 4, ".exe") == 0) {
        size_t copy_len = name_len - 4;
        if (copy_len >= buffer_size) copy_len = buffer_size - 1;
        strncpy(buffer, name, copy_len);
        buffer[copy_len] = '\0';
    } else {
        strncpy(buffer, name, buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
    }
    return buffer;
}

char *trim_whitespace(char *str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}
