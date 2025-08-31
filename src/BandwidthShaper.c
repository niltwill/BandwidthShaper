// Define statements
#define WIN32_LEAN_AND_MEAN
#define MAX_INTERVAL_STR_LEN 32
#define MAX_PACKET_SIZE 65575      // Maximum packet size (65535 + 40)
#define DEFAULT_DL_BUFFER 150000   // Default download buffer size in bytes
#define DEFAULT_UL_BUFFER 150000   // Default upload buffer size in bytes
#define DELAY_BUFFER_SIZE 8192     // Circular buffer size for delayed packets
#define STATS_UPDATE_INTERVAL 5000 // Update stats every 5 seconds

// Standard library headers
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

// System-specific headers (Windows APIs)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <iphlpapi.h>

// Third-party or external libraries
#include "windivert.h"
#include "uthash.h"

// Linker directives
#pragma comment(lib, "User32.lib") // GetAsyncKeyState
#pragma comment(lib, "iphlpapi.lib")

// Single global lock
CRITICAL_SECTION g_global_lock;

// Hash Map for Target PIDs
typedef struct {
    int pid;                // Process ID (key)
    UT_hash_handle hh;      // Hash handle for uthash
} PIDEntry;

// Parameters for connection rate
typedef struct {
    char ip[INET_ADDRSTRLEN];  // IP address as key
    UINT port;
    int packet_count;
    DWORD last_reset;
    UT_hash_handle hh;
} ConnectionRate;

// Parameters for the NICs
typedef struct {
    unsigned int *nic_indices;
    unsigned int nic_count;
    double *download_limits; // Download rate per NIC (bytes per second)
    double *upload_limits;   // Upload rate per NIC (bytes per second)
} ThrottlingParams;

// The parameters for processes
typedef struct {
    PIDEntry *pid_map;
    ConnectionRate *connection_rates;
    char *process_list;
    unsigned int packet_threshold;
    unsigned int time_threshold_ms;
    unsigned int packet_count;
    clock_t last_update_time;
    bool needs_update;
} ProcessParams;

// Token Bucket Structure
typedef struct {
    double rate;            // Tokens added per second
    int max_tokens;         // Maximum tokens allowed
    volatile LONG tokens;   // Current number of tokens (atomic)
    double token_accumulator; // Stores fractional tokens to prevent truncation loss
    volatile LONGLONG last_checked; // Last update time (high precision)
    double freq;            // QueryPerformanceFrequency() value for time conversion
} TokenBucket;

// Delayed packet structure for circular buffer
typedef struct {
    char packet[MAX_PACKET_SIZE];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    LONGLONG timestamp;  // When to reinject
    bool in_use;
} DelayedPacket;

// Circular buffer for delayed packets
typedef struct {
    DelayedPacket *packets;
    int head;
    int tail;
    int count;
    int capacity;
} DelayBuffer;

// Statistics structure
typedef struct {
    volatile LONG packets_processed;
    volatile LONG packets_dropped_rate_limit;
    volatile LONG packets_dropped_loss;
    volatile LONG packets_delayed;
    volatile LONG bytes_processed;
    volatile LONG invalid_packets;
    LONGLONG last_stats_update;
} PacketStats;

// Global variables
PacketStats g_stats = {0};
DelayBuffer g_delay_buffer = {0};
double g_perf_frequency = 0.0;
volatile bool quit_program = false; // For Ctrl+C handler to quit
bool enable_statistics = false;


// Function to parse a rate string with units
double parse_rate_with_units(const char *rate_str) {
	char unit[3] = {0}; // To handle two-character units like "Gb", "Mb", etc.
	double value = 0;

	// Parse the numeric value and optional unit
	if (sscanf(rate_str, "%lf%2s", &value, unit) >= 1) {
		// Determine the multiplier based on the unit (case-sensitive)
		if (strcmp(unit, "b") == 0) {			 // Bytes
			return value;
		} else if (strcmp(unit, "KB") == 0) {	 // Kilobytes
			return value * 1000.0;
		} else if (strcmp(unit, "MB") == 0) {	 // Megabytes
			return value * 1000000.0;
		} else if (strcmp(unit, "GB") == 0) {	 // Gigabytes
			return value * 1000000000.0;
		} else if (strcmp(unit, "Kb") == 0) {	 // Kilobits
			return value * 1000.0 / 8.0;
		} else if (strcmp(unit, "Mb") == 0) {	 // Megabits
			return value * 1000000.0 / 8.0;
		} else if (strcmp(unit, "Gb") == 0) {	 // Gigabits
			return value * 1000000000.0 / 8.0;
		} else if (unit[0] == '\0') {			 // No unit specified
			return value * 1000.0;				 // Default to kilobytes
		} else {
			fprintf(stderr, "Invalid unit '%s' in rate '%s'. Defaulting to kilobytes.\n", unit, rate_str);
			return value * 1000.0; // Default to kilobytes
		}
	} else {
		fprintf(stderr, "Failed to parse rate '%s'. Defaulting to 0.\n", rate_str);
		return value;
	}
}

// Function to print rate for different units
void print_rate_with_units(const char *label, double rate_bps) {
	if (rate_bps >= 1000000000.0) { // Gigabits per second
		printf("%s: %.2f Gbps (%.2f GBps)\n", label, rate_bps / 1000000000.0, rate_bps / (1000000000.0 * 8.0));
	} else if (rate_bps >= 1000000.0) { // Megabits per second
		printf("%s: %.2f Mbps (%.2f MBps)\n", label, rate_bps / 1000000.0, rate_bps / (1000000.0 * 8.0));
	} else if (rate_bps >= 1000.0) { // Kilobits per second
		printf("%s: %.2f Kbps (%.2f KBps)\n", label, rate_bps / 1000.0, rate_bps / (1000.0 * 8.0));
	} else { // Bits per second
		printf("%s: %.2f bps (%.2f Bps)\n", label, rate_bps, rate_bps / 8.0);
	}
}

// Function to get current high-resolution time in ticks
static inline LONGLONG get_time_ticks() {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
}

// Function to initialize the token bucket
bool token_bucket_init(TokenBucket *bucket, double rate, int max_tokens) {
    if (!bucket || rate <= 0 || max_tokens <= 0) return false;

    bucket->rate = rate;
    bucket->max_tokens = max_tokens;
    bucket->tokens = max_tokens;
    bucket->token_accumulator = 0.0;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    bucket->freq = (double)freq.QuadPart;
    bucket->last_checked = get_time_ticks();
    
    return true;
}

// Function to update the token bucket (replenish tokens based on elapsed time)
void token_bucket_update(TokenBucket *bucket) {
    LONGLONG now = get_time_ticks();
    LONGLONG last = InterlockedExchangeAdd64(&bucket->last_checked, 0); // Atomic read
    LONGLONG elapsed_ticks = now - last;

    if (elapsed_ticks > 0) {
        double elapsed_seconds = (double)elapsed_ticks / bucket->freq;  // Convert ticks to seconds
        double tokens_to_add = bucket->rate * elapsed_seconds;

        // Accumulate fractional tokens
		EnterCriticalSection(&g_global_lock);
        bucket->token_accumulator += tokens_to_add;

        // Extract whole tokens and keep the fractional part
        int whole_tokens = (int)bucket->token_accumulator;
        bucket->token_accumulator -= whole_tokens;
		LeaveCriticalSection(&g_global_lock);

        // Update token count safely
        int new_tokens = min(bucket->tokens + whole_tokens, bucket->max_tokens);
        InterlockedExchange(&bucket->tokens, new_tokens);  // Atomic write

        // Update last_checked timestamp
        InterlockedExchange64(&bucket->last_checked, now);
    }
}

// Function to check if there are enough tokens for a packet
bool token_bucket_has_enough_tokens(TokenBucket *bucket, int packet_size) {
    return bucket->tokens >= packet_size;
}

// Function to consume tokens from the bucket safely (atomic operation)
bool token_bucket_consume(TokenBucket *bucket, int packet_size) {
    token_bucket_update(bucket); // Ensure tokens are up to date

    LONG old_tokens;
    do {
        old_tokens = bucket->tokens;
        if (old_tokens < packet_size) return false;  // Not enough tokens
    } while (InterlockedCompareExchange(&bucket->tokens, old_tokens - packet_size, old_tokens) != old_tokens);

    return true;
}

// Function to reinject the packet into the network
void reinject_packet(HANDLE handle, char *packet, UINT packet_len, WINDIVERT_ADDRESS *addr) {
    if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
        fprintf(stderr, "Failed to reinject packet: %lu\n", GetLastError());
    }
}

// Function to decide if a packet should be dropped due to packet loss
bool should_drop_packet(HANDLE handle, char *packet, unsigned int packet_len, WINDIVERT_ADDRESS addr, float packet_loss) {
	if (packet_loss > 0.00f) {
		float rand_value = (float)rand() / (float)RAND_MAX;  // Generate a random float between 0.0 and 1.0
		if (rand_value < (packet_loss / 100.0f)) {
			//printf("Dropped packet to simulate loss (%.2f%%)\n", packet_loss);
			InterlockedIncrement(&g_stats.packets_dropped_loss);
			return true;  // Drop the packet
		}
	}
	return false;  // No packet loss, process normally
}

// Function to list network adapters
void list_network_interfaces() {
    PIP_ADAPTER_ADDRESSES adapter_addresses = NULL;
    ULONG out_buf_len = 0;
    DWORD dwRetVal = 0;

    // Get the necessary size for the buffer
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &out_buf_len);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(out_buf_len);
        if (adapter_addresses == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }
    } else if (dwRetVal != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed with error %lu\n", dwRetVal);
        return;
    }

    // Retrieve the list of network adapters
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &out_buf_len);
    if (dwRetVal != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed with error %lu\n", dwRetVal);
        free(adapter_addresses);
        return;
    }

    printf("Available Network Interfaces:\n");
    printf("============================\n");

    // Iterate through the adapters and display information
    PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
    while (adapter) {
        const char *status_str = "Unknown";
        switch (adapter->OperStatus) {
            case IfOperStatusUp: status_str = "Up (Operational)"; break;
            case IfOperStatusDown: status_str = "Down"; break;
            case IfOperStatusTesting: status_str = "Testing"; break;
            case IfOperStatusUnknown: status_str = "Unknown"; break;
            case IfOperStatusDormant: status_str = "Dormant"; break;
            case IfOperStatusNotPresent: status_str = "Not Present"; break;
            case IfOperStatusLowerLayerDown: status_str = "Lower Layer Down"; break;
        }

        printf("Interface Index: %u\n", adapter->IfIndex);
        printf("Interface Name: %s\n", adapter->AdapterName);
        printf("Description: %ws\n", adapter->Description);
        printf("Status: %s\n", status_str);
        
        // Only show "Available for throttling" for operational interfaces
        if (adapter->OperStatus == IfOperStatusUp) {
            printf(">> Available for throttling <<\n");
        }
        
        printf("\n");
        adapter = adapter->Next;
    }

    free(adapter_addresses);
}

// Function to get all valid NIC indices on the system
bool get_valid_nic_indices(unsigned int **valid_indices, unsigned int *count) {
    PIP_ADAPTER_ADDRESSES adapter_addresses = NULL;
    ULONG out_buf_len = 0;
    DWORD dwRetVal = 0;

    // Get the necessary size for the buffer
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &out_buf_len);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(out_buf_len);
        if (adapter_addresses == NULL) {
            fprintf(stderr, "Memory allocation failed for adapter addresses\n");
            return false;
        }
    } else if (dwRetVal != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed with error %lu\n", dwRetVal);
        return false;
    }

    // Retrieve the list of network adapters
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &out_buf_len);
    if (dwRetVal != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed with error %lu\n", dwRetVal);
        free(adapter_addresses);
        return false;
    }

    // Count valid adapters first
    *count = 0;
    PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
    while (adapter) {
        // Only count operational interfaces
        if (adapter->OperStatus == IfOperStatusUp) {
            (*count)++;
        }
        adapter = adapter->Next;
    }

    if (*count == 0) {
        fprintf(stderr, "No operational network interfaces found\n");
        free(adapter_addresses);
        return false;
    }

    // Allocate array for valid indices
    *valid_indices = malloc(*count * sizeof(unsigned int));
    if (!*valid_indices) {
        fprintf(stderr, "Memory allocation failed for valid indices\n");
        free(adapter_addresses);
        return false;
    }

    // Fill the array with valid indices
    unsigned int index = 0;
    adapter = adapter_addresses;
    while (adapter && index < *count) {
        if (adapter->OperStatus == IfOperStatusUp) {
            (*valid_indices)[index] = adapter->IfIndex;
            index++;
        }
        adapter = adapter->Next;
    }

    free(adapter_addresses);
    return true;
}

// Function to check if a NIC index is valid
bool is_valid_nic_index(unsigned int nic_index, unsigned int *valid_indices, unsigned int valid_count) {
    for (unsigned int i = 0; i < valid_count; i++) {
        if (valid_indices[i] == nic_index) {
            return true;
        }
    }
    return false;
}

// Helper function to parse comma-separated NIC indices
unsigned int *parse_nic_indices(const char *input, ThrottlingParams *params) {
    // Get valid NIC indices from system
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
    if (!copy) {
        fprintf(stderr, "Memory allocation failed for NIC parsing.\n");
        free(valid_indices);
        exit(EXIT_FAILURE);
    }

    char *token = strtok(copy, ",");
    int capacity = 16;
    unsigned int *nic_indices = malloc(capacity * sizeof(unsigned int));
    params->download_limits = malloc(capacity * sizeof(double));
    params->upload_limits = malloc(capacity * sizeof(double));

    if (!nic_indices || !params->upload_limits || !params->download_limits) {
        fprintf(stderr, "Memory allocation failed for NIC parameters.\n");
        free(copy);
        free(nic_indices);
        free(params->download_limits);
        free(params->upload_limits);
        free(valid_indices);
        exit(EXIT_FAILURE);
    }

    params->nic_count = 0;

    while (token) {
        if (params->nic_count >= capacity) {
            capacity *= 2;
            unsigned int *new_indices = realloc(nic_indices, capacity * sizeof(unsigned int));
            double *new_download_limits = realloc(params->download_limits, capacity * sizeof(double));
            double *new_upload_limits = realloc(params->upload_limits, capacity * sizeof(double));

            if (!new_indices || !new_download_limits || !new_upload_limits) {
                fprintf(stderr, "Memory reallocation failed.\n");
                free(copy);
                free(nic_indices);
                free(params->download_limits);
                free(params->upload_limits);
                free(valid_indices);
                exit(EXIT_FAILURE);
            }

            nic_indices = new_indices;
            params->download_limits = new_download_limits;
            params->upload_limits = new_upload_limits;
        }

        char *entry = strdup(token);
        if (!entry) {
            fprintf(stderr, "Memory allocation failed for NIC entry parsing.\n");
            free(copy);
            free(nic_indices);
            free(params->download_limits);
            free(params->upload_limits);
            free(valid_indices);
            exit(EXIT_FAILURE);
        }

        char *nic_part = strtok(entry, ":");
        char *download_part = strtok(NULL, ":");
        char *upload_part = strtok(NULL, ":");

        if (!nic_part) {
            fprintf(stderr, "Invalid NIC format.\n");
            free(entry);
            continue;
        }

        unsigned int nic_index = (unsigned int)atoi(nic_part);

        // Validate NIC index
        if (!is_valid_nic_index(nic_index, valid_indices, valid_count)) {
            fprintf(stderr, "Error: Network interface index %u is not valid or not operational.\n", nic_index);
            fprintf(stderr, "Use --list-nics to see available interfaces.\n");
            free(entry);
            free(copy);
            free(nic_indices);
            free(params->download_limits);
            free(params->upload_limits);
            free(valid_indices);
            exit(EXIT_FAILURE);
        }

        nic_indices[params->nic_count] = nic_index;
        params->download_limits[params->nic_count] = download_part ? parse_rate_with_units(download_part) : 0;
        params->upload_limits[params->nic_count] = upload_part ? parse_rate_with_units(upload_part) : 0;

        params->nic_count++;
        free(entry);

        token = strtok(NULL, ",");
    }

    free(copy);
    free(valid_indices);
    return nic_indices;
}

// Function to find TCP PID
DWORD find_tcp_pid(UINT16 port) {
	PMIB_TCPTABLE_OWNER_PID tcpTable;
	ULONG size = 0;
	DWORD result = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (result != ERROR_INSUFFICIENT_BUFFER) {
		fprintf(stderr, "Failed to get buffer size for TCP table\n");
		return 0;
	}

	tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
	if (!tcpTable) {
		fprintf(stderr, "Memory allocation failed for TCP table\n");
		return 0;
	}

	result = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (result != NO_ERROR) {
		fprintf(stderr, "Failed to retrieve TCP table\n");
		free(tcpTable);
		return 0;
	}

	for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
		if (ntohs((USHORT)tcpTable->table[i].dwLocalPort) == port) {
			DWORD pid = tcpTable->table[i].dwOwningPid;
			free(tcpTable);
			return pid;
		}
	}

	free(tcpTable);
	return 0; // PID not found
}

// Function to find UDP PID
DWORD find_udp_pid(UINT16 port) {
	PMIB_UDPTABLE_OWNER_PID udpTable;
	ULONG size = 0;
	DWORD result = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	if (result != ERROR_INSUFFICIENT_BUFFER) {
		fprintf(stderr, "Failed to get buffer size for UDP table\n");
		return 0;
	}

	udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
	if (!udpTable) {
		fprintf(stderr, "Memory allocation failed for UDP table\n");
		return 0;
	}

	result = GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	if (result != NO_ERROR) {
		fprintf(stderr, "Failed to retrieve UDP table\n");
		free(udpTable);
		return 0;
	}

	for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
		if (ntohs((USHORT)udpTable->table[i].dwLocalPort) == port) {
			DWORD pid = udpTable->table[i].dwOwningPid;
			free(udpTable);
			return pid;
		}
	}

	free(udpTable);
	return 0; // PID not found
}

// Function to convert an IPv4 address (UINT32) to a string
void ip_to_string_ipv4(UINT32 ip, char *ip_str) {
    snprintf(ip_str, INET_ADDRSTRLEN, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

// Function to convert an IPv6 address (16-byte array) to a string
void ip_to_string_ipv6(const UINT8 *ip, char *ip_str) {
    const UINT16 *ip16 = (const UINT16 *)ip;  // Treat as 8 groups of 16-bit
    snprintf(ip_str, INET6_ADDRSTRLEN,
             "%x:%x:%x:%x:%x:%x:%x:%x",
             ntohs(ip16[0]), ntohs(ip16[1]), ntohs(ip16[2]), ntohs(ip16[3]),
             ntohs(ip16[4]), ntohs(ip16[5]), ntohs(ip16[6]), ntohs(ip16[7]));
}

// Function to get the source IP address, supporting both IPv4 and IPv6
void get_source_ip(const WINDIVERT_ADDRESS *addr, char *ip_str) {
    if (addr->IPv6) {  // Check the IPv6 flag
        ip_to_string_ipv6((const UINT8 *)addr->Flow.LocalAddr, ip_str);
    } else {  // Assume IPv4 if IPv6 flag is not set
        ip_to_string_ipv4(addr->Flow.LocalAddr[0], ip_str);
    }
}

// Helper function to extract the protocol and port information from the packet
int get_packet_protocol_and_port(const char *packet, unsigned int packet_len, UINT *src_port, UINT *dest_port, BYTE *protocol) {
    PWINDIVERT_IPHDR ipHdr = NULL;
    PWINDIVERT_IPV6HDR ipv6Hdr = NULL;
    PWINDIVERT_TCPHDR tcpHdr = NULL;
    PWINDIVERT_UDPHDR udpHdr = NULL;

    // Use WinDivert helper to parse the packet
    if (!WinDivertHelperParsePacket((PVOID)packet, packet_len, &ipHdr, &ipv6Hdr, protocol, NULL, NULL, &tcpHdr, &udpHdr, NULL, NULL, NULL, NULL)) {
        return 0; // Failed to parse the packet
    }

    // Check for IPv4 packet
    if (ipHdr != NULL) {
        if (*protocol == IPPROTO_TCP) {
            *src_port = ntohs(tcpHdr->SrcPort);
            *dest_port = ntohs(tcpHdr->DstPort);
        } else if (*protocol == IPPROTO_UDP) {
            *src_port = ntohs(udpHdr->SrcPort);
            *dest_port = ntohs(udpHdr->DstPort);
        }
        return 1; // Successfully extracted protocol and ports
    }

    // Check for IPv6 packet
    if (ipv6Hdr != NULL) {
        if (*protocol == IPPROTO_TCP) {
            *src_port = ntohs(tcpHdr->SrcPort);
            *dest_port = ntohs(tcpHdr->DstPort);
        } else if (*protocol == IPPROTO_UDP) {
            *src_port = ntohs(udpHdr->SrcPort);
            *dest_port = ntohs(udpHdr->DstPort);
        }
        return 1; // Successfully extracted protocol and ports
    }

    return 0; // Unrecognized packet
}

// Function to get the PID of a packet
DWORD get_packet_pid(const WINDIVERT_ADDRESS *addr, const char *packet, unsigned int packet_len) {
	UINT src_port = 0, dest_port = 0;
	BYTE protocol = 0;

	// Use this helper function to extract protocol and ports
	if (!get_packet_protocol_and_port(packet, packet_len, &src_port, &dest_port, &protocol)) {
		return 0; // Invalid or non-TCP/UDP packet
	}

	// Based on protocol, determine PID using src_port or dest_port
	DWORD pid = 0;
	if (protocol == IPPROTO_TCP) {
		pid = find_tcp_pid(dest_port); // Use dest_port for TCP
	} else if (protocol == IPPROTO_UDP) {
		pid = find_udp_pid(dest_port); // Use dest_port for UDP
	}

	return pid;  // Return the PID
}

// Per-IP and Per-Port Rate Limiting
bool check_packet_rate_limit(ProcessParams *processparams, const char *ip, UINT port, int max_packets) {
    DWORD current_time = GetTickCount64();
    ConnectionRate *rate_entry = NULL;

    EnterCriticalSection(&g_global_lock);

    HASH_FIND_STR(processparams->connection_rates, ip, rate_entry);
    if (!rate_entry) {
        rate_entry = malloc(sizeof(ConnectionRate));
        if (!rate_entry) {
            LeaveCriticalSection(&g_global_lock);
            return false;  // Memory allocation failed
        }
        strncpy(rate_entry->ip, ip, INET_ADDRSTRLEN);
        rate_entry->port = port;
        rate_entry->packet_count = 1;
        rate_entry->last_reset = current_time;
        HASH_ADD_STR(processparams->connection_rates, ip, rate_entry);
    } else {
        if (current_time - rate_entry->last_reset > 1000) {  // Reset every second
            rate_entry->packet_count = 1;
            rate_entry->last_reset = current_time;
        } else {
            rate_entry->packet_count++;
        }

        if (rate_entry->packet_count > max_packets) {
            LeaveCriticalSection(&g_global_lock);
            return false;  // Drop packet
        }
    }

    LeaveCriticalSection(&g_global_lock);
    return true;
}

// Initialize delay buffer
bool delay_buffer_init(DelayBuffer *buffer, int capacity) {
    buffer->packets = calloc(capacity, sizeof(DelayedPacket));
    if (!buffer->packets) {
        return false;
    }

    buffer->head = 0;
    buffer->tail = 0;
    buffer->count = 0;
    buffer->capacity = capacity;

    return true;
}

void delay_buffer_cleanup(DelayBuffer *buffer) {
    if (buffer) {
        free(buffer->packets);
        memset(buffer, 0, sizeof(DelayBuffer));
    }
}

// Add packet to delay buffer
bool delay_buffer_add(DelayBuffer *buffer, const char *packet, UINT packet_len, 
                     const WINDIVERT_ADDRESS *addr, LONGLONG delay_ticks) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONGLONG target_time = counter.QuadPart + delay_ticks;

    EnterCriticalSection(&g_global_lock);

    if (buffer->count >= buffer->capacity) {
        LeaveCriticalSection(&g_global_lock);
        return false; // Buffer full
    }

    DelayedPacket *delayed = &buffer->packets[buffer->tail];
    memcpy(delayed->packet, packet, packet_len);
    delayed->packet_len = packet_len;
    delayed->addr = *addr;
    delayed->timestamp = target_time;
    delayed->in_use = true;

    buffer->tail = (buffer->tail + 1) % buffer->capacity;
    buffer->count++;

    LeaveCriticalSection(&g_global_lock);

    InterlockedIncrement(&g_stats.packets_delayed);
    return true;
}

// Process delayed packets
void delay_buffer_process(DelayBuffer *buffer, HANDLE handle) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    LONGLONG current_time = counter.QuadPart;

    EnterCriticalSection(&g_global_lock);

    while (buffer->count > 0) {
        DelayedPacket *delayed = &buffer->packets[buffer->head];

        if (!delayed->in_use || delayed->timestamp > current_time) {
            break;
        }

        // Copy packet data before releasing lock
        char temp_packet[MAX_PACKET_SIZE];
        UINT temp_len = delayed->packet_len;
        WINDIVERT_ADDRESS temp_addr = delayed->addr;
        memcpy(temp_packet, delayed->packet, temp_len);

        delayed->in_use = false;
        buffer->head = (buffer->head + 1) % buffer->capacity;
        buffer->count--;

        LeaveCriticalSection(&g_global_lock);

        // Send packet outside of lock
        if (!WinDivertSend(handle, temp_packet, temp_len, NULL, &temp_addr)) {
            // Log error but continue
        }

        EnterCriticalSection(&g_global_lock); // Re-enter for next iteration
    }

    LeaveCriticalSection(&g_global_lock);
}

// Validate packet structure and content
bool validate_packet(const char *packet, UINT packet_len) {
    if (!packet || packet_len == 0 || packet_len > MAX_PACKET_SIZE) {
        InterlockedIncrement(&g_stats.invalid_packets);
        return false;
    }

    PWINDIVERT_IPHDR ipHdr = NULL;
    PWINDIVERT_IPV6HDR ipv6Hdr = NULL;
    PWINDIVERT_TCPHDR tcpHdr = NULL;
    PWINDIVERT_UDPHDR udpHdr = NULL;
    BYTE protocol = 0;

    // Use WinDivert to parse and validate packet structure
    if (!WinDivertHelperParsePacket((PVOID)packet, packet_len, &ipHdr, &ipv6Hdr, 
                                   &protocol, NULL, NULL, &tcpHdr, &udpHdr, NULL, NULL, NULL, NULL)) {
        InterlockedIncrement(&g_stats.invalid_packets);
        return false;
    }

    // Validate IPv4 header
    if (ipHdr) {
        if (ipHdr->Version != 4) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
        
        UINT16 total_length = ntohs(ipHdr->Length);
        if (total_length > packet_len || total_length < (ipHdr->HdrLength * 4)) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
        
        // Basic header length validation
        if (ipHdr->HdrLength < 5 || ipHdr->HdrLength > 15) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
    }
    
    // Validate IPv6 header
    if (ipv6Hdr) {
        if ((ipv6Hdr->Version) != 6) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
        
        UINT16 payload_length = ntohs(ipv6Hdr->Length);
        if (payload_length + 40 > packet_len) { // 40 is IPv6 header size
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
    }
    
    // Validate TCP header
    if (tcpHdr && (protocol == IPPROTO_TCP)) {
        if (tcpHdr->HdrLength < 5 || tcpHdr->HdrLength > 15) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
        
        // Validate port numbers (0 is invalid for TCP)
        if (tcpHdr->SrcPort == 0 || tcpHdr->DstPort == 0) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
    }
    
    // Validate UDP header
    if (udpHdr && (protocol == IPPROTO_UDP)) {
        UINT16 udp_length = ntohs(udpHdr->Length);
        if (udp_length < 8) { // Minimum UDP header size
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
        
        // Check if UDP length makes sense within the packet
        UINT16 ip_header_size = ipHdr ? (ipHdr->HdrLength * 4) : (ipv6Hdr ? 40 : 0);
        if (ip_header_size + udp_length > packet_len) {
            InterlockedIncrement(&g_stats.invalid_packets);
            return false;
        }
    }

    return true;
}


// Cleanup function to free all memory associated with rate limits
void cleanup_rate_limits(ProcessParams *processparams) {
    ConnectionRate *current_rate, *tmp;
    DWORD current_time = GetTickCount64();
    int cleaned = 0;

    EnterCriticalSection(&g_global_lock);

    HASH_ITER(hh, processparams->connection_rates, current_rate, tmp) {
        // Clean up entries older than 30 seconds
        if (current_time - current_rate->last_reset > 30000) {
            HASH_DEL(processparams->connection_rates, current_rate);
            free(current_rate);
            cleaned++;
        }
    }

    LeaveCriticalSection(&g_global_lock);

    // Optional: log cleanup activity
    if (cleaned > 0) {
        printf("Cleaned up %d stale connection entries\n", cleaned);
    }
}

// Function to add a PID to the hash map (avoids duplicates)
void add_pid_to_map(PIDEntry **pid_map, int pid) {
    PIDEntry *entry;
    HASH_FIND_INT(*pid_map, &pid, entry);  // Check if already exists
    if (entry) return;  // Avoid duplicate entries

    entry = malloc(sizeof(PIDEntry));
    if (!entry) {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(EXIT_FAILURE);
    }
    entry->pid = pid;
    HASH_ADD_INT(*pid_map, pid, entry);
}

// Function to check if a PID exists in the hash map
int is_pid_in_map(PIDEntry *pid_map, unsigned int pid) {
	PIDEntry *entry;
	HASH_FIND_INT(pid_map, &pid, entry);
	return entry != NULL;
}

// Function to free the hash map
void free_pid_map(PIDEntry *pid_map) {
    if (!pid_map) return;  // Prevent NULL pointer dereference

    PIDEntry *entry, *tmp;
    HASH_ITER(hh, pid_map, entry, tmp) {
        HASH_DEL(pid_map, entry);
        free(entry);
    }
}

// Get all PIDs matching the process name
int get_pids_from_name(const char *process_name, int **pid_list) {
    DWORD processes[1024], needed;
    if (!EnumProcesses(processes, sizeof(processes), &needed)) {
        fprintf(stderr, "Failed to enumerate processes.\n");
        return 0;
    }

    int pid_count = 0;
    int *pids = malloc(sizeof(int) * (needed / sizeof(DWORD)));

    if (!pids) {  // Check for malloc failure
        fprintf(stderr, "Failed to allocate memory for PID list.\n");
        return 0;
    }

    for (unsigned int i = 0; i < needed / sizeof(DWORD); i++) {
        char name[MAX_PATH] = {0};
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess) {
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseNameA(hProcess, hMod, name, sizeof(name));
                if (_stricmp(name, process_name) == 0) { // Case-insensitive comparison
                    pids[pid_count++] = processes[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

	// If no PIDs were found, free the allocated memory and return 0
	if (pid_count == 0) {
		free(pids);
		*pid_list = NULL;
		return 0;
	}

    // Reallocate to fit the actual PID count
    int *new_pids = realloc(pids, pid_count * sizeof(int));
    if (new_pids) {
        *pid_list = new_pids;  // Assign the resized array to the output
    } else {
        // If realloc fails, free the original memory and return 0
        free(pids);
        *pid_list = NULL;  // Ensure the output is NULL in case of failure
        return 0;
    }

    return pid_count; // Return the number of PIDs found
}

// Parse a comma-separated string of process names into an array
char **parse_processes(char *input, int *count) {
    int capacity = 16;
    char **processes = malloc(capacity * sizeof(char *));
    if (processes == NULL) {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(EXIT_FAILURE);
    }
    *count = 0;

    char *token;
    char *context = NULL;
    token = strtok_s(input, ",", &context);
    
    while (token != NULL) {
        if (*count >= capacity) {
            capacity *= 2;
            char **new_processes = realloc(processes, capacity * sizeof(char *));
            if (new_processes == NULL) {
                fprintf(stderr, "Memory allocation failed during resizing!\n");
                // Free all previously allocated strings
                for (int i = 0; i < *count; i++) {
                    free(processes[i]);
                }
                free(processes);
                exit(EXIT_FAILURE);
            }
            processes = new_processes;
        }

        // Trim leading spaces
        while (*token == ' ') token++;
        
        // Trim trailing spaces
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') {
            *end = '\0';
            end--;
        }

        processes[*count] = strdup(token);
        if (processes[*count] == NULL) {
            fprintf(stderr, "Memory allocation failed for process name!\n");
            // Free all previously allocated strings
            for (int i = 0; i < *count; i++) {
                free(processes[i]);
            }
            free(processes);
            exit(EXIT_FAILURE);
        }
        (*count)++;
        token = strtok_s(NULL, ",", &context);
    }

    return processes;
}

// Function to parse the process update interval (packets or time)
int parse_process_update_interval(const char *input, ProcessParams *processparams) {
	size_t len = strlen(input);

	// Handle the special case where input is "0"
	if (strcmp(input, "0") == 0) {
		processparams->packet_threshold = 0;  // Disable packet-based updates
		processparams->time_threshold_ms = 0; // Disable time-based updates
		return 0; // Success
	}

	if (len < 2 || len >= MAX_INTERVAL_STR_LEN) {
		fprintf(stderr, "Error: Invalid format for --process-update-interval. Use '<value>p', '<value>t', or '0'.\n");
		return 1;
	}

	char value_str[MAX_INTERVAL_STR_LEN];
	strncpy(value_str, input, len - 1); // Extract the numeric part
	value_str[len - 1] = '\0';		    // Null-terminate

	if (!isdigit(value_str[0])) {
		fprintf(stderr, "Error: Invalid numeric value for --process-update-interval.\n");
		return 1;
	}

	unsigned int value = atoi(value_str);

	char unit = tolower(input[len - 1]); // Last character is the unit
	if (unit == 'p') {
		processparams->packet_threshold = value;
		processparams->time_threshold_ms = 0; // Disable time-based updates
	} else if (unit == 't') {
		processparams->time_threshold_ms = value;
		processparams->packet_threshold = 0; // Disable packet-based updates
	} else {
		fprintf(stderr, "Error: Unknown unit '%c' for --process-update-interval. Use 'p' for packets, 't' for time, or '0'.\n", unit);
		return 1;
	}

	return 0; // Success
}

// Function to get the name of the process from its PID
/*
int get_process_name_from_pid(DWORD pid, char *process_name, size_t name_size) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess) {
		return 0; // Process could not be opened
	}

	HMODULE hMod;
	DWORD cbNeeded;
	if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
		GetModuleBaseNameA(hProcess, hMod, process_name, name_size);
	} else {
		CloseHandle(hProcess);
		return 0;
	}

	CloseHandle(hProcess);
	return 1;
}
*/

// Function to check if a PID exists
bool is_process_alive(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
            CloseHandle(hProcess);
            return true;
        }
        CloseHandle(hProcess);
    }
    return false;
}

// Function to update the PIDs (remove stale PIDs and add new ones)
void update_pid_map(ProcessParams *processparams) {
	if (!processparams->process_list) return;

	clock_t current_time = clock();
	double elapsed_time_ms = ((double)(current_time - processparams->last_update_time) / CLOCKS_PER_SEC) * 1000.0;
	
    // Enforce minimum 5-second interval regardless of packet count
    bool time_based_update = (processparams->time_threshold_ms > 0 && elapsed_time_ms >= processparams->time_threshold_ms);
    bool packet_based_update = (processparams->packet_threshold > 0 && ++processparams->packet_count >= processparams->packet_threshold);
	
    // Add minimum 5-second cooldown
    static clock_t last_actual_update = 0;
    double since_last_update = ((double)(current_time - last_actual_update) / CLOCKS_PER_SEC) * 1000.0;

    if ((time_based_update || packet_based_update) && since_last_update >= 5000) {
        last_actual_update = current_time;
        processparams->packet_count = 0;
        processparams->last_update_time = current_time;
        processparams->needs_update = true;
    }

	if (!processparams->needs_update) return;
	processparams->needs_update = false;

	// Remove stale PIDs (only dead ones)
    PIDEntry **to_remove = malloc(HASH_COUNT(processparams->pid_map) * sizeof(PIDEntry*));
    int remove_count = 0;

    PIDEntry *entry, *tmp;
    HASH_ITER(hh, processparams->pid_map, entry, tmp) {
        if (!is_process_alive(entry->pid)) {
            if (remove_count < 1024) {
                to_remove[remove_count++] = entry;
            }
        }
    }

    // Remove dead PIDs
    for (int i = 0; i < remove_count; i++) {
        printf("Stale PID %u was removed.\n", to_remove[i]->pid);
        HASH_DEL(processparams->pid_map, to_remove[i]);
        free(to_remove[i]);
    }

	// Add new PIDs
	int process_count = 0;
	char *process_list_copy = strdup(processparams->process_list);
	if (process_list_copy == NULL) {
		fprintf(stderr, "Memory allocation failed!\n");
		exit(EXIT_FAILURE);
	}
	char **processes = parse_processes(process_list_copy, &process_count);
	free(process_list_copy);  // Free the copy after parsing

	// Resolve PIDs and add to hash map
	for (int i = 0; i < process_count; i++) {
		//printf("Debug: Processing: '%s'\n", processes[i]);

		int *pid_list = NULL;
		int pid_count = get_pids_from_name(processes[i], &pid_list);

		for (int j = 0; j < pid_count; j++) {
			int pid = pid_list[j];

            HASH_FIND_INT(processparams->pid_map, &pid, entry);
            if (entry) {
                //printf("PID %d already exists, skipping.\n", pid);
                continue;
            }

            // Verify process existence before adding
            if (is_process_alive(pid)) {
                add_pid_to_map(&processparams->pid_map, pid);
                printf("Added new PID '%d' for process '%s' to the hash map.\n", pid, processes[i]);
            }
		}
		if (pid_list) free(pid_list);
		free(processes[i]);
	}
	free(to_remove);
	free(processes);
}

// Stops the WinDivert service
void stop_windivert() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        fprintf(stderr, "OpenSCManager failed (%lu)\n", GetLastError());
        return; // FIXED: Return instead of falling through
    }

    hService = OpenService(hSCManager, TEXT("WinDivert"), SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (hService == NULL) {
        fprintf(stderr, "OpenService failed (%lu)\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, 
                           (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            printf("The WinDivert service is running, stopping it...\n");
            if (ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status)) {
                printf("The WinDivert service stopped successfully.\n");
            } else {
                fprintf(stderr, "Failed to stop the WinDivert service: (%lu)\n", GetLastError());
            }
        } else {
            printf("WinDivert service is not running.\n");
        }
    } else {
        fprintf(stderr, "QueryServiceStatusEx failed (%lu)\n", GetLastError());
    }

    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);
}

// Check if the process is running with admin privileges
int is_admin() {
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = NULL;

    // Allocate and initialize SID for the Administrators group
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        // Check if the current token is a member of the Administrators group
        if (!CheckTokenMembership(NULL, admin_group, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(admin_group);
    }
    return is_admin;
}

// Update and print statistics
void print_statistics() {
	if (!enable_statistics) return;

    // Take atomic snapshots of all statistics
    LONG processed = InterlockedExchangeAdd(&g_stats.packets_processed, 0);
    LONG dropped_rate = InterlockedExchangeAdd(&g_stats.packets_dropped_rate_limit, 0);
    LONG dropped_loss = InterlockedExchangeAdd(&g_stats.packets_dropped_loss, 0);
    LONG delayed = InterlockedExchangeAdd(&g_stats.packets_delayed, 0);
    LONG bytes = InterlockedExchangeAdd(&g_stats.bytes_processed, 0);
    LONG invalid = InterlockedExchangeAdd(&g_stats.invalid_packets, 0);

    printf("\n=== Bandwidth Shaper Statistics ===\n");
    printf("Packets processed: %ld\n", processed);
    printf("Bytes processed: %ld (%.2f MB)\n", bytes, bytes / 1048576.0);
    printf("Packets dropped (rate limit): %ld\n", dropped_rate);
    printf("Packets dropped (loss simulation): %ld\n", dropped_loss);
    printf("Packets delayed: %ld\n", delayed);
    printf("Invalid packets: %ld\n", invalid);

    if (processed > 0) {
        printf("Drop rate: %.2f%%\n", ((double)(dropped_rate + dropped_loss) / processed) * 100.0);
    }
    printf("===================================\n\n");
}

void update_statistics() {
	if (!enable_statistics) return;

    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    
    if ((counter.QuadPart - g_stats.last_stats_update) * 1000.0 / g_perf_frequency >= STATS_UPDATE_INTERVAL) {
        print_statistics();
        g_stats.last_stats_update = counter.QuadPart;
    }
}

// Handler for control events (like Ctrl+C)
BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            printf("Emergency shutdown initiated...\n");
            quit_program = true;
            // Give main loop time to clean up properly
            Sleep(1000);
            return TRUE;
        default:
            return FALSE;
    }
}

// Function to get the program's name without the .exe extension
const char *get_program_name(const char *path) {
    if (!path) return "unknown";
    
    const char *name = strrchr(path, '\\'); // Look for last backslash (Windows path)
    if (!name) name = strrchr(path, '/');   // Look for last slash (POSIX path)
    if (name) name++;  // Skip the slash
    else name = path; // No slashes, use the whole path

    // Check for .exe extension
    size_t name_len = strlen(name);
    const char *ext = ".exe";
    size_t ext_len = 4;
    
    if (name_len >= ext_len && 
        _stricmp(name + name_len - ext_len, ext) == 0) {
        
        static char buffer[MAX_PATH];
        size_t copy_len = name_len - ext_len;
        
        // Bounds check
        if (copy_len >= MAX_PATH) {
            copy_len = MAX_PATH - 1;
        }
        
        strncpy(buffer, name, copy_len);
        buffer[copy_len] = '\0';
        return buffer;
    }

    return name;
}

// Function to display help message
void print_help(const char *program_path) {
    const char *program_name = get_program_name(program_path);
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -P, --priority <NUM>                         Set WinDivert priority (default: 0, range: %d to %d)\n", WINDIVERT_PRIORITY_LOWEST, WINDIVERT_PRIORITY_HIGHEST);
    printf("  -p, --process <process1,process2,...>        List of processes to monitor (comma-separated)\n");
    printf("  -i, --process-update-interval <NUM>[p|t]     Packet count or time in ms needed for process updates (0 = no update)\n");
    printf("  -d, --download <RATE>[b|Kb|KB|Mb|MB|Gb|GB]   Download speed limit per second (default unit: KB)\n");
    printf("  -u, --upload <RATE>[b|Kb|KB|Mb|MB|Gb|GB]     Upload speed limit per second (default unit: KB)\n");
    printf("  -D, --download-buffer <bytes>                Maximum download buffer size in bytes (default: 150000)\n");
    printf("  -U, --upload-buffer <bytes>                  Maximum upload buffer size in bytes (default: 150000)\n");
    printf("  -t, --tcp-limit <NUM>                        Maximum limit of active TCP connections (default: 0 = unlimited)\n");
    printf("  -r, --udp-limit <NUM>                        Maximum limit of active UDP connections (default: 0 = unlimited)\n");
    printf("  -L, --latency <ms>                           Set the latency in milliseconds (default: 0 = no latency)\n");
    printf("  -m, --packet-loss <float>                    Set the packet loss in percentage (default: 0.00 = no loss)\n");
    printf("  -n, --nic <interface_index>                  Throttle traffic for the specified network interfaces (comma-separated)\n");
    printf("            <NIC_INDEX:DL_RATE:UL_RATE>        For different global download and upload rate limits per NIC\n");
    printf("  -l, --list-nics                              List all available network interfaces\n");
    printf("  -s, --statistics                             Enable statistics output (default: disabled)\n");
    printf("  -h, --help                                   Display this help message and exit\n");
}

int main(int argc, char *argv[]) {
	// Seed random generator for packet loss
	srand((unsigned int)time(NULL));

	// Set up the control handler
	if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)console_ctrl_handler, TRUE)) {
		fprintf(stderr, "Failed to set control handler!\n");
		return 1;
	}

	// Initialize performance counter frequency
	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);
	g_perf_frequency = (double)freq.QuadPart;
	
	// Initialize delay buffer
	if (!delay_buffer_init(&g_delay_buffer, DELAY_BUFFER_SIZE)) {
		fprintf(stderr, "Failed to initialize delay buffer.\n");
		return EXIT_FAILURE;
	}

	// Initialize statistics
	g_stats.last_stats_update = get_time_ticks();

	// Track if we modified the packet
	bool packet_modified = false;
	
	// To process delayed packets less often
	static int delay_process_counter = 0;

    // Default values for command-line parameters
    int priority = 0;
    double download_rate = 0;
    double upload_rate = 0;
    unsigned int download_buffer_size = DEFAULT_DL_BUFFER;
    unsigned int upload_buffer_size = DEFAULT_UL_BUFFER;
    unsigned int max_tcp_connections = 0;  // unlimited
    unsigned int max_udp_packets_per_second = 0;  // unlimited
    unsigned int latency_ms = 0;  // no latency
    float packet_loss = 0.00f;  // no packet loss

	// Initialize throttling parameters
	ThrottlingParams params = {
		.nic_indices = NULL,
		.nic_count = 0,
		.download_limits = 0,
		.upload_limits = 0
	};

	// Declare a process instance
	ProcessParams processparams = {
		.pid_map = NULL,
		.process_list = NULL,
		.packet_threshold = 0,
		.time_threshold_ms = 0,
		.packet_count = 0,
		.last_update_time = clock(),
		.needs_update = false
	};

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // Display help if no arguments are provided
    if (argc == 1) {
        print_help(argv[0]);
        return EXIT_SUCCESS;
    }

    // Manual argument parsing
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--download") == 0 || strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
            download_rate = parse_rate_with_units(argv[++i]);
        } else if ((strcmp(argv[i], "--upload") == 0 || strcmp(argv[i], "-u") == 0) && i + 1 < argc) {
            upload_rate = parse_rate_with_units(argv[++i]);
		} else if ((strcmp(argv[i], "--download-buffer") == 0 || strcmp(argv[i], "-D") == 0) && i + 1 < argc) {
			download_buffer_size = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--upload-buffer") == 0 || strcmp(argv[i], "-U") == 0) && i + 1 < argc) {
			upload_buffer_size = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--tcp-limit") == 0 || strcmp(argv[i], "-t") == 0) && i + 1 < argc) {
			max_tcp_connections = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--udp-limit") == 0 || strcmp(argv[i], "-r") == 0) && i + 1 < argc) {
			max_udp_packets_per_second = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--process") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) {
			processparams.process_list = argv[++i];
		} else if ((strcmp(argv[i], "--process-update-interval") == 0 || strcmp(argv[i], "-i") == 0) && i + 1 < argc) {
			if (parse_process_update_interval(argv[++i], &processparams) != 0) {
				print_help(argv[0]);
				return EXIT_FAILURE;
			}
		} else if ((strcmp(argv[i], "--priority") == 0 || strcmp(argv[i], "-P") == 0) && i + 1 < argc) {
			priority = atoi(argv[++i]);
			if (priority < WINDIVERT_PRIORITY_LOWEST || priority > WINDIVERT_PRIORITY_HIGHEST) {
				fprintf(stderr, "Error: Priority must be between %d and %d.\n", WINDIVERT_PRIORITY_LOWEST, WINDIVERT_PRIORITY_HIGHEST);
				return EXIT_FAILURE;
			}
		} else if ((strcmp(argv[i], "--latency") == 0 || strcmp(argv[i], "-L") == 0) && i + 1 < argc) {
			latency_ms = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--packet-loss") == 0 || strcmp(argv[i], "-m") == 0) && i + 1 < argc) {
			packet_loss = atof(argv[++i]);
        } else if ((strcmp(argv[i], "--nic") == 0 || strcmp(argv[i], "-n") == 0) && i + 1 < argc) {
            params.nic_indices = parse_nic_indices(argv[++i], &params);
		} else if ((strcmp(argv[i], "--list-nics") == 0 || strcmp(argv[i], "-l") == 0)) {
            list_network_interfaces();
            WSACleanup();
            return EXIT_SUCCESS;
		} else if ((strcmp(argv[i], "--statistics") == 0 || strcmp(argv[i], "-s") == 0)) {
			enable_statistics = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "Unknown or invalid argument: %s\n", argv[i]);
            print_help(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Validate required parameters	
	if (download_rate < 0 || upload_rate < 0) {
		fprintf(stderr, "Error: Download/Upload speed limit must not be negative.\n");
		return EXIT_FAILURE;
	}
	
	if (download_buffer_size < 0 || upload_buffer_size < 0) {
		fprintf(stderr, "Error: Download/Upload buffer size must not be negative.\n");
		return EXIT_FAILURE;
	}

	if (max_tcp_connections < 0) {
		fprintf(stderr, "Error: The max TCP connection number cannot be negative.\n");
		return EXIT_FAILURE;
	}

	if (max_udp_packets_per_second < 0) {
		fprintf(stderr, "Error: The max UDP connection number cannot be negative.\n");
		return EXIT_FAILURE;
	}

	if (packet_loss < 0.00f || packet_loss > 100.00f) {
		fprintf(stderr, "Error: Packet loss percentage must be between 0 and 100.\n");
		return EXIT_FAILURE;
	}

	if (latency_ms < 0) {
		fprintf(stderr, "Error: Latency must not be negative.\n");
		return EXIT_FAILURE;
	}
	
	if (params.nic_count == 0) {
		fprintf(stderr, "Error: You must specify at least one NIC index with --nic.\n");
		return EXIT_FAILURE;
	}

	if (!is_admin()) {
		fprintf(stderr, "Error: Not running as admin, please use an elevated command prompt - WinDivert cannot manage network operations without it.\n");
		return EXIT_FAILURE;
	}

	// Print info for the user
	printf("Priority: %d", priority);
	if (priority == 30000) {
		printf(" (highest)\n");
	} else if (priority <= 29999 && priority > 15000) {
		printf(" (high)\n");
	} else if (priority >= 0 && priority <= 14999) {
		printf(" (normal)\n");
	} else if (priority < 0 && priority >= -15000) {
		printf(" (low)\n");
	} else if (priority < -15000 && priority >= -30000) {
		printf(" (lowest)\n");
	}

	printf("Bandwidth throttled on NIC index: ");
	for (int i = 0; i < params.nic_count; i++) {
		if (i > 0) {
			printf(", "); // Add a comma and space between indices
		}
		printf("%d", params.nic_indices[i]);
	}
	printf("\n");

	if (download_rate > 0) print_rate_with_units("Download limit", download_rate);
	if (upload_rate > 0) print_rate_with_units("Upload limit", upload_rate);
	if (download_rate > 0) printf("Max download buffer size: %d bytes\n", download_buffer_size);
	if (upload_rate > 0) printf("Max upload buffer size: %d bytes\n", upload_buffer_size);
	if (max_tcp_connections > 0) printf("Max TCP connections: %d\n", max_tcp_connections);
	if (max_udp_packets_per_second > 0) printf("Max UDP connections: %d\n", max_udp_packets_per_second);
	if (latency_ms > 0) printf("Simulated latency: %d (ms)\n", latency_ms);
	if (packet_loss > 0.00f && packet_loss <= 100.00f) printf("Simulated packet loss: %f%%\n", packet_loss);
	printf("\nPress 'q' or 'Ctrl+C' to quit the bandwidth throttler.\n\n");

	// One-time only: make a process list if processes exist
	if (processparams.process_list != NULL) {
		// Parse process list and resolve to PIDs
		int process_count = 0;
		char *process_list_copy = strdup(processparams.process_list);
		if (process_list_copy == NULL) {
			fprintf(stderr, "Memory allocation failed!\n");
			exit(EXIT_FAILURE);
		}
		char **processes = parse_processes(process_list_copy, &process_count);
		free(process_list_copy);  // Free the copy after parsing

		// Resolve PIDs and add to hash map
		for (int i = 0; i < process_count; i++) {
			//printf("Debug: Processing: '%s'\n", processes[i]);

			int *pid_list = NULL;
			int pid_count = get_pids_from_name(processes[i], &pid_list);

			if (pid_count > 0) {
				for (int j = 0; j < pid_count; j++) {
					add_pid_to_map(&processparams.pid_map, pid_list[j]);
					printf("Added PID '%d' for process '%s' to the hash map.\n", pid_list[j], processes[i]);
				}
			} else {
				fprintf(stderr, "Warning: Could not resolve PIDs for process '%s'.\n", processes[i]);
			}
			if (pid_list) free(pid_list);
			free(processes[i]);
		}
		free(processes);
	} else {
		printf("No processes were specified. Global bandwidth throttling will apply.\n");
	}

	// Set token bucket and handle to zero
    TokenBucket *download_buckets = NULL;
    TokenBucket *upload_buckets = NULL;
    HANDLE handle = INVALID_HANDLE_VALUE;
    bool global_critical_section_initialized = false;

    // Initialize critical section with error checking
    if (!InitializeCriticalSectionAndSpinCount(&g_global_lock, 4000)) {
        fprintf(stderr, "Failed to initialize global critical section.\n");
        goto cleanup;
    }
    global_critical_section_initialized = true;

    // Allocate token buckets
    download_buckets = malloc(params.nic_count * sizeof(TokenBucket));
    upload_buckets = malloc(params.nic_count * sizeof(TokenBucket));
    if (!download_buckets || !upload_buckets) {
        fprintf(stderr, "Memory allocation failed for token buckets.\n");
        goto cleanup;
    }

	// Track initialization progress
	int initialized_download_buckets = 0;
	int initialized_upload_buckets = 0;

	for (int i = 0; i < params.nic_count; i++) {
		// If it is not set, use the global download and upload rate instead
		if (params.download_limits[i] == 0) {
			params.download_limits[i] = download_rate;
		}
		if (params.upload_limits[i] == 0) {
			params.upload_limits[i] = upload_rate;
		}

		// Initialize download bucket only if download limit is nonzero
		if (params.download_limits[i] > 0) {
			if (!token_bucket_init(&download_buckets[i], params.download_limits[i], download_buffer_size)) {
				fprintf(stderr, "Failed to initialize download bucket %d.\n", i);
				goto cleanup;
			}
			initialized_download_buckets++;
		}

		// Initialize upload bucket only if upload limit is nonzero
		if (params.upload_limits[i] > 0) {
			if (!token_bucket_init(&upload_buckets[i], params.upload_limits[i], upload_buffer_size)) {
				fprintf(stderr, "Failed to initialize upload bucket %d.\n", i);
				goto cleanup;
			}
			initialized_upload_buckets++;
		}
	}

	// Set up WinDivert
	char packet[MAX_PACKET_SIZE];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;

	// Open WinDivert handle for capturing traffic
	handle = WinDivertOpen("ip or tcp or udp", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		switch (error) {
			case 2:	   fprintf(stderr, "Either one of the WinDivert32.sys or WinDivert64.sys files were not found.\n"); break;
			case 5:	   fprintf(stderr, "Permission issue: Administrator rights are required.\n"); break;
			case 87:   fprintf(stderr, "There is an invalid parameter regarding the packet filter string, layer, priority, or flags.\n"); break;
			case 577:  fprintf(stderr, "The WinDivert32.sys or WinDivert64.sys driver file does not have a valid digital signature.\n"); break;
			case 1058: fprintf(stderr, "There is a previous WinDivert instance hanging. Quit gracefully now and restart.\n"); break;
			case 1275: fprintf(stderr, "The driver is blocked! Make sure not to load the 32-bit WinDivert.sys driver on a 64-bit system (or vice versa).\n"); break;
			case 1753: fprintf(stderr, "The Base Filtering Engine (BFE) service is not running! Start it for WinDivert to be able to run!\n"); break;
			default:   fprintf(stderr, "Error opening WinDivert: %lu\n", error);
		}
		//fprintf(stderr, "Error opening WinDivert handle: %lu\n", GetLastError());
		goto cleanup;
	}

	// Create event handle for timeout for WinDivertRecv call
	HANDLE recv_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!recv_event) {
		fprintf(stderr, "Failed to create event for timeout\n");
		goto cleanup;
	}

    // Main loop for processing packets
    while (!quit_program) {  // Check quit_program at loop start
		// Read a packet from the network
		DWORD recv_len;
		OVERLAPPED overlapped = {0};
		overlapped.hEvent = recv_event;
		if (!WinDivertRecvEx(handle, packet, sizeof(packet), &recv_len, 0, &addr, NULL, &overlapped)) {
			DWORD error = GetLastError();
			if (error == ERROR_IO_PENDING) {
				// Wait with timeout (100ms)
				DWORD wait_result = WaitForSingleObject(overlapped.hEvent, 100);
				if (wait_result == WAIT_TIMEOUT) {
					CancelIo(handle);
					continue; // Check quit_program flag
				} else if (wait_result == WAIT_OBJECT_0) {
					if (!GetOverlappedResult(handle, &overlapped, &recv_len, FALSE)) {
						DWORD get_error = GetLastError();
						if (get_error == ERROR_NO_MORE_ITEMS || get_error == ERROR_HANDLE_EOF) {
							break;
						}
						continue;
					}
					packet_len = recv_len;
				} else {
					continue; // Error case
				}
			} else if (error == ERROR_NO_MORE_ITEMS || error == ERROR_HANDLE_EOF) {
				break;
			} else {
				if (quit_program) break;
				fprintf(stderr, "Failed to receive packet: %lu\n", error);
				continue;
			}
		} else {
			packet_len = recv_len;
		}

		// Early exit check
		if(quit_program) break;

		// Update statistics
		InterlockedIncrement(&g_stats.packets_processed);
		InterlockedExchangeAdd(&g_stats.bytes_processed, packet_len);
		update_statistics();

		// Process delayed packets first
		if (++delay_process_counter >= 10) { // Process every 10 packets instead of every packet
			delay_process_counter = 0;
			delay_buffer_process(&g_delay_buffer, handle);
		}

		// Validate packet before processing
		if (!validate_packet(packet, packet_len)) {
			continue; // Skip invalid packets
		}

		// Check for 'Q' key
		static int key_check_counter = 0;
		if (++key_check_counter >= 2) { // Check every 2 packets
			key_check_counter = 0;
			HWND hwnd = GetConsoleWindow();
			if (GetForegroundWindow() == hwnd && (GetAsyncKeyState('Q') & 0x8000)) {
				printf("Exiting bandwidth throttler...\n");
				break;
			}
		}

		// Get the NIC index
		unsigned int if_idx = addr.Network.IfIdx;

		// Find the matching NIC bucket index
		int nic_index = -1;
		for (int i = 0; i < params.nic_count; i++) {
			if (params.nic_indices[i] == if_idx) {
				nic_index = i;
				break;
			}
		}

		// If the NIC is not managed, skip processing
		if (nic_index == -1) {
			continue;
		}

		// Check if packet matches a monitored process
		if (processparams.process_list != NULL) {
			update_pid_map(&processparams);
			DWORD pid = get_packet_pid(&addr, packet, packet_len);
			if (processparams.pid_map != NULL && !is_pid_in_map(processparams.pid_map, pid)) {
				//printf("Debug: PID %ld is not monitored, continuing...\n", pid);
				reinject_packet(handle, packet, packet_len, &addr);
				continue;
			}
		}

		// Apply TCP connection limit (for TCP packets)
		if (max_tcp_connections > 0) {
			UINT src_port = 0, dest_port = 0;
			BYTE protocol = 0;
			char ip_address[INET_ADDRSTRLEN];  // To hold the source IP address

			// Retrieve protocol and ports from the packet
			if (get_packet_protocol_and_port(packet, packet_len, &src_port, &dest_port, &protocol)) {
				if (protocol == IPPROTO_TCP) {
					// Get source IP address
					get_source_ip(&addr, ip_address);  // Get the source IP

					if (!check_packet_rate_limit(&processparams, ip_address, src_port, max_tcp_connections)) {
						//printf("Debug: Dropped TCP packet, IP: %s, src port: %d, dest port: %d\n", ip_address, src_port, dest_port);
						continue;
					}
				}
			}
		}

		// Apply UDP packet limit (for UDP packets)
		if (max_udp_packets_per_second > 0) {
			UINT src_port = 0, dest_port = 0;
			BYTE protocol = 0;
			char ip_address[INET_ADDRSTRLEN];  // To hold the source IP address

			// Retrieve protocol and ports from the packet
			if (get_packet_protocol_and_port(packet, packet_len, &src_port, &dest_port, &protocol)) {
				if (protocol == IPPROTO_UDP) {
					// Get source IP address
					get_source_ip(&addr, ip_address);  // Get the source IP

					if (!check_packet_rate_limit(&processparams, ip_address, src_port, max_udp_packets_per_second)) {
						//printf("Debug: Dropped UDP packet, IP: %s, src port: %d, dest port: %d\n", ip_address, src_port, dest_port);
						continue;
					}
				}
			}
		}

		// Select the correct token bucket
		TokenBucket *bucket = NULL;
		if (addr.Outbound) {
			bucket = (params.upload_limits[nic_index] > 0) ? &upload_buckets[nic_index] : NULL;
		} else {
			bucket = (params.download_limits[nic_index] > 0) ? &download_buckets[nic_index] : NULL;
		}

		if (bucket != NULL) {
			if (!token_bucket_consume(bucket, packet_len)) {
				// Not enough tokens, so drop the packet (rate limiting in action)
				//printf("Packet dropped due to rate limiting: %u bytes\n", packet_len);
				InterlockedIncrement(&g_stats.packets_dropped_rate_limit);
				continue;
			}
		}

		// Simulate packet loss
		if (should_drop_packet(handle, packet, packet_len, addr, packet_loss)) {
			continue;
		}

		// Simulate latency using non-blocking delay
		if (latency_ms > 0) {
			//Sleep(latency_ms);  // Delay in milliseconds

			// Calculate delay in ticks
			LONGLONG delay_ticks = (LONGLONG)(latency_ms * g_perf_frequency / 1000.0);
			
			if (!delay_buffer_add(&g_delay_buffer, packet, packet_len, &addr, delay_ticks)) {
				// Buffer full, process immediately
				if (packet_modified) {
					if (!WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0)) {
						fprintf(stderr, "Error: Checksum calculation failed. Skipping packet...\n");
						continue;
					}
				}
				reinject_packet(handle, packet, packet_len, &addr);
			}
			continue; // Don't reinject immediately if delayed
		}

		// Ensure packet checksums are valid
		if (packet_modified) {
			if (!WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0)) {
				fprintf(stderr, "Error: Checksum calculation failed. Skipping modified packet...\n");
				continue;
			}
		}

		reinject_packet(handle, packet, packet_len, &addr);
	}

	goto cleanup;

	cleanup:
		// Process any remaining delayed packets before cleanup
		if (handle != INVALID_HANDLE_VALUE) {
			delay_buffer_process(&g_delay_buffer, handle);
			delay_buffer_cleanup(&g_delay_buffer); // Clean up delay buffer after processing remaining packets
		}

		// Print final statistics before cleaning up data structures
		print_statistics();

		if (recv_event != NULL) {
			CloseHandle(recv_event);
			recv_event = NULL;  // Prevent double-close
		}

		if (handle != INVALID_HANDLE_VALUE) {
			WinDivertClose(handle);
		}

		if (global_critical_section_initialized) {
			DeleteCriticalSection(&g_global_lock); // Clean up the single global lock
		}

		// Clean up only successfully initialized buckets
		if (download_buckets) {
			free(download_buckets);
		}

		if (upload_buckets) {
			free(upload_buckets);
		}

		free(params.nic_indices);
		free(params.download_limits);
		free(params.upload_limits);
		cleanup_rate_limits(&processparams);

		if (processparams.process_list != NULL) {
			free_pid_map(processparams.pid_map);
		}

		WSACleanup();
		stop_windivert();
		return EXIT_SUCCESS;
}
