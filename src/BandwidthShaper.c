/*
 * BandwidthShaper.c
 * Copyright (c) 2025 Thomas K.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

// Define statements
#define WIN32_LEAN_AND_MEAN
#define MAX_INTERVAL_STR_LEN 32
#define REINJECT_FLAG 0xDEADBEEF         // Unique flag to mark reinjected packets
#define INIT_PACKET_BUFFER 65535         // Initial packet buffer size in bytes
#define DEFAULT_MAX_BUFFER 75000         // Default max buffer size in bytes
#define DEFAULT_DL_BUFFER 150000         // Default download buffer size in bytes
#define DEFAULT_UL_BUFFER 150000         // Default upload buffer size in bytes

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
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Global atomic flag for controlling the loop in multiple threads (1 = enabled at start)
volatile LONG running = 1;

// PID thread specific flag (1 = enabled at start)
volatile LONG pid_thread_running = 1;

///
/// TYPEDEF STUFF
///

// Token Bucket Structure
typedef struct {
	double rate;              // rate in bytes per second
	double max_tokens;        // maximum tokens (bucket size)
	double tokens;            // current tokens
	int buffer_size;          // current buffer usage (in bytes, kept as int)
	DWORD last_checked;       // last time tokens were replenished (milliseconds)
	CRITICAL_SECTION lock;    // mutex for thread safety
} TokenBucket;

// Hash Map for Target PIDs
typedef struct {
	int pid;                // Process ID (key)
	UT_hash_handle hh;      // Hash handle for uthash
} PIDEntry;

// Structures for Packet Parsing (parsing IP, TCP, and UDP packets)
typedef struct {
	char ip[INET_ADDRSTRLEN];  // IP address as key
	UINT port;
	int packet_count;
	DWORD last_reset;
	UT_hash_handle hh;
} ConnectionRate;

// WinDivert
typedef struct {
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	char *packet;
	UINT packet_len;
	int requeue_attempts; // Track requeues
} PacketData;

// The main parameters for throttling
typedef struct {
	int priority;
	double download_rate;
	double upload_rate;
	unsigned int max_buffer_size;
	unsigned int download_buffer_size;
	unsigned int upload_buffer_size;
	unsigned int latency_ms;
	float packet_loss;
	unsigned int *nic_indices;
	unsigned int nic_count;
	double *download_limits; // Download rate per NIC (bytes per second)
	double *upload_limits;   // Upload rate per NIC (bytes per second)
	unsigned int max_tcp_connections;
	unsigned int max_udp_packets_per_second;
} ThrottlingParams;

// The parameters for processes
typedef struct {
	PIDEntry *pid_map;
	ConnectionRate *connection_rates;
	CRITICAL_SECTION rate_limit_lock;
	char *process_list;
	unsigned int packet_threshold;
	unsigned int time_threshold_ms;
	unsigned int packet_count;
	clock_t last_update_time;
	bool needs_update;
} ProcessParams;

// Lock-Free Queue Structure
typedef struct {
	PacketData *queue;
    LONG head, tail;
    LONG size;
    size_t capacity;
} LockFreeQueue;

// Arguments that can be passed to threads
typedef struct {
	LockFreeQueue *queue;
	PacketData *data;
	ThrottlingParams *params;
	ProcessParams *processparams;
	TokenBucket *download_buckets;
	TokenBucket *upload_buckets;
	int bucket_count;
} ThreadArgs;


///
/// GLOBAL VARIABLES
///

// Debug, quiet and no error mode
bool DEBUG = false;
bool QUIET = false;
bool ERRORS = false;


///
/// DWORD STUFF
///

// Function to find TCP PID
DWORD find_tcp_pid(UINT16 port) {
	PMIB_TCPTABLE_OWNER_PID tcpTable;
	ULONG size = 0;
	DWORD result = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (result != ERROR_INSUFFICIENT_BUFFER) {
		if (!ERRORS) fprintf(stderr, "Failed to get buffer size for TCP table\n");
		return 0;
	}

	tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
	if (!tcpTable) {
		if (!ERRORS) fprintf(stderr, "Memory allocation failed for TCP table\n");
		return 0;
	}

	result = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (result != NO_ERROR) {
		if (!ERRORS) fprintf(stderr, "Failed to retrieve TCP table\n");
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
		if (!ERRORS) fprintf(stderr, "Failed to get buffer size for UDP table\n");
		return 0;
	}

	udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
	if (!udpTable) {
		if (!ERRORS) fprintf(stderr, "Memory allocation failed for UDP table\n");
		return 0;
	}

	result = GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	if (result != NO_ERROR) {
		if (!ERRORS) fprintf(stderr, "Failed to retrieve UDP table\n");
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
void ip_to_string_ipv6(const UINT32 *ip, char *ip_str) {
    snprintf(ip_str, INET6_ADDRSTRLEN,
             "%x:%x:%x:%x:%x:%x:%x:%x",
             ntohs(ip[0]), ntohs(ip[1]), ntohs(ip[2]), ntohs(ip[3]),
             ntohs(ip[4]), ntohs(ip[5]), ntohs(ip[6]), ntohs(ip[7]));
}

// Function to get the source IP address, supporting both IPv4 and IPv6
void get_source_ip(const WINDIVERT_ADDRESS *addr, char *ip_str) {
    if (addr->Flow.LocalAddr[0] != 0) {  // Check for IPv4
        ip_to_string_ipv4(addr->Flow.LocalAddr[0], ip_str);  // For IPv4
    } else {
        ip_to_string_ipv6((const UINT32 *)addr->Flow.LocalAddr, ip_str);  // For IPv6
    }
}

// Function to get the destination IP address, supporting both IPv4 and IPv6
void get_dest_ip(const WINDIVERT_ADDRESS *addr, char *ip_str) {
    if (addr->Flow.RemoteAddr[0] != 0) {  // Check for IPv4
        ip_to_string_ipv4(addr->Flow.RemoteAddr[0], ip_str);  // For IPv4
    } else {
        ip_to_string_ipv6((const UINT32 *)addr->Flow.RemoteAddr, ip_str);  // For IPv6
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

	EnterCriticalSection(&processparams->rate_limit_lock);

	HASH_FIND_STR(processparams->connection_rates, ip, rate_entry);
	if (!rate_entry) {
		rate_entry = malloc(sizeof(ConnectionRate));
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
			LeaveCriticalSection(&processparams->rate_limit_lock);
			return false;  // Drop packet
		}
	}

	LeaveCriticalSection(&processparams->rate_limit_lock);
	return true;
}


///
/// TOKEN BUCKET
///

// Function to initialize the token bucket
bool token_bucket_init(TokenBucket *bucket, double rate, int max_tokens) {
    if (!bucket) {
        return false;  // Prevent NULL pointer dereference
    }

	bucket->rate = rate;  // Set the rate in bytes per second (double for precision)
	bucket->max_tokens = max_tokens;
	bucket->tokens = max_tokens;  // Start with a full bucket
	bucket->buffer_size = 0;  // Initially, the buffer is empty
	bucket->last_checked = GetTickCount64();  // Get current time

    // Initialize critical section with spin count for better performance
    if (!InitializeCriticalSectionAndSpinCount(&bucket->lock, 4000)) {
        return false;  // Return failure if initialization fails
    }

    return true;  // Successfully initialized
}

// Function to update the token bucket (replenish tokens based on time)
void token_bucket_update(TokenBucket *bucket) {
	DWORD now = GetTickCount64();
	DWORD elapsed = now - bucket->last_checked;

	// Lock the bucket before making changes
	EnterCriticalSection(&bucket->lock);

	if (DEBUG) printf("Debug: Bucket Rate: %.2f, Elapsed time: %lu ms\n", bucket->rate, elapsed);

	// Replenish tokens based on elapsed time and rate (this will work with fractional tokens)
	if (elapsed > 0 && bucket->rate > 0) {
		double tokens_to_add = bucket->rate * (elapsed / 1000.0);
		if (DEBUG) printf("Debug: Tokens to add: %.2f\n", tokens_to_add);
		bucket->tokens = fmin(bucket->tokens + tokens_to_add, bucket->max_tokens);
	} else {
		if (DEBUG) printf("Debug: Skipping token addition due to zero elapsed time or zero rate.\n");
	}

	bucket->last_checked = now;  // Update last checked time
	
	if (DEBUG) printf("Debug: Tokens in bucket after update: %.2f, Max tokens: %f\n", bucket->tokens, bucket->max_tokens);

	// Unlock the bucket after updating
	LeaveCriticalSection(&bucket->lock);
}

// Function to consume tokens from the bucket
bool token_bucket_consume(TokenBucket *bucket, int packet_size) {
	bool success = false;

	EnterCriticalSection(&bucket->lock);

	if (bucket->tokens >= packet_size) {
		bucket->tokens -= packet_size;
		success = true;  // Successfully consumed tokens
	} else {
		success = false; // Not enough tokens available
	}

	LeaveCriticalSection(&bucket->lock);

	return success;
}

// Cleanup function for the mutex
void token_bucket_destroy(TokenBucket *bucket) {
	DeleteCriticalSection(&bucket->lock);
}


///
/// PACKET-RELATED FUNCTIONS
///

// Function to capture packet
BOOL capture_packet(HANDLE handle, char *packet, UINT packet_size, WINDIVERT_ADDRESS *addr, DWORD *recv_len) {
	OVERLAPPED recv_overlap = {0};
	recv_overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	BOOL recv_status = WinDivertRecvEx(handle, packet, packet_size, recv_len, 0, addr, NULL, &recv_overlap);
	if (!recv_status) {
		DWORD error = GetLastError();
		if (error == ERROR_IO_PENDING) {
			// Wait for the operation to complete
			WaitForSingleObject(recv_overlap.hEvent, INFINITE);
			if (!GetOverlappedResult(handle, &recv_overlap, recv_len, FALSE)) {
				if (!ERRORS) fprintf(stderr, "Failed to read packet after async completion: %lu\n", GetLastError());
				CloseHandle(recv_overlap.hEvent);
				return FALSE;
			}
		} else if (error == ERROR_TIMEOUT) {
			CloseHandle(recv_overlap.hEvent);
			return FALSE;  // Timeout occurred, signal no packet captured
		} else {
			if (!ERRORS) fprintf(stderr, "Failed to read packet: %lu\n", error);
			CloseHandle(recv_overlap.hEvent);
			return FALSE;
		}
	}

	// Cleanup
	CloseHandle(recv_overlap.hEvent);
	return TRUE;
}

// Function to reinject the packet into the network
void reinject_packet(HANDLE handle, char *packet, unsigned int packet_len, WINDIVERT_ADDRESS *addr) {
	OVERLAPPED send_overlap = {0};
	send_overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	DWORD send_len = 0;
	BOOL send_status = WinDivertSendEx(
		handle,
		packet,
		packet_len,
		&send_len,                   // pSendLen
		0,                           // flags
		addr,                        // pAddr
		sizeof(WINDIVERT_ADDRESS),   // addrLen
		&send_overlap                // lpOverlapped
	);

	if (!send_status) {
		DWORD error = GetLastError();
		if (error == ERROR_IO_PENDING) {
			// Wait for the operation to complete
			WaitForSingleObject(send_overlap.hEvent, INFINITE);
			if (!GetOverlappedResult(handle, &send_overlap, &send_len, FALSE)) {
				if (!ERRORS) fprintf(stderr, "Failed to send packet after async completion: %lu\n", GetLastError());
			}
		} else {
			if (!ERRORS) fprintf(stderr, "Failed to send packet: %lu\n", error);
		}
	}

	// Cleanup
	CloseHandle(send_overlap.hEvent);
}

// Function to check if the packet is reinjected
int is_reinjected_packet(const uint8_t *packet, unsigned int len) {
    if (len < sizeof(uint32_t)) return 0;
    uint32_t *flag = (uint32_t *)(packet + len - sizeof(uint32_t));
    return (*flag == REINJECT_FLAG);
}

// Function to mark the packet as reinjected
uint8_t *mark_packet_as_reinjected(uint8_t *packet, unsigned int len, unsigned int *new_len) {
    *new_len = len + sizeof(uint32_t);  // Increase size to accommodate flag

    // Allocate new memory for packet + flag
	uint8_t *temp = realloc(packet, *new_len);
	if (!temp) return packet;  // Return original if allocation fails

    // Append the flag at the end
    uint32_t *flag = (uint32_t *)(temp + len);
    *flag = REINJECT_FLAG;

    return temp;
}

// Function to strip the flag when handling the packet
uint8_t *strip_reinject_flag(uint8_t *packet, unsigned int *len) {
    if (*len < sizeof(uint32_t)) return packet;  // Safety check: packet too small

    uint32_t *flag = (uint32_t *)(packet + *len - sizeof(uint32_t));
    if (*flag == REINJECT_FLAG) {
        *len -= sizeof(uint32_t);  // Reduce the effective length by 4 bytes
    }

    return packet;  // Return the same pointer with the new length
}

// Function to decide if a packet should be dropped due to packet loss
bool should_drop_packet(HANDLE handle, char *packet, unsigned int packet_len, WINDIVERT_ADDRESS addr, float packet_loss) {
	if (packet_loss > 0.00f) {
		float rand_value = (float)rand() / (float)RAND_MAX;  // Generate a random float between 0.0 and 1.0
		if (rand_value < (packet_loss / 100.0f)) {
			if (DEBUG) printf("Debug: Dropped packet to simulate loss (%.2f%%)\n", packet_loss);
			return true;  // Drop the packet
		}
	}
	return false;  // No packet loss, process normally
}

// Log packet information (for debugging)
//void log_packet(const char *direction, const TokenBucket *bucket, unsigned int packet_len) {
//	printf("[%s] Packet size: %u, Tokens: %.2f\n", direction, packet_len, (double)bucket->tokens);
//}


///
/// PARSING FUNCTIONS
///

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
			if (!ERRORS) fprintf(stderr, "Invalid unit '%s' in rate '%s'. Defaulting to kilobytes.\n", unit, rate_str);
			return value * 1000.0; // Default to kilobytes
		}
	} else {
		if (!ERRORS) fprintf(stderr, "Failed to parse rate '%s'. Defaulting to 0.\n", rate_str);
		return 0;
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

///
/// Network interface related functions
///

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
			printf("Memory allocation failed\n");
			exit(EXIT_FAILURE);
		}
	} else if (dwRetVal != NO_ERROR) {
		printf("GetAdaptersAddresses failed with error %lu\n", dwRetVal);
		return;
	}

	// Retrieve the list of network adapters
	dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &out_buf_len);
	if (dwRetVal != NO_ERROR) {
		printf("GetAdaptersAddresses failed with error %lu\n", dwRetVal);
		free(adapter_addresses);
		return;
	}

	// Iterate through the adapters and display information
	PIP_ADAPTER_ADDRESSES adapter = adapter_addresses;
	int index = 1;  // Start index numbering from 1
	while (adapter) {
		printf("Interface Index: %u\n", adapter->IfIndex);           // Display the interface index
		printf("Interface Name: %s\n", adapter->AdapterName);        // Display the interface name
		printf("Adapter Description: %ws\n", adapter->Description);  // Description of the adapter

		adapter = adapter->Next;
		index++;  // Increment the index for each adapter
		printf("\n");
	}

	free(adapter_addresses);
}

// Helper function to parse comma-separated NIC indices
unsigned int *parse_nic_indices(const char *input, ThrottlingParams *params) {
    char *copy = strdup(input);
    if (!copy) {
        if (!ERRORS) fprintf(stderr, "Memory allocation failed for NIC parsing.\n");
        exit(EXIT_FAILURE);
    }

    char *token = strtok(copy, ",");
    int capacity = 16;
    int *nic_indices = malloc(capacity * sizeof(int));
    params->download_limits = malloc(capacity * sizeof(double));
    params->upload_limits = malloc(capacity * sizeof(double));

    if (!nic_indices || !params->upload_limits || !params->download_limits) {
        if (!ERRORS) fprintf(stderr, "Memory allocation failed for NIC parameters.\n");
        free(copy);
        exit(EXIT_FAILURE);
    }

    params->nic_count = 0;
    
    while (token) {
        if (params->nic_count >= capacity) {
            capacity *= 2;
            int *new_indices = realloc(nic_indices, capacity * sizeof(int));
            params->download_limits = realloc(params->download_limits, capacity * sizeof(double));
            params->upload_limits = realloc(params->upload_limits, capacity * sizeof(double));
            if (!new_indices || !params->download_limits || !params->upload_limits) {
                if (!ERRORS) fprintf(stderr, "Memory reallocation failed.\n");
                exit(EXIT_FAILURE);
            }
			nic_indices = new_indices;
        }

        // Parse "NIC_INDEX:DOWNLOAD:UPLOAD"
        char *nic_part = strtok(token, ":");
        char *download_part = strtok(NULL, ":");
        char *upload_part = strtok(NULL, ":");

        nic_indices[params->nic_count] = atoi(nic_part);
        params->download_limits[params->nic_count] = download_part ? parse_rate_with_units(download_part) : 0;
		params->upload_limits[params->nic_count] = upload_part ? parse_rate_with_units(upload_part) : 0;

        params->nic_count++;
        token = strtok(NULL, ",");
    }

    free(copy);
	return nic_indices;
}

// Function to check if a NIC index is in the target list
bool is_nic_index_in_list(ThrottlingParams *params, unsigned int nic_index) {
	for (int i = 0; i < params->nic_count; i++) {
		if (params->nic_indices[i] == nic_index) {
			return true;
		}
	}
	return false;
}

///
/// PID and process-related functions
///

// Function to add a PID to the hash map
void add_pid_to_map(PIDEntry **pid_map, int pid) {
	PIDEntry *entry = malloc(sizeof(PIDEntry));
	if (!entry) {
		if (!ERRORS) fprintf(stderr, "Memory allocation failed!\n");
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
		if (!ERRORS) fprintf(stderr, "Failed to enumerate processes.\n");
		return 0;
	}

	int pid_count = 0;
	int *pids = malloc(sizeof(int) * (needed / sizeof(DWORD)));

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

	*pid_list = realloc(pids, pid_count * sizeof(int)); // Resize array to actual PID count
	return pid_count; // Return the number of PIDs found
}

// Parse a comma-separated string of process names into an array
char **parse_processes(char *input, int *count) {
	int capacity = 16;
	char **processes = malloc(capacity * sizeof(char *));
	if (processes == NULL) {
		if (!ERRORS) fprintf(stderr, "Memory allocation failed!\n");
		exit(EXIT_FAILURE);
	}
	*count = 0;

	char *token;
	char *context = NULL;  // Required for strtok_s
	token = strtok_s(input, ",", &context);
	while (token != NULL) {
		if (*count >= capacity) {
			capacity *= 2;
			processes = realloc(processes, capacity * sizeof(char *));
			if (processes == NULL) {
				if (!ERRORS) fprintf(stderr, "Memory allocation failed during resizing!\n");
				exit(EXIT_FAILURE);
			}
		}

		// Trim leading spaces
		while (*token == ' ') token++;

		processes[*count] = strdup(token);
		if (processes[*count] == NULL) {
			if (!ERRORS) fprintf(stderr, "Memory allocation failed for process name!\n");
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
		if (!ERRORS) fprintf(stderr, "Error: Invalid format for --process-update-interval. Use '<value>p', '<value>t', or '0'.\n");
		return -1;
	}

	char value_str[MAX_INTERVAL_STR_LEN];
	strncpy(value_str, input, len - 1); // Extract the numeric part
	value_str[len - 1] = '\0';		    // Null-terminate

	if (!isdigit(value_str[0])) {
		if (!ERRORS) fprintf(stderr, "Error: Invalid numeric value for --process-update-interval.\n");
		return -1;
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
		if (!ERRORS) fprintf(stderr, "Error: Unknown unit '%c' for --process-update-interval. Use 'p' for packets, 't' for time, or '0'.\n", unit);
		return -1;
	}

	return 0; // Success
}

// Functino to get the name of the process from its PID
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

	if ((processparams->packet_threshold > 0 && ++processparams->packet_count >= processparams->packet_threshold) ||
		(processparams->time_threshold_ms > 0 && elapsed_time_ms >= processparams->time_threshold_ms)) {

		processparams->packet_count = 0;
		processparams->last_update_time = clock();
		processparams->needs_update = true;
	}

	if (!processparams->needs_update) return;
	processparams->needs_update = false;

	// Remove stale PIDs (only dead ones)
    PIDEntry *entry, *tmp;
    UT_hash_handle *hh;
    HASH_ITER(hh, processparams->pid_map, entry, tmp) {
        if (!is_process_alive(entry->pid)) {
			if (!QUIET) printf("Stale PID %u was removed.\n", entry->pid);
            HASH_DEL(processparams->pid_map, entry);
            free(entry);
        }
    }

	// Add new PIDs
	int process_count = 0;
	char *process_list_copy = strdup(processparams->process_list);
	if (process_list_copy == NULL) {
		if (!ERRORS) fprintf(stderr, "Memory allocation failed!\n");
		exit(EXIT_FAILURE);
	}
	char **processes = parse_processes(process_list_copy, &process_count);
	free(process_list_copy);  // Free the copy after parsing

	// Resolve PIDs and add to hash map
	for (int i = 0; i < process_count; i++) {
		if (DEBUG) printf("Debug: Processing: '%s'\n", processes[i]);

		int *pid_list = NULL;
		int pid_count = get_pids_from_name(processes[i], &pid_list);

		for (int j = 0; j < pid_count; j++) {
			int pid = pid_list[j];

            HASH_FIND_INT(processparams->pid_map, &pid, entry);
            if (!entry) {
                // Verify process existence before adding
                if (is_process_alive(pid)) {
                    add_pid_to_map(&processparams->pid_map, pid);
                    if (!QUIET) printf("Added new PID '%d' for process '%s' to the hash map.\n", pid, processes[i]);
                }
            }
		}
		free(pid_list);
		free(processes[i]);
	}
	free(processes);
}

///
/// TIMER
///

// High-precision timer (QueryPerformanceCounter)
DWORD get_frequency_ticks() {
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);
	return frequency.QuadPart;  // Return the frequency of the performance counter as LONGLONG
}

DWORD get_current_time_ticks() {
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return counter.QuadPart;  // Return the current high-resolution counter value as LONGLONG
}

void non_blocking_delay(int delay_ms) {
	LONGLONG frequency = get_frequency_ticks();
	LONGLONG target_time_ticks = get_current_time_ticks() + (delay_ms * frequency / 1000);

	// Handle overflow by ensuring target_time_ticks doesn't exceed LONGLONG_MAX
	if (target_time_ticks < 0) {
		target_time_ticks = LLONG_MAX;  // Cap it to max LONGLONG value to prevent overflow
	}

	while (get_current_time_ticks() < target_time_ticks) {
		if (InterlockedOr(&running, 0) == 0) {
			return;  // Exit if running is false
		}
		YieldProcessor();  // Yield CPU
	}
}

///
/// LOCK-FREE QUEUE
///

// Initialize lock-free queue
bool init_queue(LockFreeQueue *queue, size_t capacity) {
    queue->queue = (PacketData*)malloc(sizeof(PacketData) * capacity);
    if (!queue->queue) {
        if (!ERRORS) fprintf(stderr, "Memory allocation failed for queue.\n");
        return false;
    }
    queue->capacity = capacity;
    queue->head = 0;
    queue->tail = 0;
    queue->size = 0;
    return true;
}

// Enqueue a packet (returns false if full)
bool enqueue(LockFreeQueue *queue, PacketData *data) {
    LONG size = InterlockedOr(&queue->size, 0);  // Read size atomically
    if (size >= queue->capacity) {
        return false;  // Queue full
    }

    LONG tail = queue->tail;
    LONG next = (tail + 1) % queue->capacity;

    if (next == queue->head) {
        return false; // Queue full (redundant check for safety)
    }

    // Copy metadata
    queue->queue[tail] = *data;

    // Allocate and copy packet data
    queue->queue[tail].packet = (char *)malloc(data->packet_len);
    if (!queue->queue[tail].packet) {
        if (!ERRORS) fprintf(stderr, "Failed to allocate memory for packet in enqueue.\n");
        return false;
    }
    memcpy(queue->queue[tail].packet, data->packet, data->packet_len);

    // Atomically update the tail index
    InterlockedExchange(&queue->tail, next);

    // Atomically increment queue size
    InterlockedIncrement(&queue->size);

    return true;
}

// Dequeue a packet (returns false if empty)
bool dequeue(LockFreeQueue *queue, PacketData *data) {
    if (InterlockedOr(&queue->size, 0) == 0) {
        return false;  // Queue empty
    }

    LONG head = queue->head;
    if (head == queue->tail) {
        return false; // Queue still empty (redundant safety check)
    }

    // Copy packet data
    *data = queue->queue[head];

    // Atomically update the head index
    InterlockedExchange(&queue->head, (head + 1) % queue->capacity);

    // Atomically decrement queue size
    InterlockedDecrement(&queue->size);

    return true;
}

// Check if queue is full (safe for multiple threads)
bool is_queue_full(LockFreeQueue *queue) {
    return InterlockedOr(&queue->size, 0) >= queue->capacity * 0.8;
}

// Cleanup function for queue
void destroy_queue(LockFreeQueue *queue) {
    if (!queue || !queue->queue) return;

    LONG head = queue->head;
    LONG tail = queue->tail;

    while (head != tail) {
        free(queue->queue[head].packet);
        queue->queue[head].packet = NULL;
        head = (head + 1) % queue->capacity;
    }

    free(queue->queue);
    queue->queue = NULL;
    queue->head = queue->tail = queue->size = 0;
}


///
/// THREADS
///

// Thread function for capturing packets
DWORD WINAPI capture_packets(LPVOID arg) {
	ThreadArgs *args = (ThreadArgs*)arg;
	ThrottlingParams *params = args->params;
	LockFreeQueue *queue = args->queue;
	
	// Initialize packet data structure
	PacketData data;
	data.packet = malloc(params->max_buffer_size);  // Allocate memory for packet
	if (!data.packet) {
		if (!ERRORS) fprintf(stderr, "Failed to allocate memory for packet capture.\n");
		return EXIT_FAILURE;
	}

	// Open WinDivert handle for capturing traffic
	data.handle = WinDivertOpen("ip or tcp or udp", WINDIVERT_LAYER_NETWORK, params->priority, 0);
	if (data.handle == INVALID_HANDLE_VALUE && !ERRORS) {
		DWORD error = GetLastError();
		if (!ERRORS) {
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
		}
		return EXIT_FAILURE;
	}

	// Capture loop - check atomic flag
	while (InterlockedCompareExchange(&running, 0, 0)) {
		// Capture packet
		if (!capture_packet(data.handle, data.packet, params->max_buffer_size, &data.addr, &data.packet_len)) {
			if (!ERRORS) fprintf(stderr, "Failed to read packet: %lu\n", GetLastError());
			continue;
		}

		// Reset requeue attempts for new packets
		data.requeue_attempts = 0;

		// Check if we're dealing with a network packet
		if (data.addr.Layer == WINDIVERT_LAYER_NETWORK) {
			unsigned int if_idx = data.addr.Network.IfIdx;
			if (!is_nic_index_in_list(params, if_idx)) {
				continue;  // Skip packets from unwanted NICs
			}
		}

		// Ensure packet checksums are valid
		if (!WinDivertHelperCalcChecksums(data.packet, data.packet_len, &data.addr, 0)) {
			if (!ERRORS) fprintf(stderr, "Checksum calculation failed.\n");
			continue;
		}

		// Check queue and enqueue packet
		if (!enqueue(queue, &data)) {
			if (!QUIET) printf("Queue is full, dropping packet.\n");
			Sleep(1); // Reduce CPU usage when queue is full or when waiting for packets
		}
	}

	// Cleanup after capture loop ends
	WinDivertClose(data.handle);
	return 0;
}

// Thread function for handling PIDs
DWORD WINAPI pid_updater(LPVOID arg) {
	ThreadArgs *args = (ThreadArgs*)arg;
    ProcessParams *processparams = args->processparams;

    while (InterlockedCompareExchange(&pid_thread_running, 0, 0) && InterlockedCompareExchange(&running, 0, 0)) {
		// Update PIDs dynamically based on thresholds
		if (processparams->process_list != NULL) {
			update_pid_map(processparams);
		} else {
			// Stop this thread by setting the flag to 0
			InterlockedExchange(&pid_thread_running, 0);  // Set thread flag to 0 to stop it
			break;  // Exit the loop
		}

        Sleep(100);
    }
    return 0;
}

// Thread function for processing packets for traffic shaping
DWORD WINAPI process_packets(LPVOID arg) {
	ThreadArgs *args = (ThreadArgs*)arg;
	ThrottlingParams *params = args->params;
	ProcessParams *processparams = args->processparams;
	LockFreeQueue *queue = args->queue;
	unsigned int new_len;

	while (InterlockedCompareExchange(&running, 0, 0)) {
		PacketData data;
		if (!dequeue(queue, &data)) {
			Sleep(1);  // Wait for packets to arrive
			continue;
		}
		
		// Check how queue is filled, this should prevent packet congestion
		if (is_queue_full(queue)) {
			if (DEBUG) printf("Debug: Queue nearly full, dropping packet.\n");
			free(data.packet);
			continue;
		}

        // Make a temporary pointer for checking reinjection flag
        uint8_t *packet_copy = data.packet;
        unsigned int packet_len_copy = data.packet_len;

        // Check if the packet was already reinjected (before stripping)
        if (data.requeue_attempts == 0 && is_reinjected_packet(packet_copy, packet_len_copy)) {
			if (DEBUG) printf("Debug: Packet with PID %ld already reinjected, skipping.\n", get_packet_pid(&data.addr, data.packet, data.packet_len));
            continue;
        }

        // Strip reinjection flag from the actual packet (ensure it's safe)
        uint8_t *stripped_packet = strip_reinject_flag(data.packet, &data.packet_len);
        if (!stripped_packet) {  
			if (DEBUG) printf("Debug: Failed to strip reinjection flag from packet.\n");
            free(data.packet);
            continue;
        }
        data.packet = stripped_packet; // Assign the stripped version

		// Mark packet with custom flag (append flag at the end)
		uint8_t *marked_packet = mark_packet_as_reinjected(data.packet, data.packet_len, &new_len);
		if (!marked_packet) { 
			if (DEBUG) printf("Debug: Failed to mark packet with reinjection flag.\n");
			free(data.packet);
			continue;
		}
		data.packet = marked_packet;  // Only assign if successful
		data.packet_len = new_len;
		if (DEBUG) printf("Debug: Packet marked with reinjection flag. New length: %u\n", data.packet_len);

		// Check if packet matches a monitored process
		if (processparams->process_list != NULL) {
			DWORD pid = get_packet_pid(&data.addr, data.packet, data.packet_len);
			if (processparams->pid_map != NULL && !is_pid_in_map(processparams->pid_map, pid)) {
				if (DEBUG) printf("Debug: PID %ld is not monitored, dropping related packet to it.\n", pid);
				// Reinject these packets back as is, if they are valid
				if(data.packet) {
					reinject_packet(data.handle, data.packet, data.packet_len, &data.addr);
					free(data.packet);
					continue;
				} else {
					continue;
				}
			}
		}

		// Apply TCP connection limit (for TCP packets)
		if (params->max_tcp_connections > 0) {
			UINT src_port = 0, dest_port = 0;
			BYTE protocol = 0;
			char ip_address[INET_ADDRSTRLEN];  // To hold the source IP address

			// Retrieve protocol and ports from the packet
			if (get_packet_protocol_and_port(data.packet, data.packet_len, &src_port, &dest_port, &protocol)) {
				if (protocol == IPPROTO_TCP) {
					// Get source IP address
					get_source_ip(&data.addr, ip_address);  // Get the source IP

					if (!check_packet_rate_limit(processparams, ip_address, src_port, params->max_tcp_connections)) {
						if (DEBUG) printf("Debug: Dropped TCP packet, IP: %s, src port: %d, dest port: %d\n", ip_address, src_port, dest_port);
						free(data.packet);  // Drop packet if limit exceeded
						continue;
					}
				}
			}
		}

		// Apply UDP packet limit (for UDP packets)
		if (params->max_udp_packets_per_second > 0) {
			UINT src_port = 0, dest_port = 0;
			BYTE protocol = 0;
			char ip_address[INET_ADDRSTRLEN];  // To hold the source IP address

			// Retrieve protocol and ports from the packet
			if (get_packet_protocol_and_port(data.packet, data.packet_len, &src_port, &dest_port, &protocol)) {
				if (protocol == IPPROTO_UDP) {
					// Get source IP address
					get_source_ip(&data.addr, ip_address);  // Get the source IP

					if (!check_packet_rate_limit(processparams, ip_address, src_port, params->max_udp_packets_per_second)) {
						if (DEBUG) printf("Debug: Dropped UDP packet, IP: %s, src port: %d, dest port: %d\n", ip_address, src_port, dest_port);
						free(data.packet);  // Drop packet if limit exceeded
						continue;
					}
				}
			}
		}
		
		// Get the NIC index
		unsigned int if_idx = data.addr.Network.IfIdx;
		
		// Find the matching NIC bucket index
		int nic_index = -1;
		for (int i = 0; i < args->bucket_count; i++) {
			if (params->nic_indices[i] == if_idx) {
				nic_index = i;
				break;
			}
		}

		// If the NIC is not managed, skip processing
		// (this should not be needed, as it's already handled in the previous thread,
		// but a double check never hurts, to make sure)
		if (nic_index == -1) {
			free(data.packet);
			continue;
		}

		// Select the correct token bucket
		TokenBucket *bucket = NULL;
		if (data.addr.Outbound) {
			bucket = (params->upload_limits[nic_index] > 0) ? &args->upload_buckets[nic_index] : NULL;
		} else {
			bucket = (params->download_limits[nic_index] > 0) ? &args->download_buckets[nic_index] : NULL;
		}

		if (bucket != NULL) {
			if (DEBUG) printf("Debug: Rate before update: %.2f\n", bucket->rate);
			token_bucket_update(bucket);

			if (DEBUG) printf("Debug: Bucket Rate: %.2f, Tokens Available: %.2f\n", bucket->rate, bucket->tokens);

			// Consume tokens from the bucket (if enough tokens available)
			int retry_count = 5;  // Allow up to 5 retries
			int elapsed_time = 0;

			while (retry_count > 0 && elapsed_time < 500) {  // 500ms max wait
				if (token_bucket_consume(bucket, data.packet_len)) {
					break;
				}
				int delay_time = min(max((int)(1000.0 * (data.packet_len / bucket->rate)), 5), 100);
				non_blocking_delay(delay_time);
				elapsed_time += delay_time;
				retry_count--;
			}

			// If retries failed, try requeueing
			if (retry_count == 0) {
				if (data.requeue_attempts < 3) {
					data.requeue_attempts++;  // Increase requeue count
					if (enqueue(queue, &data)) { 
						continue; // Successfully requeued, skip further processing
					}
				}
				
				// If max requeue attempts exceeded or queue is full, drop the packet
				free(data.packet);
				continue;
			}

			if (DEBUG) printf("Debug: Tokens remaining after consumption: %.2f\n", bucket->tokens);
		}

		// Simulate packet loss
		if (should_drop_packet(data.handle, data.packet, data.packet_len, data.addr, params->packet_loss)) {
			free(data.packet);
			continue;
		}

		// Simulate latency using non-blocking delay
		if (params->latency_ms > 0) {
			non_blocking_delay(params->latency_ms);  // Delay in milliseconds
		}

		// Reinject the processed packet
		if (DEBUG) printf("Debug: Reinjecting packet of size %lu\n", data.packet_len);

		// Only reinject valid packet data
		if(data.packet) {
			reinject_packet(data.handle, data.packet, data.packet_len, &data.addr);
			free(data.packet);
		} else {
			continue;  // Skip further processing for invalid packet
		}
	}

	return 0;
}

// Handle the exit key ('Q')
DWORD WINAPI exit_key(LPVOID arg) {
	ThreadArgs *args = (ThreadArgs *)arg;
	HWND hwnd = GetConsoleWindow(); // Get handle to the console window

    while (InterlockedCompareExchange(&running, 0, 0)) { // Check running flag
        if (GetForegroundWindow() == hwnd && (GetAsyncKeyState('Q') & 0x8000)) {
            if (!QUIET) printf("\nExiting bandwidth throttler...\n");

            // Signal all threads to stop
            InterlockedExchange(&running, 0);
			InterlockedExchange(&pid_thread_running, 0);
            break;
        }

        Sleep(10);
    }

    return 0;
}

///
/// HELPER FUNCTIONS FOR MAIN
///

// Stops the WinDivert service
void stop_windivert() {
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS_PROCESS status;
	DWORD bytesNeeded;

	// Open the service control manager
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hSCManager == NULL) {
		if (!ERRORS) printf("OpenSCManager failed (%d)\n", GetLastError());
	}

	// Open the service
	hService = OpenService(hSCManager, "WinDivert", SERVICE_QUERY_STATUS | SERVICE_STOP);
	if (hService == NULL) {
		if (!ERRORS) printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(hSCManager);
	}

	// Query the service status
	if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
		// Check if the service is running
		if (status.dwCurrentState == SERVICE_RUNNING) {
			if (!QUIET) printf("The WinDivert service is running, stopping it...\n");

			// Stop the service
			if (ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&status)) {
				if (!QUIET) printf("The WinDivert service stopped successfully.\n");
			} else {
				if (!ERRORS) printf("Failed to stop the WinDivert service: (%d)\n", GetLastError());
			}
		} else {
			if (!QUIET) printf("WinDivert service is not running.\n");
		}
	} else {
		if (!ERRORS) printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
	}

	// Clean up
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}

// Handler for control events (like Ctrl+C)
BOOL ctrl_handler(DWORD fdwCtrlType) {
	if (fdwCtrlType == CTRL_C_EVENT) {
		if (!QUIET) printf("Ctrl+C pressed, stopping...\n");
		InterlockedExchange(&running, 0);  // Set running flag to 0
		InterlockedExchange(&pid_thread_running, 0);  // Set pid_thread_running flag to 0
		return TRUE;
	}
	return FALSE;
}

// Function to get the program's name without the .exe extension
const char *get_program_name(const char *path) {
	const char *name = strrchr(path, '\\'); // Look for last backslash (Windows path)
	if (!name) name = strrchr(path, '/');   // Look for last slash (POSIX path)
	if (name) name++;                       // Skip the slash
	else name = path;                       // No slashes, use the whole path

	// Remove the ".exe" extension if present
	char *ext = strstr(name, ".exe");
	if (ext && ext == name + strlen(name) - 4) { // Ensure ".exe" is at the end
		static char buffer[MAX_PATH];            // Static buffer for the program name
		strncpy(buffer, name, ext - name);       // Copy without ".exe"
		buffer[ext - name] = '\0';
		return buffer;
	}

	return name; // Return the original name if no ".exe" extension
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
	printf("  -b, --packet-buffer <bytes>                  Maximum packet buffer size in bytes (default: 65535)\n");
	printf("  -t, --tcp-limit <NUM>                        Maximum limit of active TCP connections (default: 0 = unlimited)\n");
	printf("  -r, --udp-limit <NUM>                        Maximum limit of active UDP connections (default: 0 = unlimited)\n");
	printf("  -L, --latency <ms>                           Set the latency in milliseconds (default: 0 = no latency)\n");
	printf("  -m, --packet-loss <float>                    Set the packet loss in percentage (default: 0.00 = no loss)\n");
	printf("  -n, --nic <interface_index>                  Throttle traffic for the specified network interfaces (comma-separated)\n");
	printf("            <NIC_INDEX:DL_RATE:UL_RATE>        For different global download and upload rate limits per NIC\n");
	printf("  -l, --list-nics                              List all available network interfaces\n");
	printf("  -d, --debug                                  Display more informational messages (in case of issues)\n");
	printf("  -q, --quiet                                  Do not display any messages (except errors)\n");
	printf("  -e, --no-errors                              Do not display any error messages\n");
	printf("  -h, --help                                   Display this help message and exit\n");
}


///
/// MAIN
///

int main(int argc, char *argv[]) {
	// Seed random generator for packet loss
	srand((unsigned int)time(NULL));

	// Set up the control handler
	if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ctrl_handler, TRUE)) {
		if (!ERRORS) fprintf(stderr, "Failed to set control handler\n");
		return 1;
	}

	// Initialize parameters
	ThrottlingParams params = {
		.priority = 0,
		.download_rate = 0,
		.upload_rate = 0,
		.max_buffer_size = INIT_PACKET_BUFFER,
		.download_buffer_size = DEFAULT_DL_BUFFER,
		.upload_buffer_size = DEFAULT_UL_BUFFER,
		.latency_ms = 0,
		.packet_loss = 0.00f,
		.nic_indices = NULL,
		.nic_count = 0,
		.download_limits = 0,
		.upload_limits = 0,
		.max_tcp_connections = 0,
		.max_udp_packets_per_second = 0
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

	// For NIC listing
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup failed\n");
		return 1;
	}

	// Display help if no arguments are provided
	if (argc == 1) {
		print_help(argv[0]);
		return EXIT_SUCCESS;
	}

	// Manual argument parsing
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "--process") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) {
			processparams.process_list = argv[++i];
		} else if ((strcmp(argv[i], "--process-update-interval") == 0 || strcmp(argv[i], "-i") == 0) && i + 1 < argc) {
			if (processparams.process_list != NULL) {
				if (parse_process_update_interval(argv[++i], &processparams) != 0) {
					print_help(argv[0]);
					return EXIT_FAILURE;
				}
			}
		} else if ((strcmp(argv[i], "--download") == 0 || strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
			params.download_rate = parse_rate_with_units(argv[++i]);
		} else if ((strcmp(argv[i], "--upload") == 0 || strcmp(argv[i], "-u") == 0) && i + 1 < argc) {
			params.upload_rate = parse_rate_with_units(argv[++i]);
		} else if ((strcmp(argv[i], "--priority") == 0 || strcmp(argv[i], "-P") == 0) && i + 1 < argc) {
			params.priority = atoi(argv[++i]);
			if (params.priority < WINDIVERT_PRIORITY_LOWEST || params.priority > WINDIVERT_PRIORITY_HIGHEST) {
				if (!ERRORS) fprintf(stderr, "Error: Priority must be between %d and %d.\n", WINDIVERT_PRIORITY_LOWEST, WINDIVERT_PRIORITY_HIGHEST);
				return EXIT_FAILURE;
			}
		} else if ((strcmp(argv[i], "--packet-buffer") == 0 || strcmp(argv[i], "-b") == 0) && i + 1 < argc) {
			params.max_buffer_size = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--download-buffer") == 0 || strcmp(argv[i], "-D") == 0) && i + 1 < argc) {
			params.download_buffer_size = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--upload-buffer") == 0 || strcmp(argv[i], "-U") == 0) && i + 1 < argc) {
			params.upload_buffer_size = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--tcp-limit") == 0 || strcmp(argv[i], "-t") == 0) && i + 1 < argc) {
			params.max_tcp_connections = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--udp-limit") == 0 || strcmp(argv[i], "-r") == 0) && i + 1 < argc) {
			params.max_udp_packets_per_second = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--latency") == 0 || strcmp(argv[i], "-L") == 0) && i + 1 < argc) {
			params.latency_ms = atoi(argv[++i]);
		} else if ((strcmp(argv[i], "--packet-loss") == 0 || strcmp(argv[i], "-m") == 0) && i + 1 < argc) {
			params.packet_loss = atof(argv[++i]);
		} else if ((strcmp(argv[i], "--nic") == 0 || strcmp(argv[i], "-n") == 0) && i + 1 < argc) {
			params.nic_indices = parse_nic_indices(argv[++i], &params);
		} else if ((strcmp(argv[i], "--list-nics") == 0 || strcmp(argv[i], "-l") == 0)) {
			list_network_interfaces();
			WSACleanup();
			return EXIT_SUCCESS;
		} else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
			DEBUG = true;
		} else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
			QUIET = true;
		} else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--no-errors") == 0) {
			ERRORS = true;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			print_help(argv[0]);
			return EXIT_SUCCESS;
		} else {
			printf("Unknown or invalid argument: %s\n", argv[i]);
			print_help(argv[0]);
			return EXIT_FAILURE;
		}
	}

	// Validate required parameters
	if (params.download_rate < 0 || params.upload_rate < 0) {
		if (!ERRORS) fprintf(stderr, "Error: Download/Upload speed limit must not be negative.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.nic_count == 0) {
		if (!ERRORS) fprintf(stderr, "Error: You must specify at least one NIC index with --nic.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.max_buffer_size < 0 || params.max_buffer_size > DEFAULT_MAX_BUFFER) {
		if (!ERRORS) fprintf(stderr, "Error: Packet buffer size must be between 0 and %d.\n", DEFAULT_MAX_BUFFER);
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.download_buffer_size < 0) {
		if (!ERRORS) fprintf(stderr, "Error: Download buffer size must not be negative.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.upload_buffer_size < 0) {
		if (!ERRORS) fprintf(stderr, "Error: Upload buffer size must not be negative.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.max_tcp_connections  < 0) {
		if (!ERRORS) fprintf(stderr, "Error: The max TCP connection number cannot be negative.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}
	
	if (params.max_udp_packets_per_second  < 0) {
		if (!ERRORS) fprintf(stderr, "Error: The max UDP connection number cannot be negative.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.packet_loss < 0.00f || params.packet_loss > 100.00f) {
		if (!ERRORS) fprintf(stderr, "Error: Packet loss percentage must be between 0 and 100.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	if (params.latency_ms < 0) {
		if (!ERRORS) fprintf(stderr, "Error: Latency must not be negative.\n");
		print_help(argv[0]);
		return EXIT_FAILURE;
	}

	// Print info for the user
	if (!QUIET || DEBUG) {

		if (DEBUG) {
			printf("--- DEBUG MODE ---\n");
		}

		printf("Priority: %d", params.priority);
		if (params.priority == 30000) {
			printf(" (highest)\n");
		} else if (params.priority <= 29999 && params.priority > 15000) {
			printf(" (high)\n");
		} else if (params.priority >= 0 && params.priority <= 14999) {
			printf(" (normal)\n");
		} else if (params.priority < 0 && params.priority >= -15000) {
			printf(" (low)\n");
		} else if (params.priority < -15000 && params.priority >= -30000) {
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

		if (params.download_rate > 0) {
			print_rate_with_units("Download limit", params.download_rate);
		}
		if (params.upload_rate > 0) {
			print_rate_with_units("Upload limit", params.upload_rate);
		}

		printf("Max packet buffer size: %d bytes\n", params.max_buffer_size);
		printf("Max download buffer size: %d bytes\n", params.download_buffer_size);
		printf("Max upload buffer size: %d bytes\n", params.upload_buffer_size);

		if (params.latency_ms > 0) {
			printf("Simulated latency: %d (ms)\n", params.latency_ms);
		}

		if (params.packet_loss > 0.00f && params.packet_loss <= 100.00f) {
			printf("Simulated packet loss: %f%\n", params.packet_loss);
		}

		if (params.max_tcp_connections > 0)
		{
			printf("Max TCP connections: %d\n", params.max_tcp_connections);
		}

		if (params.max_udp_packets_per_second > 0)
		{
			printf("Max UDP connections: %d\n", params.max_udp_packets_per_second);
		}

		printf("\nPress 'q' to quit the bandwidth throttler.\n\n");
	}

	// One-time only: make a process list if processes exist
	if (processparams.process_list != NULL) {
		// Parse process list and resolve to PIDs
		int process_count = 0;
		char *process_list_copy = strdup(processparams.process_list);
		if (process_list_copy == NULL) {
			if (!ERRORS) fprintf(stderr, "Memory allocation failed!\n");
			exit(EXIT_FAILURE);
		}
		char **processes = parse_processes(process_list_copy, &process_count);
		free(process_list_copy);  // Free the copy after parsing

		// Resolve PIDs and add to hash map
		for (int i = 0; i < process_count; i++) {
			if (DEBUG) printf("Debug: Processing: '%s'\n", processes[i]);

			int *pid_list = NULL;
			int pid_count = get_pids_from_name(processes[i], &pid_list);

			if (pid_count > 0) {
				for (int j = 0; j < pid_count; j++) {
					add_pid_to_map(&processparams.pid_map, pid_list[j]);
					if (!QUIET) printf("Added PID '%d' for process '%s' to the hash map.\n", pid_list[j], processes[i]);
				}
			} else {
				if (!ERRORS) fprintf(stderr, "Warning: Could not resolve PIDs for process '%s'.\n", processes[i]);
			}
			free(pid_list);
			free(processes[i]);
		}
		free(processes);
	} else {
		if (!QUIET) printf("No processes were specified. Global bandwidth throttling will apply.\n");
	}

	// Initialize lock-free queue
	LockFreeQueue queue;
	if (!init_queue(&queue, 1024)) {
		goto cleanup_final2;
	}

	// Initialize the argument structure for threads
	ThreadArgs args = {
		.queue = &queue,
		.params = &params,
		.processparams = &processparams
	};

	// Allocate token buckets for each NIC
	args.download_buckets = malloc(params.nic_count * sizeof(TokenBucket));
	args.upload_buckets = malloc(params.nic_count * sizeof(TokenBucket));

	if (!args.download_buckets || !args.upload_buckets) {
		if (!ERRORS) fprintf(stderr, "Memory allocation failed for the token buckets.\n");

		// Cleanup in case one allocation succeeded but the other failed
		goto cleanup_final2;
	}

	for (int i = 0; i < params.nic_count; i++) {
		// If it is not set, use the global download and upload rate instead
		if (params.download_limits[i] == 0) {
			params.download_limits[i] = params.download_rate;
		}
		if (params.upload_limits[i] == 0) {
			params.upload_limits[i] = params.upload_rate;
		}
		if (!token_bucket_init(&args.download_buckets[i], params.download_limits[i], params.download_buffer_size) ||
		    !token_bucket_init(&args.upload_buckets[i], params.upload_limits[i], params.upload_buffer_size)) {
				if (!ERRORS) fprintf(stderr, "Failed to initialize token buckets.\n");
				goto cleanup_final;
			}
	}
	args.bucket_count = params.nic_count;

    // Initialize mutex for rate limit with error handling
    if (!InitializeCriticalSectionAndSpinCount(&processparams.rate_limit_lock, 4000)) {
        if (!ERRORS) fprintf(stderr, "Failed to initialize critical section.\n");
        goto cleanup_final;
    }

	// Create threads using Windows API
	HANDLE capture_thread = CreateThread(NULL, 0, capture_packets, &args, 0, NULL);
	HANDLE pid_thread = CreateThread(NULL, 0, pid_updater, &args, 0, NULL);
	HANDLE process_thread = CreateThread(NULL, 0, process_packets, &args, 0, NULL);
	HANDLE exit_thread = CreateThread(NULL, 0, exit_key, &args, 0, NULL);

    // Check if any thread creation failed
	if (!capture_thread) {
		if (!ERRORS) fprintf(stderr, "Failed to create the capture thread.\n");
		goto cleanup_threads;
	}
	if (!pid_thread) {
		if (!ERRORS) fprintf(stderr, "Failed to create the PID thread.\n");
		goto cleanup_threads;
	}
	if (!process_thread) {
		if (!ERRORS) fprintf(stderr, "Failed to create the process thread.\n");
		goto cleanup_threads;
	}
	if (!exit_thread) {
		if (!ERRORS) fprintf(stderr, "Failed to create the exit thread.\n");
		goto cleanup_threads;
	}

	// Ensure all threads exit before cleanup
	WaitForSingleObject(exit_thread, INFINITE);
	WaitForSingleObject(capture_thread, INFINITE);
	WaitForSingleObject(pid_thread, INFINITE);
	WaitForSingleObject(process_thread, INFINITE);


	cleanup_threads:
		// Clean up handles if they were successfully created
		if (capture_thread) CloseHandle(capture_thread);
		if (pid_thread) CloseHandle(pid_thread);
		if (process_thread) CloseHandle(process_thread);
		if (exit_thread) CloseHandle(exit_thread);

		// Destroy mutex for rate limit
		DeleteCriticalSection(&processparams.rate_limit_lock);
		goto cleanup_final;


	cleanup_final:
		// Destroy token buckets
		for (int i = 0; i < params.nic_count; i++) {
			token_bucket_destroy(&args.download_buckets[i]);
			token_bucket_destroy(&args.upload_buckets[i]);
		}
		goto cleanup_final2;


	cleanup_final2:
		// Destroy queue
		destroy_queue(&queue);

		// Destroy token buckets
		free(args.download_buckets);
		free(args.upload_buckets);

		// Other cleanup
		WSACleanup();
		free(params.nic_indices);

		if (processparams.process_list != NULL) {
			free_pid_map(processparams.pid_map);
		}

		// This closes the WinDivert service before exit
		stop_windivert();

		return EXIT_SUCCESS;
}
