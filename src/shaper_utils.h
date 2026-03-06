#ifndef SHAPER_UTILS_H
#define SHAPER_UTILS_H

// shaper_utils.h
// Miscellaneous helper functions:
//   - Rate string parsing / printing
//   - NIC enumeration / validation
//   - Packet parsing helpers
//   - Delay buffer
//   - Statistics
//   - Process / PID list parsing
//   - WinDivert / admin helpers

#include "common.h"
#include "pid_cache.h"  // For PIDEntry, ConnectionRate definitions

// -----------------------------------------------------------------------
// ConnectionRate (used in ProcessParams)
// -----------------------------------------------------------------------
typedef struct {
    char key[INET_ADDRSTRLEN + 7]; // "ip:port"
    int packet_count;
    ULONGLONG last_reset;
    UT_hash_handle hh;
} ConnectionRate;

// -----------------------------------------------------------------------
// ThrottlingParams
// -----------------------------------------------------------------------
typedef struct {
    unsigned int *nic_indices;
    unsigned int nic_count;
    double *download_limits;  // bytes/sec per NIC (0 = unlimited)
    double *upload_limits;
} ThrottlingParams;

// -----------------------------------------------------------------------
// ProcessParams
// -----------------------------------------------------------------------
typedef struct {
    PIDEntry *pid_map;
    ConnectionRate *connection_rates;
    char *process_list;  // owned, comma-separated
    unsigned int packet_threshold;
    unsigned int time_threshold_ms;
    unsigned int min_update_interval_ms;
    unsigned int packet_count;
    clock_t last_update_time;
    clock_t last_actual_update;
    bool needs_update;
} ProcessParams;

// -----------------------------------------------------------------------
// DelayBuffer
// -----------------------------------------------------------------------
typedef struct {
    char packet[MAX_PACKET_SIZE];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    LONGLONG timestamp;  // QPC tick when to re-inject
    bool in_use;
} DelayedPacket;

typedef struct {
    DelayedPacket *packets;
    int head, tail, count, capacity;
} DelayBuffer;

// -----------------------------------------------------------------------
// PacketStats
// -----------------------------------------------------------------------
typedef struct {
    volatile LONG packets_processed;
    volatile LONG packets_dropped_rate_limit;
    volatile LONG packets_dropped_loss;
    volatile LONG packets_delayed;
    volatile LONGLONG bytes_processed;
    volatile LONG invalid_packets;
    LONGLONG last_stats_update;
} PacketStats;

// -----------------------------------------------------------------------
// Rate parsing / printing
// -----------------------------------------------------------------------

// Parse a rate string such as "10MB", "5Mb", "100KB", "1GB", etc.
// Returns bytes/second.  Default unit when no suffix given: KB.
double parse_rate_with_units(const char *rate_str);

// Print a labelled rate in human-readable form.
void print_rate_with_units(const char *label, double rate_bps);

// -----------------------------------------------------------------------
// NIC helpers
// -----------------------------------------------------------------------

// Print a formatted list of all available network interfaces to stdout.
void list_network_interfaces(void);

// Fill *valid_indices/*count with indices of all operational NICs.
// Caller must free(*valid_indices).
bool get_valid_nic_indices(unsigned int **valid_indices, unsigned int *count);

// Returns true if nic_index appears in valid_indices[0..valid_count-1].
bool is_valid_nic_index(unsigned int nic_index,
                        unsigned int *valid_indices, unsigned int valid_count);

// Parse a comma-separated NIC spec string (e.g. "3:10MB:5MB,5:0:2MB").
// Populates params->nic_indices, download_limits, upload_limits, nic_count.
// Exits on fatal errors (invalid NIC, malloc fail).
unsigned int *parse_nic_indices(const char *input, ThrottlingParams *params);

// -----------------------------------------------------------------------
// Packet helpers
// -----------------------------------------------------------------------

// Parse IP/TCP/UDP headers; populate local/remote IP strings and ports.
// Swaps src/dst to always present the LOCAL side as local_ip/local_port.
// Returns false if the packet cannot be parsed.
bool parse_packet_headers(const char *packet, UINT packet_len, bool outbound,
                          char *local_ip_str, char *remote_ip_str,
                          UINT *local_port, UINT *remote_port,
                          BYTE *protocol, size_t ip_buffer_size);

// Validate the packet's IP/TCP/UDP structure.
// Increments g_stats.invalid_packets on failure.
bool validate_packet(const char *packet, UINT packet_len,
                     PacketStats *stats);

// Re-inject packet back into the network stack.
// Returns false and logs an error on failure.
bool reinject_packet(HANDLE handle, char *packet, UINT packet_len,
                     WINDIVERT_ADDRESS *addr, PacketStats *stats);

// Returns true if the packet should be dropped for simulated packet loss.
bool should_drop_packet(float packet_loss, PacketStats *stats);

// -----------------------------------------------------------------------
// Per-IP / per-port rate limiting (TCP connection limiter / UDP rate limiter)
// -----------------------------------------------------------------------

// Returns false if the packet should be dropped to enforce the limit.
// Uses and updates processparams->connection_rates.
bool check_packet_rate_limit(ProcessParams *processparams,
                              CRITICAL_SECTION *lock,
                              const char *ip, UINT port,
                              int max_packets);

// Free all connection-rate hash entries in processparams.
void cleanup_rate_limits(ProcessParams *processparams,
                         CRITICAL_SECTION *lock);

// -----------------------------------------------------------------------
// Delay buffer
// -----------------------------------------------------------------------

bool delay_buffer_init(DelayBuffer *buffer, int capacity);
void delay_buffer_cleanup(DelayBuffer *buffer);

// Add a packet to the buffer; re-inject after delay_ticks QPC ticks.
// Returns false if the buffer is full.
bool delay_buffer_add(DelayBuffer *buffer, CRITICAL_SECTION *lock,
                      const char *packet, UINT packet_len,
                      const WINDIVERT_ADDRESS *addr, LONGLONG delay_ticks,
                      PacketStats *stats);

// Re-inject all buffered packets whose timestamp has arrived.
void delay_buffer_process(DelayBuffer *buffer, CRITICAL_SECTION *lock,
                          HANDLE handle);

// -----------------------------------------------------------------------
// Process list helpers
// -----------------------------------------------------------------------

// Split a comma-separated process list into an array of trimmed strings.
// *count receives the element count.  Caller must free each element and
// the array itself.
char **parse_processes(char *input, int *count);

// Parse a process-update-interval spec such as "100p", "500t,1000".
// Returns 0 on success, non-zero on error.
int parse_process_update_interval(const char *input,
                                  ProcessParams *processparams);

// Update the PID map in processparams based on throttle/time thresholds.
// Removes dead PIDs and adds newly discovered ones.
void update_pid_map(ProcessParams *processparams, PidTableCache *pid_cache);

// -----------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------

// Print a statistics snapshot to stdout (no-op if enable_statistics==false).
void print_statistics(bool enable_statistics, const PacketStats *stats);

// Call periodically; prints stats if the STATS_UPDATE_INTERVAL has elapsed.
void update_statistics(bool enable_statistics, PacketStats *stats,
                       double perf_frequency);

// -----------------------------------------------------------------------
// WinDivert / admin helpers
// -----------------------------------------------------------------------

// Attempt to stop the WinDivert kernel service.
void stop_windivert(void);

// Returns non-zero if the current process has administrator privileges.
int is_admin(void);

// -----------------------------------------------------------------------
// String helpers
// -----------------------------------------------------------------------

// Thread-safe version: copies the filename part of path (minus .exe) into
// buffer.  Returns buffer.
const char *get_program_name_r(const char *path, char *buffer, size_t buffer_size);

// Trim leading and trailing whitespace in-place.  Returns str.
char *trim_whitespace(char *str);

#endif // SHAPER_UTILS_H
