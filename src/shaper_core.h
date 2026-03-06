#ifndef SHAPER_CORE_H
#define SHAPER_CORE_H

// shaper_core.h
// Public API for the BandwidthShaper core engine.
//
// The core owns all WinDivert interaction, token buckets, and the
// packet-processing loop.  Callers (CLI or future GUI) create a
// ShaperConfig, hand it to shaper_start(), and receive live stats
// through shaper_get_stats() or the optional callbacks.
//

#include "common.h"
#include "token_bucket.h"
#include "pid_cache.h"
#include "shaper_utils.h"
#include "schedule.h"

// -----------------------------------------------------------------------
// Per-process rule
// -----------------------------------------------------------------------
typedef struct ProcessRule {
    char         name[MAX_PROCESS_NAME_LEN];

    uint32_t flags;
#define RULE_FLAG_IS_PID        (1 << 0)  // Rule is for a specific PID (not process name)
#define RULE_FLAG_DL_BLOCKED    (1 << 1)  // Download direction is blocked
#define RULE_FLAG_UL_BLOCKED    (1 << 2)  // Upload direction is blocked
#define RULE_FLAG_HAS_QUOTA_IN  (1 << 3)  // Has inbound quota
#define RULE_FLAG_HAS_QUOTA_OUT (1 << 4)  // Has outbound quota
#define RULE_FLAG_QUOTA_IN_EXHAUSTED  (1 << 5)  // Inbound quota reached
#define RULE_FLAG_QUOTA_OUT_EXHAUSTED (1 << 6)  // Outbound quota reached
#define RULE_FLAG_NEEDS_REFRESH       (1 << 7)  // PID map needs refresh
#define RULE_FLAG_DL_EXPLICITLY_BLOCKED (1 << 8)  // Download was explicitly blocked at creation
#define RULE_FLAG_UL_EXPLICITLY_BLOCKED (1 << 9)  // Upload was explicitly blocked at creation
#define RULE_FLAG_HAS_SCHEDULE          (1 << 10)  // Rule has a schedule
#define RULE_FLAG_SCHEDULE_ACTIVE       (1 << 11)  // Schedule is currently active

    double dl_rate;
    double ul_rate;
    int burst;
    PIDEntry *pids;
    TokenBucket *dl_buckets;
    TokenBucket *ul_buckets;

    // Quota tracking fields
    uint64_t quota_in;           // bytes; 0 = unlimited
    uint64_t quota_out;          // bytes; 0 = unlimited

    // Schedule tracking
    Schedule schedule;           // When this rule is active
    time_t last_schedule_check;  // Last time we checked schedule status

    // Live traffic counters – incremented atomically by the packet loop.
    // Reset to zero by shaper_reset_pid_stats().
    volatile LONGLONG dl_bytes;  // bytes passed downstream for this rule
    volatile LONGLONG ul_bytes;  // bytes passed upstream   for this rule
    volatile LONG dl_packets;    // packets passed downstream
    volatile LONG ul_packets;    // packets passed upstream

    UT_hash_handle hh;
} ProcessRule;

// -----------------------------------------------------------------------
// Per-PID / per-rule statistics snapshot
// -----------------------------------------------------------------------
typedef struct {
    DWORD pid;                             // the PID queried (0 = name-based lookup)
    char rule_name[MAX_PROCESS_NAME_LEN];  // rule that matched this PID
    double dl_rate_limit;                  // configured DL limit (bytes/sec)
    double ul_rate_limit;                  // configured UL limit (bytes/sec)
    uint64_t dl_bytes;                     // bytes received since last reset
    uint64_t ul_bytes;                     // bytes sent since last reset
    uint64_t dl_packets;                   // packets received since last reset
    uint64_t ul_packets;                   // packets sent since last reset
    bool has_rule;                         // false if no rule matched this PID
} PidStats;

// -----------------------------------------------------------------------
// Per-PID traffic tracking (all processes, not just ruled ones)
// -----------------------------------------------------------------------
typedef struct PidTraffic {
    DWORD pid;
    volatile LONGLONG dl_bytes;  // Download bytes (inbound)
    volatile LONGLONG ul_bytes;  // Upload bytes (outbound)
    time_t last_active;          // Track last time this PID was seen

    // For activity detection between cleanups
    volatile LONGLONG last_snapshot_dl;  // DL bytes at last cleanup
    volatile LONGLONG last_snapshot_ul;  // UL bytes at last cleanup

    UT_hash_handle hh;
} PidTraffic;

// -----------------------------------------------------------------------
// Statistics snapshot
// -----------------------------------------------------------------------
typedef struct {
    uint64_t packets_processed;
    uint64_t packets_dropped_rate_limit;
    uint64_t packets_dropped_loss;
    uint64_t packets_delayed;
    uint64_t bytes_processed;        // Total bytes processed (including dropped?)
    uint64_t bytes_throttled;        // Bytes that passed through throttle
    uint64_t invalid_packets;
    bool is_running;
    bool cap_reached;
} ShaperStats;

// -----------------------------------------------------------------------
// ShaperInstance - opaque handle returned to callers
// -----------------------------------------------------------------------

typedef struct ShaperInstance ShaperInstance;

// Thread state for introspection (optional but useful for GUI)
typedef enum {
    SHAPER_THREAD_IDLE,      // Created but not started
    SHAPER_THREAD_RUNNING,   // Worker thread active
    SHAPER_THREAD_STOPPING,  // Stop requested, waiting for join
    SHAPER_THREAD_STOPPED    // Joined, can restart or destroy
} ShaperThreadState;

// -----------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------

// Allocate and zero-initialise a shaper instance.
// Returns NULL on allocation failure.
ShaperInstance *shaper_create(void);

// Stop the shaper (if running) and free the instance.
void shaper_destroy(ShaperInstance *shaper);

// -----------------------------------------------------------------------
// Control
// -----------------------------------------------------------------------

// Start packet interception using the supplied parameters.
// Takes ownership of nothing - caller keeps params alive for the duration.
// Returns false and logs an error if startup fails.
bool shaper_start(ShaperInstance *shaper,
                  const ThrottlingParams *params,
                  const ProcessParams *processparams,
                  double download_rate,
                  double upload_rate,
                  unsigned int download_buffer_size,
                  unsigned int upload_buffer_size,
                  unsigned int max_tcp_connections,
                  unsigned int max_udp_packets_per_second,
                  unsigned int latency_ms,
                  float packet_loss,
                  int priority,
                  int burst_size,
                  uint64_t data_cap_bytes,
                  unsigned int quota_check_interval_ms,
                  const Schedule *global_schedule,
                  bool quiet_mode,
                  bool enable_statistics);

// Signal the processing loop to stop and wait for clean shutdown.
void shaper_stop(ShaperInstance *shaper);

// Tear down existing buckets/rules, re-apply new parameters, and resume.
// Equivalent to stop + start but without closing the WinDivert handle.
bool shaper_reload(ShaperInstance *shaper,
                   const ThrottlingParams *params,
                   const ProcessParams *processparams,
                   double download_rate,
                   double upload_rate,
                   unsigned int download_buffer_size,
                   unsigned int upload_buffer_size,
                   unsigned int max_tcp_connections,
                   unsigned int max_udp_packets_per_second,
                   unsigned int latency_ms,
                   float packet_loss,
                   int priority,
                   int burst_size,
                   uint64_t data_cap_bytes,
                   unsigned int quota_check_interval_ms,
                   const Schedule *global_schedule,
                   bool quiet_mode,
                   bool enable_statistics);

// -----------------------------------------------------------------------
// Status / introspection
// -----------------------------------------------------------------------

// Returns true between shaper_start() and shaper_stop().
bool shaper_is_running(const ShaperInstance *shaper);

// Fill *out with an atomic snapshot of current statistics.
void shaper_get_stats(ShaperInstance *shaper, ShaperStats *out);

// Returns the last error string set by the core (never NULL).
const char *shaper_get_last_error(const ShaperInstance *shaper);

// -----------------------------------------------------------------------
// Per-process rule management (called before shaper_start)
// -----------------------------------------------------------------------

// Register a rate rule for a named process or a numeric PID string.
// dl_rate / ul_rate are bytes/sec; 0 means "fall back to global rate".
bool shaper_add_process_rule(ShaperInstance *shaper,
                              const char *identifier,
                              double dl_rate,
                              double ul_rate,
                              bool dl_blocked,
                              bool ul_blocked,
                              uint64_t quota_in,
                              uint64_t quota_out,
                              Schedule *schedule);

// Remove all registered process rules (frees bucket/PID memory).
void shaper_clear_process_rules(ShaperInstance *shaper);

// -----------------------------------------------------------------------
// Per-PID / per-rule statistics
// -----------------------------------------------------------------------

// Enumerate all rules, calling cb(stats, userdata) once per rule.
// The callback receives a filled PidStats with pid=0 for name-based rules
// (the pid field is not meaningful; use rule_name instead).
// Iteration stops early if the callback returns false.
// Thread-safe: takes the instance lock internally.
typedef bool (*ShaperPidStatsCallback)(const PidStats *stats, void *userdata);

// Reset per-rule traffic counters to zero for all rules (or one PID's rule).
// Pass pid=0 to reset every rule at once.
// Thread-safe: takes the instance lock internally.
void shaper_reset_pid_stats(ShaperInstance *shaper, DWORD pid);

// Reload process rules from the rule table without stopping the shaper.
// This allows dynamic rule updates while the shaper is running.
// Returns false if the shaper is not running or an error occurs.
bool shaper_reload_rules(ShaperInstance *shaper);

// -----------------------------------------------------------------------
// Per-PID traffic (tracks ALL processes, not just ruled ones)
// -----------------------------------------------------------------------

// Get traffic counters for any PID, regardless of rules.
// Returns true if PID has been seen (even if counters are zero),
// false if PID not tracked or error.
// Thread-safe: takes the instance lock internally.
bool shaper_get_pid_traffic(ShaperInstance *shaper, DWORD pid, 
                            uint64_t *dl_bytes, uint64_t *ul_bytes);

// Reset per-PID traffic counters. Pass pid=0 to reset all.
// Thread-safe: takes the instance lock internally.
void shaper_reset_pid_traffic(ShaperInstance *shaper, DWORD pid);

// Periodic cleanup function for PID traffic
void shaper_cleanup_pid_traffic(ShaperInstance *shaper, int interval_seconds, int max_age_seconds);
void shaper_periodic_cleanup(ShaperInstance *shaper, int interval_seconds, int max_age_seconds);

// -----------------------------------------------------------------------
// Thread introspection
// -----------------------------------------------------------------------

// Returns current thread state (for GUI status indicators)
ShaperThreadState shaper_get_thread_state(const ShaperInstance *shaper);

// Returns Win32 thread handle, or NULL if not running.
// Caller can WaitForSingleObject() if they want blocking behavior.
// Do not CloseHandle() - owned by the core.
HANDLE shaper_get_thread_handle(const ShaperInstance *shaper);

// -----------------------------------------------------------------------
// Per-process rule management APIs (schedule/quota handling)
// -----------------------------------------------------------------------

// Check if a rule exists for the given identifier (process name or "__PID_<n>__").
// Returns true if found, false otherwise.
// Thread-safe: takes the instance lock internally.
bool shaper_has_process_rule(ShaperInstance *shaper, const char *identifier);

// Remove a specific rule by identifier (process name or "__PID_<n>__").
// Returns true if the rule was found and removed, false otherwise.
// Thread-safe: takes the instance lock internally.
bool shaper_remove_process_rule(ShaperInstance *shaper, const char *identifier);

// Set byte quotas for an existing rule. 
// quota_in/quota_out are in bytes; 0 means no quota for that direction.
// The rule must already exist (use shaper_add_process_rule first).
// Returns true if quotas were set, false if rule not found.
// Thread-safe: takes the instance lock internally.
bool shaper_set_process_quota(ShaperInstance *shaper,
                               const char *identifier,
                               uint64_t quota_in,
                               uint64_t quota_out);

// Get the quota status for a rule.
// Fills *quota_in/out with the configured limits (0 if none),
// and *in_reached/out_reached with enforcement state.
// Returns true if rule found, false otherwise.
// Thread-safe: takes the instance lock internally.
bool shaper_get_process_quota(ShaperInstance *shaper,
                               const char *identifier,
                               uint64_t *quota_in,
                               uint64_t *quota_out,
                               bool *in_reached,
                               bool *out_reached);

// Reset quota enforcement state (e.g., after CLI has handled quota breach).
// Pass clear_counters=true to also zero the dl_bytes/ul_bytes counters.
// Returns true if rule found and reset, false otherwise.
// Thread-safe: takes the instance lock internally.
bool shaper_reset_process_quota(ShaperInstance *shaper,
                                 const char *identifier,
                                 bool clear_counters);

// Get aggregate traffic for all PIDs belonging to a process name.
// Sums traffic across all currently known PIDs for that process.
// Returns true if any PIDs were found and *total_dl/out are filled,
// false if process name not found or no traffic tracked yet.
// Thread-safe: takes the instance lock internally.
bool shaper_get_process_traffic_by_name(ShaperInstance *shaper,
                                         const char *process_name,
                                         uint64_t *total_dl,
                                         uint64_t *total_ul);

// Get the list of all currently tracked PIDs for a process name.
// Caller provides *pid_array (can be NULL to query count) and *count.
// If pid_array is non-NULL, fills up to *count entries and sets *count to actual.
// Returns true if process name found (even with 0 PIDs), false if not found.
// Thread-safe: takes the instance lock internally.
bool shaper_get_process_pids(ShaperInstance *shaper,
                             const char *process_name,
                             DWORD *pid_array,
                             int *count);

// An entry for traffic snapshot
typedef struct TrafficSnapshotEntry {
    DWORD pid;
    uint64_t dl_bytes;
    uint64_t ul_bytes;
} TrafficSnapshotEntry;

// Atomic snapshot of all traffic counters
typedef struct TrafficSnapshot {
    uint64_t timestamp;
    TrafficSnapshotEntry *entries;  // Heap allocated by shaper_snapshot_traffic
    int count;
    int capacity;  // Allocated size
    bool truncated;
} TrafficSnapshot;

// Take an atomic snapshot of all traffic counters
bool shaper_snapshot_traffic(ShaperInstance *shaper, TrafficSnapshot *snapshot);

// Caller must also free snapshot->entries when done
void shaper_free_traffic_snapshot(TrafficSnapshot *snapshot);

#endif // SHAPER_CORE_H
