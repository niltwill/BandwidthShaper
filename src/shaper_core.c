// shaper_core.c
// BandwidthShaper core engine.
//
// Owns:
//   - WinDivert handle lifecycle
//   - Token bucket allocation / teardown
//   - Per-process rule storage and PID resolution
//   - The packet-processing loop (run on the internal worker thread via shaper_packet_loop_internal)
//

// -----------------------------------------------------------------------
// ProcessRule flag documentation
// -----------------------------------------------------------------------
// RULE_FLAG_IS_PID (1 << 0) - Indicates this rule was created from a numeric PID string
//   rather than a process name. This flag is set only in shaper_add_process_rule()
//   and never changes thereafter. It affects behavior in two ways:
//   1. During initial rule creation: PID rules skip process name resolution
//   2. During rule refresh (shaper_reload_rules): PID rules are skipped because
//      their PID maps are static (PIDs don't change their identity)
//
// All other flags control runtime behavior:
//   RULE_FLAG_DL_BLOCKED / RULE_FLAG_UL_BLOCKED - Direction is completely blocked
//   RULE_FLAG_HAS_QUOTA_IN / RULE_FLAG_HAS_QUOTA_OUT - Quotas are configured
//   RULE_FLAG_QUOTA_IN_EXHAUSTED / RULE_FLAG_QUOTA_OUT_EXHAUSTED - Quotas reached
//   RULE_FLAG_NEEDS_REFRESH - PID map needs refresh (name-based rules only)
//   RULE_FLAG_DL_EXPLICITLY_BLOCKED / RULE_FLAG_UL_EXPLICITLY_BLOCKED - Direction was explicitly blocked at creation

#include "common.h"
#include "shaper_core.h"
#include "shaper_utils.h"
#include "token_bucket.h"
#include "pid_cache.h"
#include "schedule.h"

// -----------------------------------------------------------------------
// Defines
// -----------------------------------------------------------------------
// One per typical core
#define PID_CACHE_SHARDS 16

// Maximum temporary PIDs
#define MAX_TEMP_PIDS 256

// Threshold for switching between linear scan and hash table
#define RULE_COUNT_THRESHOLD 32

// Batch statistics thresholds
#define BATCH_THRESHOLD 64      // Flush after 64 packets
#define BATCH_TIMEOUT_MS 10     // Or after 10ms, whichever comes first

// -----------------------------------------------------------------------
// Quiet-mode helper (mirrors original QUIET_PRINTF macro)
// -----------------------------------------------------------------------
#define CORE_PRINTF(shaper, ...) \
    do { if (!(shaper)->quiet_mode) printf(__VA_ARGS__); } while (0)

// -----------------------------------------------------------------------
// ShaperInstance definition
// -----------------------------------------------------------------------

// PID to rule mapping entry
typedef struct PIDToRuleMap {
    DWORD pid;               // Key
    ProcessRule *rule;       // Associated rule
    UT_hash_handle hh;
} PIDToRuleMap;

struct ShaperInstance {
    // runtime state
    bool is_running;  // Worker thread spawned
    volatile bool should_stop;  // Signal to worker thread
    HANDLE windivert_handle;
    HANDLE recv_event;

    // token buckets (one per NIC)
    TokenBucket *download_buckets;
    TokenBucket *upload_buckets;

    // per-process rules (uthash map)
    ProcessRule *rules;
    int rule_count;
    unsigned int rule_refresh_packet_counter;
    clock_t rule_refresh_last_time;

    // flat array for small rule sets
    struct {
        ProcessRule **array;
        int count;
        int capacity;
        CRITICAL_SECTION lock;
        bool initialized;
    } flat_rules;

    // reverse index for O(1) PID -> rule lookup
    struct {
        PIDToRuleMap *pid_to_rule;  // uthash mapping PID -> ProcessRule*
        CRITICAL_SECTION lock;
        bool initialized;
    } reverse_index;

    // PID table cache
    PidTableCache pid_cache;

    // statistics
    PacketStats stats;
    DelayBuffer delay_buffer;

    // batch statistics for reduced atomic overhead
    struct {
        volatile LONG packet_count;
        volatile LONG byte_count_low;   // Low 32 bits of byte count
        volatile LONG byte_count_high;  // High 32 bits of byte count
        volatile LONG packets_dropped_rate_limit;
        volatile LONG packets_dropped_loss;
        volatile LONG packets_delayed;
        volatile LONG invalid_packets;
        ULONGLONG last_flush_tick;
        CRITICAL_SECTION flush_lock;
        bool initialized;
    } batch_stats;

    // data cap
    volatile LONGLONG total_bytes_throttled;
    LONGLONG data_cap_bytes;
    bool cap_reached;

    // sharded PID traffic for reduced lock contention
    PidTraffic *pid_traffic_shards[PID_CACHE_SHARDS];
    CRITICAL_SECTION pid_traffic_locks[PID_CACHE_SHARDS];
    bool pid_traffic_shards_initialized;

    // config snapshot (copied in at start/reload)
    ThrottlingParams params;         // nic_indices/limits owned here
    ProcessParams processparams;     // process_list string owned here
    double download_rate;
    double upload_rate;
    unsigned int download_buffer_size;
    unsigned int upload_buffer_size;
    unsigned int max_tcp_connections;
    unsigned int max_udp_packets_per_second;
    unsigned int latency_ms;
    float packet_loss;
    int priority;
    int burst_size;
    double perf_frequency;
    bool quiet_mode;
    bool enable_statistics;
    // Global schedule (applies to all traffic when no rule matches)
    Schedule global_schedule;
    bool global_schedule_active;
    time_t last_global_schedule_check;
    // Quota check interval (configurable)
    unsigned int quota_check_interval_ms;

    // cleanup configuration
    time_t last_cleanup_time;
    volatile LONG cleanup_in_progress;

    // thread management
    HANDLE worker_thread;            // The background thread handle
    ShaperThreadState thread_state;  // For external state queries
    volatile LONG worker_active;     // Set by worker when loop entered

    // synchronisation
    CRITICAL_SECTION global_lock;
    bool lock_initialized;
    CRITICAL_SECTION rule_update_lock;
    bool rule_update_lock_initialized;

    // error buffer
    char error_buf[512];
};

// Build new PID maps outside lock
typedef struct {
    ProcessRule *rule;
    PIDEntry *new_pid_map;
} PidSwap;

// Snapshot rule names under lock
typedef struct {
	ProcessRule *rule;
	char name[MAX_PROCESS_NAME_LEN];
} RuleNameSnapshot;

// For per-CPU sharding
typedef struct {
    PidTraffic *shard[PID_CACHE_SHARDS];
    CRITICAL_SECTION locks[PID_CACHE_SHARDS];
} ShardedPidTraffic;

// Forward declaration
static DWORD WINAPI shaper_worker_thread(LPVOID param);
static void shaper_packet_loop_internal(ShaperInstance *shaper);
void shaper_update_pid_traffic(ShaperInstance *shaper, DWORD pid, int packet_len, bool outbound);
static bool check_rule_schedule(ProcessRule *rule);
bool shaper_is_global_schedule_active(ShaperInstance *shaper);

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------
static inline LONGLONG core_get_ticks(void) {
    LARGE_INTEGER c; QueryPerformanceCounter(&c); return c.QuadPart;
}

static void set_error(ShaperInstance *s, const char *msg) {
    strncpy(s->error_buf, msg, sizeof(s->error_buf) - 1);
    s->error_buf[sizeof(s->error_buf) - 1] = '\0';
}

// Hash function to distribute PIDs across shards
static inline int pid_shard(DWORD pid) {
    return (int)(((pid * 0x9e3779b9u) >> 28) & (PID_CACHE_SHARDS - 1));
}

// -----------------------------------------------------------------------
// PID-to-rule reverse index helpers
// -----------------------------------------------------------------------
// Update reverse index when adding a PID to a rule
static void add_pid_to_reverse_index(ShaperInstance *shaper, DWORD pid, ProcessRule *rule) {
    if (!shaper->reverse_index.initialized) return;

    EnterCriticalSection(&shaper->reverse_index.lock);

    // Check if PID already mapped
    PIDToRuleMap *entry;
    HASH_FIND(hh, shaper->reverse_index.pid_to_rule, &pid, sizeof(DWORD), entry);

    if (!entry) {
        entry = malloc(sizeof(PIDToRuleMap));
        if (entry) {
            entry->pid = pid;
            entry->rule = rule;
            HASH_ADD(hh, shaper->reverse_index.pid_to_rule, pid, sizeof(DWORD), entry);
        }
    }
    // Note: If PID already mapped to a different rule, we have a conflict
    // This shouldn't happen with proper rule management

    LeaveCriticalSection(&shaper->reverse_index.lock);
}

// Remove PID from reverse index
static void remove_pid_from_reverse_index(ShaperInstance *shaper, DWORD pid) {
    if (!shaper->reverse_index.initialized) return;

    EnterCriticalSection(&shaper->reverse_index.lock);
    PIDToRuleMap *entry;
    HASH_FIND(hh, shaper->reverse_index.pid_to_rule, &pid, sizeof(DWORD), entry);
    if (entry) {
        HASH_DEL(shaper->reverse_index.pid_to_rule, entry);
        free(entry);
    }
    LeaveCriticalSection(&shaper->reverse_index.lock);
}

// Clear all PIDs for a rule from reverse index
static void clear_rule_from_reverse_index(ShaperInstance *shaper, ProcessRule *rule) {
    if (!shaper->reverse_index.initialized || !rule || !rule->pids) return;

    EnterCriticalSection(&shaper->reverse_index.lock);

    // Iterate through all PID mappings and remove those belonging to this rule
    PIDToRuleMap *entry, *tmp;
    HASH_ITER(hh, shaper->reverse_index.pid_to_rule, entry, tmp) {
        if (entry->rule == rule) {
            HASH_DEL(shaper->reverse_index.pid_to_rule, entry);
            free(entry);
        }
    }

    LeaveCriticalSection(&shaper->reverse_index.lock);
}

// Also update the reverse index
static void add_pid_to_rule_map(ShaperInstance *shaper, ProcessRule *rule, int pid) {
    add_pid_to_map_pool(&rule->pids, pid, &g_pid_pool);
    add_pid_to_reverse_index(shaper, (DWORD)pid, rule);
}

// Fast O(1) PID to rule lookup using reverse index
static inline ProcessRule* find_rule_by_pid(ShaperInstance *shaper, DWORD pid) {
    if (!shaper->reverse_index.initialized) return NULL;

    ProcessRule *result = NULL;

    EnterCriticalSection(&shaper->reverse_index.lock);
    PIDToRuleMap *entry;
    HASH_FIND(hh, shaper->reverse_index.pid_to_rule, &pid, sizeof(DWORD), entry);
    if (entry) {
        result = entry->rule;
    }
    LeaveCriticalSection(&shaper->reverse_index.lock);

    return result;
}

// Internal helper that assumes global_lock is held
static int collect_rule_pids_locked(ProcessRule *r, DWORD *pid_array, int max_pids) {
    if (!r || !r->pids) return 0;

    int count = 0;
    PIDEntry *p, *tmp;
    HASH_ITER(hh, r->pids, p, tmp) {
        if (count < max_pids) {
            pid_array[count] = (DWORD)p->pid;
        }
        count++;
    }
    return count;
}

// -----------------------------------------------------------------------
// Batch statistics
// -----------------------------------------------------------------------
// Flush batch statistics to global PacketStats
static void flush_batch_stats(ShaperInstance *shaper) {
    if (!shaper) return;

    EnterCriticalSection(&shaper->batch_stats.flush_lock);

    LONG packets = shaper->batch_stats.packet_count;
    shaper->batch_stats.packet_count = 0;

    ULONGLONG bytes = ((ULONGLONG)shaper->batch_stats.byte_count_high << 32) | 
                       (ULONG)shaper->batch_stats.byte_count_low;
    shaper->batch_stats.byte_count_low = 0;
    shaper->batch_stats.byte_count_high = 0;

    LONG dropped_rate = shaper->batch_stats.packets_dropped_rate_limit;
    shaper->batch_stats.packets_dropped_rate_limit = 0;

    LONG dropped_loss = shaper->batch_stats.packets_dropped_loss;
    shaper->batch_stats.packets_dropped_loss = 0;

    LONG delayed = shaper->batch_stats.packets_delayed;
    shaper->batch_stats.packets_delayed = 0;

    LONG invalid = shaper->batch_stats.invalid_packets;
    shaper->batch_stats.invalid_packets = 0;

    shaper->batch_stats.last_flush_tick = GetTickCount64();

    LeaveCriticalSection(&shaper->batch_stats.flush_lock);

    if (packets > 0) {
        InterlockedAdd(&shaper->stats.packets_processed, packets);
        InterlockedAdd64(&shaper->stats.bytes_processed, bytes);
        InterlockedAdd(&shaper->stats.packets_dropped_rate_limit, dropped_rate);
        InterlockedAdd(&shaper->stats.packets_dropped_loss, dropped_loss);
        InterlockedAdd(&shaper->stats.packets_delayed, delayed);
        InterlockedAdd(&shaper->stats.invalid_packets, invalid);
    }
}

// Update batch statistics (called from packet loop)
static inline void update_batch_stats(ShaperInstance *shaper, int packet_len, 
                                      bool b_dropped_rate, bool b_dropped_loss, 
                                      bool b_delayed, bool b_invalid) {
    EnterCriticalSection(&shaper->batch_stats.flush_lock);

    // Update byte count with proper 64-bit arithmetic
    ULONGLONG current_bytes = ((ULONGLONG)shaper->batch_stats.byte_count_high << 32) | 
                               (ULONG)shaper->batch_stats.byte_count_low;
    current_bytes += packet_len;

    shaper->batch_stats.byte_count_low = (LONG)(current_bytes & 0xFFFFFFFF);
    shaper->batch_stats.byte_count_high = (LONG)(current_bytes >> 32);

    shaper->batch_stats.packet_count++;

    // Update other counters
    if (b_dropped_rate) shaper->batch_stats.packets_dropped_rate_limit++;
    if (b_dropped_loss) shaper->batch_stats.packets_dropped_loss++;
    if (b_delayed) shaper->batch_stats.packets_delayed++;
    if (b_invalid) shaper->batch_stats.invalid_packets++;

    // Check if we should flush
    ULONGLONG now = GetTickCount64();
    if (shaper->batch_stats.packet_count >= BATCH_THRESHOLD || 
        (now - shaper->batch_stats.last_flush_tick) >= BATCH_TIMEOUT_MS) {

        // Capture all counters
        LONG b_packets = shaper->batch_stats.packet_count;
        shaper->batch_stats.packet_count = 0;

        ULONGLONG b_bytes = ((ULONGLONG)shaper->batch_stats.byte_count_high << 32) | 
                           (ULONG)shaper->batch_stats.byte_count_low;
        shaper->batch_stats.byte_count_low = 0;
        shaper->batch_stats.byte_count_high = 0;

        LONG b_dropped_rate = shaper->batch_stats.packets_dropped_rate_limit;
        shaper->batch_stats.packets_dropped_rate_limit = 0;

        LONG b_dropped_loss = shaper->batch_stats.packets_dropped_loss;
        shaper->batch_stats.packets_dropped_loss = 0;

        LONG b_delayed = shaper->batch_stats.packets_delayed;
        shaper->batch_stats.packets_delayed = 0;

        LONG b_invalid = shaper->batch_stats.invalid_packets;
        shaper->batch_stats.invalid_packets = 0;

        shaper->batch_stats.last_flush_tick = now;

        LeaveCriticalSection(&shaper->batch_stats.flush_lock);

        // Update global stats atomically
        if (b_packets > 0) {
            InterlockedAdd(&shaper->stats.packets_processed, b_packets);
            InterlockedAdd64(&shaper->stats.bytes_processed, b_bytes);
            InterlockedAdd(&shaper->stats.packets_dropped_rate_limit, b_dropped_rate);
            InterlockedAdd(&shaper->stats.packets_dropped_loss, b_dropped_loss);
            InterlockedAdd(&shaper->stats.packets_delayed, b_delayed);
            InterlockedAdd(&shaper->stats.invalid_packets, b_invalid);
        }
    } else {
        LeaveCriticalSection(&shaper->batch_stats.flush_lock);
    }
}

// Force flush on shutdown
static void flush_batch_stats_final(ShaperInstance *shaper) {
    if (!shaper) return;
    flush_batch_stats(shaper);
}

// -----------------------------------------------------------------------
// Per-process rule helpers
// -----------------------------------------------------------------------
bool shaper_add_process_rule(ShaperInstance *shaper,
                              const char *identifier,
                              double dl_rate,
                              double ul_rate,
                              bool dl_blocked,
                              bool ul_blocked,
                              uint64_t quota_in,
                              uint64_t quota_out,
                              Schedule *schedule) {
    if (!shaper || !identifier) return false;
    if (dl_rate < 0 || ul_rate < 0) {
        set_error(shaper, "Invalid rate in shaper_add_process_rule");
        return false;
    }

    ProcessRule *r = calloc(1, sizeof(ProcessRule));
    if (!r) { set_error(shaper, "OOM in shaper_add_process_rule"); return false; }

    // Store rates and quotas
    r->dl_rate = dl_rate;
    r->ul_rate = ul_rate;
    r->quota_in = quota_in;
    r->quota_out = quota_out;

    // Set quota flags
    if (quota_in > 0) r->flags |= RULE_FLAG_HAS_QUOTA_IN;
    if (quota_out > 0) r->flags |= RULE_FLAG_HAS_QUOTA_OUT;

    // Set schedule if provided
    if (schedule && !schedule_is_empty(schedule)) {
        r->schedule = *schedule;
        r->flags |= RULE_FLAG_HAS_SCHEDULE;
        r->last_schedule_check = time(NULL);
        
        // Check initial active state
        if (schedule_is_active_now(schedule)) {
            r->flags |= RULE_FLAG_SCHEDULE_ACTIVE;
        }
    } else {
        schedule_init(&r->schedule);
    }

    // Set blocked flags and preserve explicit intent
    if (dl_blocked) {
        r->flags |= RULE_FLAG_DL_BLOCKED;
        r->flags |= RULE_FLAG_DL_EXPLICITLY_BLOCKED;
    }
    if (ul_blocked) {
        r->flags |= RULE_FLAG_UL_BLOCKED;
        r->flags |= RULE_FLAG_UL_EXPLICITLY_BLOCKED;
    }

    // Determine if identifier is a pure numeric PID
    bool is_pid = true;
    for (const char *c = identifier; *c; c++) {
        if (!isdigit((unsigned char)*c)) { is_pid = false; break; }
    }

    if (is_pid) {
        int pid = atoi(identifier);
        if (pid <= 0) {
            set_error(shaper, "Invalid PID in shaper_add_process_rule");
            free(r); return false;
        }
        snprintf(r->name, sizeof(r->name), "__PID_%d__", pid);
        add_pid_to_map_pool(&r->pids, pid, &g_pid_pool);
        add_pid_to_reverse_index(shaper, (DWORD)pid, r);
        r->flags |= RULE_FLAG_IS_PID;

        CORE_PRINTF(shaper, "PID rule: %d | DL %.2f MB/s UL %.2f MB/s | Quota: IN=%llu OUT=%llu | Schedule: %s\n",
                    pid, dl_rate / 1e6, ul_rate / 1e6, 
                    (unsigned long long)quota_in, (unsigned long long)quota_out,
                    (r->flags & RULE_FLAG_HAS_SCHEDULE) ? "yes" : "no");
    } else {
        strncpy(r->name, identifier, sizeof(r->name) - 1);
        r->name[sizeof(r->name) - 1] = '\0';
        CORE_PRINTF(shaper, "Rule: %s | DL %.2f MB/s UL %.2f MB/s | Quota: IN=%llu OUT=%llu | Schedule: %s\n",
                    identifier, dl_rate / 1e6, ul_rate / 1e6,
                    (unsigned long long)quota_in, (unsigned long long)quota_out,
                    (r->flags & RULE_FLAG_HAS_SCHEDULE) ? "yes" : "no");
    }

    r->burst = shaper->burst_size;
    HASH_ADD_KEYPTR(hh, shaper->rules, r->name, strlen(r->name), r);
    shaper->rule_count++;

    // Add to flat array for small-set optimization
    EnterCriticalSection(&shaper->flat_rules.lock);
    if (shaper->flat_rules.count >= shaper->flat_rules.capacity) {
        int new_cap = shaper->flat_rules.capacity == 0 ? 16 : shaper->flat_rules.capacity * 2;
        ProcessRule **new_array = realloc(shaper->flat_rules.array, 
                                         new_cap * sizeof(ProcessRule *));
        if (new_array) {
            shaper->flat_rules.array = new_array;
            shaper->flat_rules.capacity = new_cap;
        }
    }
    if (shaper->flat_rules.count < shaper->flat_rules.capacity) {
        shaper->flat_rules.array[shaper->flat_rules.count++] = r;
    }
    LeaveCriticalSection(&shaper->flat_rules.lock);

    return true;
}

void shaper_clear_process_rules(ShaperInstance *shaper) {
    if (!shaper) return;

    // First acquire locks in correct order
    EnterCriticalSection(&shaper->global_lock);
    EnterCriticalSection(&shaper->reverse_index.lock);
    EnterCriticalSection(&shaper->flat_rules.lock);

    // Clear flat array
    free(shaper->flat_rules.array);
    shaper->flat_rules.array = NULL;
    shaper->flat_rules.count = 0;
    shaper->flat_rules.capacity = 0;

    // Clear reverse index
    PIDToRuleMap *entry, *tmp;
    HASH_ITER(hh, shaper->reverse_index.pid_to_rule, entry, tmp) {
        HASH_DEL(shaper->reverse_index.pid_to_rule, entry);
        free(entry);
    }

    // Clear rules
    ProcessRule *r, *rtmp;
    HASH_ITER(hh, shaper->rules, r, rtmp) {
        HASH_DEL(shaper->rules, r);
        free_pid_map_pool(r->pids, &g_pid_pool);
        if (r->dl_buckets) {
            for (int i = 0; i < shaper->params.nic_count; i++)
                token_bucket_destroy(&r->dl_buckets[i]);
            free(r->dl_buckets);
        }
        if (r->ul_buckets) {
            for (int i = 0; i < shaper->params.nic_count; i++)
                token_bucket_destroy(&r->ul_buckets[i]);
            free(r->ul_buckets);
        }
        free(r);
    }
    shaper->rules = NULL;
    shaper->rule_count = 0;

    // Release locks in reverse order
    LeaveCriticalSection(&shaper->flat_rules.lock);
    LeaveCriticalSection(&shaper->reverse_index.lock);
    LeaveCriticalSection(&shaper->global_lock);
}

// -----------------------------------------------------------------------
// Bucket initialisation / teardown
// -----------------------------------------------------------------------
static void destroy_global_buckets(ShaperInstance *s) {
    if (s->download_buckets) {
        for (int i = 0; i < s->params.nic_count; i++)
            token_bucket_destroy(&s->download_buckets[i]);
        free(s->download_buckets);
        s->download_buckets = NULL;
    }
    if (s->upload_buckets) {
        for (int i = 0; i < s->params.nic_count; i++)
            token_bucket_destroy(&s->upload_buckets[i]);
        free(s->upload_buckets);
        s->upload_buckets = NULL;
    }
}

// Apply the global download_rate to any NIC that has no per-NIC override,
// then allocate and initialise all buckets.  Returns false on failure.
static bool init_global_buckets(ShaperInstance *s) {
    s->download_buckets = malloc(s->params.nic_count * sizeof(TokenBucket));
    s->upload_buckets = malloc(s->params.nic_count * sizeof(TokenBucket));
    if (!s->download_buckets || !s->upload_buckets) {
        set_error(s, "OOM allocating token buckets");
        destroy_global_buckets(s);
        return false;
    }
    // Zero so token_bucket_destroy is safe even on partially-inited arrays
    memset(s->download_buckets, 0, s->params.nic_count * sizeof(TokenBucket));
    memset(s->upload_buckets, 0, s->params.nic_count * sizeof(TokenBucket));

    for (int i = 0; i < (int)s->params.nic_count; i++) {
        if (s->params.download_limits[i] == 0) s->params.download_limits[i] = s->download_rate;
        if (s->params.upload_limits[i] == 0) s->params.upload_limits[i] = s->upload_rate;

        if (s->params.download_limits[i] > 0) {
            int burst = s->burst_size > 0 ? s->burst_size : (int)s->download_buffer_size;
            if (!token_bucket_init(&s->download_buckets[i], s->params.download_limits[i], burst)) {
                char msg[128]; snprintf(msg, sizeof(msg), "Failed to init download bucket %d", i);
                set_error(s, msg); destroy_global_buckets(s); return false;
            }
        }
        if (s->params.upload_limits[i] > 0) {
            int burst = s->burst_size > 0 ? s->burst_size : (int)s->upload_buffer_size;
            if (!token_bucket_init(&s->upload_buckets[i], s->params.upload_limits[i], burst)) {
                char msg[128]; snprintf(msg, sizeof(msg), "Failed to init upload bucket %d", i);
                set_error(s, msg); destroy_global_buckets(s); return false;
            }
        }
    }
    return true;
}

// Allocate per-NIC buckets for all rules, resolve name→PID if needed.
static bool init_rule_buckets(ShaperInstance *s) {
    ProcessRule *r, *tmp;
    HASH_ITER(hh, s->rules, r, tmp) {
        // Only allocate buckets for directions that are NOT blocked
        if (!(r->flags & RULE_FLAG_DL_BLOCKED)) {
            r->dl_buckets = calloc(s->params.nic_count, sizeof(TokenBucket));
            if (!r->dl_buckets) {
                set_error(s, "OOM allocating per-rule DL buckets");
                return false;
            }
        }

        if (!(r->flags & RULE_FLAG_UL_BLOCKED)) {
            r->ul_buckets = calloc(s->params.nic_count, sizeof(TokenBucket));
            if (!r->ul_buckets) {
                set_error(s, "OOM allocating per-rule UL buckets");
                return false;
            }
        }

        // Resolve name-based rules on first start
        if (!(r->flags & RULE_FLAG_IS_PID)) {
            free_pid_map_pool(r->pids, &g_pid_pool); r->pids = NULL;
            int *list = NULL;
            int count = get_pids_from_name(r->name, &list);
            for (int j = 0; j < count; j++) {
                add_pid_to_map_pool(&r->pids, list[j], &g_pid_pool);
                add_pid_to_reverse_index(s, (DWORD)list[j], r);
            }
            if (list) free(list);
        }

        for (int n = 0; n < (int)s->params.nic_count; n++) {
            // Handle download direction if not blocked
            if (!(r->flags & RULE_FLAG_DL_BLOCKED)) {
                double dl = r->dl_rate > 0 ? r->dl_rate : s->download_rate;

                // Clamp to global limits
                if (s->params.download_limits[n] > 0) {
                    if (dl > s->params.download_limits[n]) {
                        dl = s->params.download_limits[n];
                    }
                } else if (s->download_rate > 0) {
                    if (dl > s->download_rate) {
                        dl = s->download_rate;
                    }
                }

                int burst = r->burst > 0 ? r->burst : DEFAULT_DL_BUFFER;

                // Only initialize bucket if rate > 0
                if (dl > 0) {
                    if (!token_bucket_init(&r->dl_buckets[n], dl, burst)) {
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Failed to init rule DL bucket for %s", r->name);
                        set_error(s, msg);
                        return false;
                    }
                }
            }

            // Handle upload direction if not blocked
            if (!(r->flags & RULE_FLAG_UL_BLOCKED)) {
                double ul = r->ul_rate > 0 ? r->ul_rate : s->upload_rate;

                // Clamp to global limits
                if (s->params.upload_limits[n] > 0) {
                    if (ul > s->params.upload_limits[n]) {
                        ul = s->params.upload_limits[n];
                    }
                } else if (s->upload_rate > 0) {
                    if (ul > s->upload_rate) {
                        ul = s->upload_rate;
                    }
                }

                int burst = r->burst > 0 ? r->burst : DEFAULT_DL_BUFFER;

                // Only initialize bucket if rate > 0
                if (ul > 0) {
                    if (!token_bucket_init(&r->ul_buckets[n], ul, burst)) {
                        char msg[256];
                        snprintf(msg, sizeof(msg), "Failed to init rule UL bucket for %s", r->name);
                        set_error(s, msg);
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

// -----------------------------------------------------------------------
// Config snapshot helpers
// -----------------------------------------------------------------------
// Deep-copy *src into shaper's params (allocates nic_indices / limits)
static bool copy_throttling_params(ShaperInstance *s, const ThrottlingParams *src) {
    // Free previous arrays
    free(s->params.nic_indices);
    free(s->params.download_limits);
    free(s->params.upload_limits);

    s->params.nic_count = src->nic_count;

    if (src->nic_count == 0) {
        s->params.nic_indices = NULL;
        s->params.download_limits = NULL;
        s->params.upload_limits = NULL;
        return true;
    }

    s->params.nic_indices = (unsigned int*)malloc(src->nic_count * sizeof(unsigned int));
    s->params.download_limits = (double*)malloc(src->nic_count * sizeof(double));
    s->params.upload_limits = (double*)malloc(src->nic_count * sizeof(double));

    if (!s->params.nic_indices || !s->params.download_limits || !s->params.upload_limits) {
        set_error(s, "OOM copying ThrottlingParams");
        free(s->params.nic_indices);
        free(s->params.download_limits);
        free(s->params.upload_limits);
        s->params.nic_indices = NULL;
        s->params.download_limits = NULL;
        s->params.upload_limits = NULL;
        return false;
    }

    memcpy(s->params.nic_indices, src->nic_indices, src->nic_count * sizeof(unsigned int));
    memcpy(s->params.download_limits, src->download_limits, src->nic_count * sizeof(double));
    memcpy(s->params.upload_limits, src->upload_limits, src->nic_count * sizeof(double));
    return true;
}

static bool copy_throttling_params_safe(ThrottlingParams *dst, const ThrottlingParams *src) {
    memset(dst, 0, sizeof(*dst));
    dst->nic_count = src->nic_count;

    if (src->nic_count == 0) return true;

    dst->nic_indices = malloc(src->nic_count * sizeof(unsigned int));
    dst->download_limits = malloc(src->nic_count * sizeof(double));
    dst->upload_limits = malloc(src->nic_count * sizeof(double));

    if (!dst->nic_indices || !dst->download_limits || !dst->upload_limits) {
        free(dst->nic_indices);
        free(dst->download_limits);
        free(dst->upload_limits);
        return false;
    }

    memcpy(dst->nic_indices, src->nic_indices, src->nic_count * sizeof(unsigned int));
    memcpy(dst->download_limits, src->download_limits, src->nic_count * sizeof(double));
    memcpy(dst->upload_limits, src->upload_limits, src->nic_count * sizeof(double));
    return true;
}

// Deep-copy processparams (only process_list string; PID map rebuilt separately)
static bool copy_process_params(ShaperInstance *s, const ProcessParams *src) {
    free(s->processparams.process_list);
    s->processparams = *src;  // shallow copy first (copies scalars)
    s->processparams.pid_map = NULL;  // will be rebuilt
    s->processparams.connection_rates = NULL;
    s->processparams.process_list = NULL;
    if (src->process_list) {
        s->processparams.process_list = strdup(src->process_list);
        if (!s->processparams.process_list) {
            set_error(s, "OOM copying process_list"); return false;
        }
    }
    return true;
}

static bool copy_process_params_safe(ProcessParams *dst, const ProcessParams *src) {
    memset(dst, 0, sizeof(*dst));

    // Copy scalar values
    dst->packet_threshold = src->packet_threshold;
    dst->time_threshold_ms = src->time_threshold_ms;
    dst->min_update_interval_ms = src->min_update_interval_ms;
    dst->packet_count = src->packet_count;
    dst->last_update_time = src->last_update_time;
    dst->last_actual_update = src->last_actual_update;
    dst->needs_update = src->needs_update;

    // These should be NULL in a safe copy - they'll be rebuilt later
    dst->pid_map = NULL;
    dst->connection_rates = NULL;
    dst->process_list = NULL;

    // Deep copy process_list string if present
    if (src->process_list) {
        dst->process_list = strdup(src->process_list);
        if (!dst->process_list) {
            return false;
        }
    }

    return true;
}

// Also need a cleanup function for the safe copy
static void cleanup_throttling_params_safe(ThrottlingParams *params) {
    free(params->nic_indices);
    free(params->download_limits);
    free(params->upload_limits);
    memset(params, 0, sizeof(*params));
}

static void cleanup_process_params_safe(ProcessParams *params) {
    free(params->process_list);
    // Don't free pid_map or connection_rates - they're not owned by safe copy
    memset(params, 0, sizeof(*params));
}

// -----------------------------------------------------------------------
// Public lifecycle
// -----------------------------------------------------------------------
ShaperInstance *shaper_create(void) {
    ShaperInstance *s = calloc(1, sizeof(ShaperInstance));
    if (!s) return NULL;
    s->windivert_handle = INVALID_HANDLE_VALUE;
    s->error_buf[0] = '\0';

    // Initialize global PID pool
    pid_pool_init_once(&g_pid_pool, 128);

    // Initialize update lock
    if (!InitializeCriticalSectionAndSpinCount(&s->rule_update_lock, 4000)) {
        free(s);
        return NULL;
    }
    s->rule_update_lock_initialized = true;

    // Initialize batch stats
    if (!InitializeCriticalSectionAndSpinCount(&s->batch_stats.flush_lock, 4000)) {
        free(s);
        return NULL;
    }
    s->batch_stats.initialized = true;
    s->batch_stats.last_flush_tick = GetTickCount64();

    // Initialize flat rules
    if (!InitializeCriticalSectionAndSpinCount(&s->flat_rules.lock, 4000)) {
        DeleteCriticalSection(&s->batch_stats.flush_lock);
        free(s);
        return NULL;
    }
    s->flat_rules.initialized = true;

    // Initialize reverse index
    if (!InitializeCriticalSectionAndSpinCount(&s->reverse_index.lock, 4000)) {
        // Clean up existing locks
        DeleteCriticalSection(&s->flat_rules.lock);
        DeleteCriticalSection(&s->batch_stats.flush_lock);
        free(s);
        return NULL;
    }
    s->reverse_index.initialized = true;
    s->reverse_index.pid_to_rule = NULL;

    // Initialize sharded PID traffic
    for (int i = 0; i < PID_CACHE_SHARDS; i++) {
        s->pid_traffic_shards[i] = NULL;
        if (!InitializeCriticalSectionAndSpinCount(&s->pid_traffic_locks[i], 4000)) {
            // Clean up already initialized locks
            DeleteCriticalSection(&s->flat_rules.lock);
            DeleteCriticalSection(&s->batch_stats.flush_lock);
            for (int j = 0; j < i; j++) {
                DeleteCriticalSection(&s->pid_traffic_locks[j]);
            }
            free(s);
            return NULL;
        }
    }
    s->pid_traffic_shards_initialized = true;

    return s;
}

void shaper_destroy(ShaperInstance *shaper) {
    if (!shaper) return;
    if (shaper->is_running) shaper_stop(shaper);
    if (shaper->batch_stats.initialized) DeleteCriticalSection(&shaper->batch_stats.flush_lock);
    if (shaper->lock_initialized) DeleteCriticalSection(&shaper->global_lock);
    if (shaper->rule_update_lock_initialized) DeleteCriticalSection(&shaper->rule_update_lock);

    // Clean up small rule sets
    if (shaper->flat_rules.initialized) {
        DeleteCriticalSection(&shaper->flat_rules.lock);
        free(shaper->flat_rules.array);
    }

    // Clean up reverse index
    if (shaper->reverse_index.initialized) {
        PIDToRuleMap *entry, *tmp;
        HASH_ITER(hh, shaper->reverse_index.pid_to_rule, entry, tmp) {
            HASH_DEL(shaper->reverse_index.pid_to_rule, entry);
            free(entry);
        }
        DeleteCriticalSection(&shaper->reverse_index.lock);
    }

    // Clean up sharded PID traffic
    if (shaper->pid_traffic_shards_initialized) {
        for (int i = 0; i < PID_CACHE_SHARDS; i++) {
            if (shaper->pid_traffic_shards[i]) {
                PidTraffic *pt, *ptmp;
                HASH_ITER(hh, shaper->pid_traffic_shards[i], pt, ptmp) {
                    HASH_DEL(shaper->pid_traffic_shards[i], pt);
                    free(pt);
                }
            }
            DeleteCriticalSection(&shaper->pid_traffic_locks[i]);
        }
        shaper->pid_traffic_shards_initialized = false;
    }

    // Free arrays
    free(shaper->params.nic_indices);
    free(shaper->params.download_limits);
    free(shaper->params.upload_limits);

    // Free process list and PID map
    free(shaper->processparams.process_list);
	if (shaper->processparams.pid_map) {
        free_pid_map_pool(shaper->processparams.pid_map, &g_pid_pool);
    }

    pid_pool_cleanup_global();
    free(shaper);
}

// -----------------------------------------------------------------------
// shaper_start - internal worker thread
// -----------------------------------------------------------------------
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
                  bool enable_statistics) {
    if (!shaper) return false;
    if (shaper->is_running) { set_error(shaper, "Already running"); return false; }

    // Prevent restart if thread is still cleaning up
    if (shaper->thread_state == SHAPER_THREAD_STOPPING) {
        set_error(shaper, "Previous stop still in progress");
        return false;
    }

    // Snapshot config
    if (!copy_throttling_params(shaper, params)) return false;
    if (!copy_process_params(shaper, processparams)) return false;

    shaper->download_rate = download_rate;
    shaper->upload_rate = upload_rate;
    shaper->download_buffer_size = download_buffer_size;
    shaper->upload_buffer_size = upload_buffer_size;
    shaper->max_tcp_connections = max_tcp_connections;
    shaper->max_udp_packets_per_second = max_udp_packets_per_second;
    shaper->latency_ms = latency_ms;
    shaper->packet_loss = packet_loss;
    shaper->priority = priority;
    shaper->burst_size = burst_size;
    shaper->data_cap_bytes = (LONGLONG)data_cap_bytes;
    shaper->cap_reached = false;
    shaper->total_bytes_throttled = 0;

    // Store global schedule
    if (global_schedule && !schedule_is_empty(global_schedule)) {
        shaper->global_schedule = *global_schedule;
        shaper->global_schedule_active = schedule_is_active_now(global_schedule);
    } else {
        schedule_init(&shaper->global_schedule);
        shaper->global_schedule_active = true;  // Always active if no schedule
    }
    shaper->last_global_schedule_check = time(NULL);
 
    // Store quota check interval
    shaper->quota_check_interval_ms = quota_check_interval_ms > 0 ? 
                                       quota_check_interval_ms : 15000;

    // Performance counter
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    shaper->perf_frequency = (double)freq.QuadPart;

    // PID cache
    pid_cache_init(&shaper->pid_cache, 100.0, shaper->perf_frequency); // 100ms TTL

    // Critical section
    if (!shaper->lock_initialized) {
        if (!InitializeCriticalSectionAndSpinCount(&shaper->global_lock, 4000)) {
            set_error(shaper, "Failed to initialize critical section");
            return false;
        }
        shaper->lock_initialized = true;
    }

    // Delay buffer
    if (!delay_buffer_init(&shaper->delay_buffer, DELAY_BUFFER_SIZE)) {
        set_error(shaper, "Failed to initialize delay buffer");
        return false;
    }

    // Stats
    memset(&shaper->stats, 0, sizeof(shaper->stats));
    shaper->stats.last_stats_update = core_get_ticks();

    // Global token buckets
    if (!init_global_buckets(shaper)) return false;

    // Per-process rule buckets + PID resolution
    if (!init_rule_buckets(shaper)) {
        destroy_global_buckets(shaper);
        return false;
    }

    // Initial PID map population (--process)
    if (shaper->processparams.process_list) {
        char *copy = strdup(shaper->processparams.process_list);
        if (copy) {
            int count = 0;
            char **procs = parse_processes(copy, &count);
            free(copy);
            for (int i = 0; i < count; i++) {
                int *pid_list = NULL;
                int pid_count = get_pids_from_name(procs[i], &pid_list);
                if (pid_count > 0) {
                    for (int j = 0; j < pid_count; j++)
                        add_pid_to_map_pool(&shaper->processparams.pid_map, pid_list[j], &g_pid_pool);
                } else {
                    fprintf(stderr, "Warning: No PIDs found for process '%s'\n", procs[i]);
                }
                if (pid_list) free(pid_list);
                free(procs[i]);
            }
            free(procs);
        }
    }

    // Open WinDivert
    shaper->windivert_handle = WinDivertOpen(
        "tcp or udp", WINDIVERT_LAYER_NETWORK, priority, 0);

    if (shaper->windivert_handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char  msg[256];
        switch (err) {
            case 2:    snprintf(msg, sizeof(msg), "WinDivert driver files not found (error 2)"); break;
            case 5:    snprintf(msg, sizeof(msg), "Permission denied - run as Administrator (error 5)"); break;
            case 87:   snprintf(msg, sizeof(msg), "Invalid WinDivert filter / parameter (error 87)"); break;
            case 577:  snprintf(msg, sizeof(msg), "WinDivert driver signature invalid (error 577)"); break;
            case 1058: snprintf(msg, sizeof(msg), "Stale WinDivert instance - restart required (error 1058)"); break;
            case 1275: snprintf(msg, sizeof(msg), "WinDivert driver blocked - bitness mismatch? (error 1275)"); break;
            case 1753: snprintf(msg, sizeof(msg), "Base Filtering Engine service not running (error 1753)"); break;
            default:   snprintf(msg, sizeof(msg), "WinDivertOpen failed: %lu", err); break;
        }
        set_error(shaper, msg);
        destroy_global_buckets(shaper);
        delay_buffer_cleanup(&shaper->delay_buffer);
        return false;
    }

    // Pre-allocate recv_event in the instance
    shaper->recv_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!shaper->recv_event) {
        set_error(shaper, "Failed to create recv event");
        WinDivertClose(shaper->windivert_handle);
        shaper->windivert_handle = INVALID_HANDLE_VALUE;
        return false;
    }

    // Reset control state
    shaper->should_stop = FALSE;
    shaper->worker_active = 0;
    shaper->rule_refresh_packet_counter = 0;
    shaper->rule_refresh_last_time = 0;

    // Spawn worker thread
    shaper->worker_thread = CreateThread(
        NULL, 0,
        shaper_worker_thread,
        shaper,
        0, NULL);

    if (!shaper->worker_thread) {
        set_error(shaper, "Failed to create worker thread");
        // Clean up everything shaper_start() opened
        WinDivertClose(shaper->windivert_handle);
        shaper->windivert_handle = INVALID_HANDLE_VALUE;
        CloseHandle(shaper->recv_event);
        shaper->recv_event = NULL;
        delay_buffer_cleanup(&shaper->delay_buffer);
        destroy_global_buckets(shaper);
        shaper_clear_process_rules(shaper);
        shaper->thread_state = SHAPER_THREAD_IDLE;
        return false;
    }

    shaper->thread_state = SHAPER_THREAD_RUNNING;
    shaper->is_running = true;

    // Optional: wait a brief moment to confirm thread started
    // Sleep(50);
    // if (!shaper->worker_active) { /* handle startup failure */ }

    return true;
}

// -----------------------------------------------------------------------
// shaper_stop
// -----------------------------------------------------------------------
void shaper_stop(ShaperInstance *shaper) {
    if (!shaper || !shaper->is_running) return;

    // Prevent re-entry / concurrent stop
    if (shaper->thread_state == SHAPER_THREAD_STOPPING) {
        // Already stopping, just wait
        if (shaper->worker_thread) {
            WaitForSingleObject(shaper->worker_thread, INFINITE);
        }
        return;
    }

    shaper->thread_state = SHAPER_THREAD_STOPPING;

    // Signal worker to exit
    InterlockedExchange((LONG *)&shaper->should_stop, TRUE);

    // Close the handle first - this unblocks WinDivertRecvEx
    HANDLE old_handle = (HANDLE)InterlockedExchangePointer(
        (void**)&shaper->windivert_handle, INVALID_HANDLE_VALUE);
    if (old_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(old_handle);
    }

    // Now the worker will exit promptly, so a short timeout is enough
    if (shaper->worker_thread) {
        WaitForSingleObject(shaper->worker_thread, 2000);
        CloseHandle(shaper->worker_thread);
        shaper->worker_thread = NULL;
    }

    // Close recv_event after worker is done with it
    if (shaper->recv_event) {
        CloseHandle(shaper->recv_event);
        shaper->recv_event = NULL;
    }

    // Cleanup the delay buffer (shaper_packet_loop_internal() already does delay_buffer_process())
    delay_buffer_cleanup(&shaper->delay_buffer);

    // Final flush of any remaining batch stats
    flush_batch_stats_final(shaper);

    print_statistics(shaper->enable_statistics, &shaper->stats);
    cleanup_rate_limits(&shaper->processparams, &shaper->global_lock);
    shaper_clear_process_rules(shaper);
    destroy_global_buckets(shaper);
    pid_cache_cleanup(&shaper->pid_cache);

    // Reset data-cap state
    shaper->cap_reached = false;
    shaper->total_bytes_throttled = 0;

    shaper->is_running = false;
    shaper->thread_state = SHAPER_THREAD_STOPPED;
}

// -----------------------------------------------------------------------
// shaper_reload
// -----------------------------------------------------------------------
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
                   bool enable_statistics) {
    if (!shaper) return false;
    if (!shaper->is_running) {
        set_error(shaper, "Cannot reload: not running");
        return false;
    }
    CORE_PRINTF(shaper, "\nReloading configuration (brief interruption)...\n");

    // Close handle first to immediately unblock the worker
    HANDLE old_handle = (HANDLE)InterlockedExchangePointer(
        (void**)&shaper->windivert_handle, INVALID_HANDLE_VALUE);
    if (old_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(old_handle);
    }

    // Signal stop and join worker
    InterlockedExchange((LONG*)&shaper->should_stop, TRUE);
    WaitForSingleObject(shaper->worker_thread, 2000);
    CloseHandle(shaper->worker_thread);
    shaper->worker_thread = NULL;

    shaper->thread_state = SHAPER_THREAD_STOPPED;
    InterlockedExchange(&shaper->worker_active, 0);

    // Save old state before destroying anything
    ThrottlingParams old_params;
    ProcessParams old_processparams;
    Schedule old_global_schedule = shaper->global_schedule;
    bool old_global_active = shaper->global_schedule_active;
    unsigned int old_quota_interval = shaper->quota_check_interval_ms;

    // Deep copy old params for potential rollback
    if (!copy_throttling_params_safe(&old_params, &shaper->params) ||
        !copy_process_params_safe(&old_processparams, &shaper->processparams)) {
        set_error(shaper, "Failed to backup old state during reload");
        return false;
    }

    // Now tear down existing state
    destroy_global_buckets(shaper);
    shaper_clear_process_rules(shaper);
    cleanup_rate_limits(&shaper->processparams, &shaper->global_lock);
    free_pid_map_pool(shaper->processparams.pid_map, &g_pid_pool);
    shaper->processparams.pid_map = NULL;

    // Reset data-cap state
    shaper->cap_reached = false;
    shaper->total_bytes_throttled = 0;
    shaper->data_cap_bytes = (LONGLONG)data_cap_bytes;

    // Store new global schedule and quota interval
    if (global_schedule && !schedule_is_empty(global_schedule)) {
        shaper->global_schedule = *global_schedule;
        shaper->global_schedule_active = schedule_is_active_now(global_schedule);
    } else {
        schedule_init(&shaper->global_schedule);
        shaper->global_schedule_active = true;  // Always active if no schedule
    }
    shaper->last_global_schedule_check = time(NULL);
    
    // Store quota check interval (default to 15000ms if not specified)
    shaper->quota_check_interval_ms = quota_check_interval_ms > 0 ? 
                                       quota_check_interval_ms : 15000;

    // Try to apply new config
    bool copy_ok = copy_throttling_params(shaper, params) &&
                   copy_process_params(shaper, processparams);

    if (!copy_ok) {
        // Restore old state
        CORE_PRINTF(shaper, "Reload failed - restoring previous configuration\n");

        // Restore throttling params
        free(shaper->params.nic_indices);
        free(shaper->params.download_limits);
        free(shaper->params.upload_limits);
        shaper->params = old_params;

        // Restore process params
        free(shaper->processparams.process_list);
        shaper->processparams = old_processparams;

        // Restore global schedule and quota interval
        shaper->global_schedule = old_global_schedule;
        shaper->global_schedule_active = old_global_active;
        shaper->quota_check_interval_ms = old_quota_interval;

        // Re-initialize with old params
        if (!init_global_buckets(shaper) || !init_rule_buckets(shaper)) {
            set_error(shaper, "Fatal: Failed to restore old config after reload failure");
            shaper->is_running = false;
            return false;
        }

        set_error(shaper, "Reload failed - configuration unchanged");
        return false;
    }

    // Free old backup (since we successfully applied new config)
    cleanup_throttling_params_safe(&old_params);
    cleanup_process_params_safe(&old_processparams);

    shaper->download_rate = download_rate;
    shaper->upload_rate = upload_rate;
    shaper->download_buffer_size = download_buffer_size;
    shaper->upload_buffer_size = upload_buffer_size;
    shaper->max_tcp_connections = max_tcp_connections;
    shaper->max_udp_packets_per_second = max_udp_packets_per_second;
    shaper->latency_ms = latency_ms;
    shaper->packet_loss = packet_loss;
    shaper->priority = priority;
    shaper->burst_size = burst_size;
    shaper->quiet_mode = quiet_mode;
    shaper->enable_statistics = enable_statistics;

    if (shaper->params.nic_count == 0) {
        set_error(shaper, "Reload error: no NICs specified");
        return false;
    }

    if (!init_global_buckets(shaper)) return false;
    if (!init_rule_buckets(shaper)) { destroy_global_buckets(shaper); return false; }

    // Re-populate PID map
    if (shaper->processparams.process_list)
        update_pid_map(&shaper->processparams, &shaper->pid_cache);

    // Reset control state
    shaper->should_stop = FALSE;
    shaper->rule_refresh_packet_counter = 0;
    shaper->rule_refresh_last_time = 0;

    // Log schedule change (simplified, without schedule_describe)
    if (memcmp(&old_global_schedule, &shaper->global_schedule, sizeof(Schedule)) != 0) {
        CORE_PRINTF(shaper, "Global schedule updated (new schedule applied)\n");
    }

    if (old_quota_interval != shaper->quota_check_interval_ms) {
        CORE_PRINTF(shaper, "Quota check interval changed: %u ms -> %u ms\n",
                    old_quota_interval, shaper->quota_check_interval_ms);
    }

    // Re-open WinDivert with the (potentially new) priority
    shaper->windivert_handle = WinDivertOpen(
        "tcp or udp", WINDIVERT_LAYER_NETWORK, shaper->priority, 0);
    if (shaper->windivert_handle == INVALID_HANDLE_VALUE) {
        set_error(shaper, "Failed to re-open WinDivert after reload");
        shaper->is_running = false;
        shaper->thread_state = SHAPER_THREAD_IDLE;
        return false;
    }

    // Pre-allocate recv_event in the instance
    shaper->recv_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!shaper->recv_event) {
        set_error(shaper, "Failed to create recv event");
        WinDivertClose(shaper->windivert_handle);
        shaper->windivert_handle = INVALID_HANDLE_VALUE;
        shaper->is_running = false;
        shaper->thread_state = SHAPER_THREAD_IDLE;
        return false;
    }

    // Restart worker thread
    shaper->worker_thread = CreateThread(
        NULL, 0,
        shaper_worker_thread,
        shaper,
        0, NULL);

    if (!shaper->worker_thread) {
        set_error(shaper, "Failed to recreate worker thread after reload");
        WinDivertClose(shaper->windivert_handle);
        shaper->windivert_handle = INVALID_HANDLE_VALUE;
        CloseHandle(shaper->recv_event);
        shaper->recv_event = NULL;
        shaper->is_running = false;
        shaper->thread_state = SHAPER_THREAD_IDLE;
        return false;
    }
    shaper->thread_state = SHAPER_THREAD_RUNNING;

    CORE_PRINTF(shaper, "Reload complete.\n");
    return true;
}

// -----------------------------------------------------------------------
// Worker thread procedure
// -----------------------------------------------------------------------
static DWORD WINAPI shaper_worker_thread(LPVOID param) {
    ShaperInstance *shaper = (ShaperInstance*)param;
    
    // Signal that we're active
    InterlockedExchange(&shaper->worker_active, 1);
    shaper->thread_state = SHAPER_THREAD_RUNNING;
    
    // Run the packet loop (extracted from old shaper_run_loop)
    shaper_packet_loop_internal(shaper);
    
    // Loop exited, clean up thread-local resources
    InterlockedExchange(&shaper->worker_active, 0);
    shaper->thread_state = SHAPER_THREAD_STOPPED;
    
    return 0;
}

// -----------------------------------------------------------------------
// Shaper - Internal packet loop
// -----------------------------------------------------------------------
static void shaper_packet_loop_internal(ShaperInstance *shaper) {
    if (!shaper || !shaper->is_running) return;

    HANDLE handle = shaper->windivert_handle;

    // Create overlapped event for non-blocking recv
    HANDLE recv_event = shaper->recv_event;

    char packet[MAX_PACKET_SIZE];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    bool shutdown_message_printed = false;
    int delay_process_counter = 0;

    while (!shaper->should_stop) {
        // Check if we can acquire rule_update_lock without blocking
        if (TryEnterCriticalSection(&shaper->rule_update_lock)) {
            // Rules are not being updated, proceed normally
            LeaveCriticalSection(&shaper->rule_update_lock);

            DWORD recv_len;
            OVERLAPPED overlapped = {0};
            overlapped.hEvent = recv_event;

            if (!WinDivertRecvEx(handle, packet, sizeof(packet), &recv_len, 0,
                                  &addr, NULL, &overlapped)) {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    DWORD wait = WaitForSingleObject(overlapped.hEvent, 100);
                    if (wait == WAIT_TIMEOUT)  { CancelIo(handle); continue; }
                    if (wait == WAIT_OBJECT_0) {
                        if (!GetOverlappedResult(handle, &overlapped, &recv_len, FALSE)) {
                            DWORD ge = GetLastError();
                            if (ge == ERROR_NO_MORE_ITEMS || ge == ERROR_HANDLE_EOF) break;
                            continue;
                        }
                        packet_len = recv_len;
                    } else { continue; }
                } else if (err == ERROR_NO_MORE_ITEMS || err == ERROR_HANDLE_EOF) {
                    break;
                } else {
                    if (shaper->should_stop) break;
                    fprintf(stderr, "WinDivertRecvEx failed: %lu\n", err);
                    continue;
                }
            } else {
                packet_len = recv_len;
            }

            if (shaper->should_stop) break;

            // Process delayed packets periodically
            if (++delay_process_counter >= 10) {
                delay_process_counter = 0;
                delay_buffer_process(&shaper->delay_buffer, &shaper->global_lock, handle);
            }

            // Track drop reasons for this packet
            bool dropped_rate = false;
            bool dropped_loss = false;
            bool delayed = false;
            bool invalid = false;
            bool packet_handled = false;  // Track if we've already decided to drop/reinject

            // Validate packet structure
            if (!validate_packet(packet, packet_len, NULL)) {  // Pass NULL to avoid stats update
                invalid = true;
                packet_handled = true;  // Will reinject after stats update
                goto stats_update;
            }

            // Data cap: check if already reached
            if (shaper->cap_reached) {
                dropped_rate = true;
                packet_handled = true;
                goto stats_update;
            }

            // Count all bytes toward data cap, regardless of throttling
            if (shaper->data_cap_bytes > 0) {
                LONGLONG total = InterlockedAdd64(&shaper->total_bytes_throttled, packet_len);

                if (total >= shaper->data_cap_bytes && !shaper->cap_reached) {
                    shaper->cap_reached = true;
                    printf("*** DATA CAP REACHED! Total: %I64d bytes ***\n", total);
                    // Drop this packet and all future packets
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }
            }

            // NIC lookup
            unsigned int if_idx = addr.Network.IfIdx;
            int nic_index = -1;
            for (int i = 0; i < (int)shaper->params.nic_count; i++) {
                if (shaper->params.nic_indices[i] == if_idx) { nic_index = i; break; }
            }

            if (nic_index == -1) {
                // Not a monitored NIC - reinject normally
                reinject_packet(handle, packet, packet_len, &addr, NULL);  // NULL to avoid stats
                packet_handled = true;
                goto stats_update;
            }

            // PID lookup
            DWORD pid = get_packet_pid(&shaper->pid_cache, &addr, packet, packet_len);

            // Update per-PID traffic counters (all PIDs, not just ruled ones)
            if (pid != 0) {
                shaper_update_pid_traffic(shaper, pid, packet_len, addr.Outbound);
            }

            // Global process filter
            if (shaper->processparams.process_list != NULL) {
                update_pid_map(&shaper->processparams, &shaper->pid_cache);
                if (shaper->processparams.pid_map != NULL && pid != 0 &&
                    !is_pid_in_map(shaper->processparams.pid_map, pid)) {
                    reinject_packet(handle, packet, packet_len, &addr, NULL);
                    packet_handled = true;
                    goto stats_update;
                }
            }

            // Check global schedule first - it acts as a master switch
            if (!shaper_is_global_schedule_active(shaper)) {
                // Global schedule inactive - all traffic passes unthrottled
                reinject_packet(handle, packet, packet_len, &addr, NULL);
                packet_handled = true;
                goto stats_update;
            }

            // Per-process rule matching
            ProcessRule *match = NULL;
            bool should_refresh = false;

            // Check if we need to refresh name-based rules
            if (shaper->processparams.packet_threshold > 0) {
                if (++shaper->rule_refresh_packet_counter >= shaper->processparams.packet_threshold) {
                    shaper->rule_refresh_packet_counter = 0;
                    should_refresh = true;
                }
            } else if (shaper->processparams.time_threshold_ms > 0) {
                clock_t now = clock();
                if (shaper->rule_refresh_last_time == 0) 
                    shaper->rule_refresh_last_time = now;
                if ((double)(now - shaper->rule_refresh_last_time) / CLOCKS_PER_SEC * 1000.0
                        >= shaper->processparams.time_threshold_ms) {
                    shaper->rule_refresh_last_time = now;
                    should_refresh = true;
                }
            }

            // Perform refresh if needed (before lookup to ensure fresh mappings)
            if (should_refresh) {
                EnterCriticalSection(&shaper->global_lock);
                EnterCriticalSection(&shaper->reverse_index.lock);

                ProcessRule *r, *tmp;
                HASH_ITER(hh, shaper->rules, r, tmp) {
                    // Skip PID-based rules
                    if (r->flags & RULE_FLAG_IS_PID) continue;

                    // Clear old reverse index entries for this rule
                    PIDToRuleMap *entry, *etmp;
                    HASH_ITER(hh, shaper->reverse_index.pid_to_rule, entry, etmp) {
                        if (entry->rule == r) {
                            HASH_DEL(shaper->reverse_index.pid_to_rule, entry);
                            free(entry);
                        }
                    }

                    // Refresh PID map
                    free_pid_map_pool(r->pids, &g_pid_pool);
                    r->pids = NULL;

                    int *list = NULL;
                    int count = get_pids_from_name(r->name, &list);
                    for (int j = 0; j < count; j++) {
                        int pid_val = list[j];

                        // Add to rule's PID map
                        add_pid_to_map_pool(&r->pids, pid_val, &g_pid_pool);

                        // Add to reverse index
                        PIDToRuleMap *new_entry = malloc(sizeof(PIDToRuleMap));
                        if (new_entry) {
                            new_entry->pid = (DWORD)pid_val;
                            new_entry->rule = r;
                            HASH_ADD(hh, shaper->reverse_index.pid_to_rule, pid, sizeof(DWORD), new_entry);
                        }
                    }
                    if (list) free(list);
                }

                // Now do the lookup for the current PID while we still hold the lock!
                if (pid != 0) {
                    PIDToRuleMap *entry;
                    HASH_FIND(hh, shaper->reverse_index.pid_to_rule, &pid, sizeof(DWORD), entry);
                    if (entry) {
                        match = entry->rule;
                    }
                }

                LeaveCriticalSection(&shaper->reverse_index.lock);
                LeaveCriticalSection(&shaper->global_lock);
            } else {
                // No refresh - just do the lookup
                if (pid != 0) {
                    match = find_rule_by_pid(shaper, pid);
                }
            }

            // Keep linear scan as a fallback
            // but it should rarely be needed if reverse index is properly maintained
            if (!match && pid != 0) {
                // This should not happen in normal operation - indicates reverse index inconsistency
                // Log once per session to avoid spam
                static bool warned = false;
                if (!warned) {
                    fprintf(stderr, "Warning: PID %lu not found in reverse index, falling back to linear scan\n", pid);
                    warned = true;
                }

                // Linear scan fallback
                ProcessRule *r, *tmp;
                HASH_ITER(hh, shaper->rules, r, tmp) {
                    if (is_pid_in_map(r->pids, pid)) {
                        match = r;

                        // Repair reverse index for future lookups
                        EnterCriticalSection(&shaper->reverse_index.lock);
                        PIDToRuleMap *entry = malloc(sizeof(PIDToRuleMap));
                        if (entry) {
                            entry->pid = pid;
                            entry->rule = r;
                            HASH_ADD(hh, shaper->reverse_index.pid_to_rule, pid, sizeof(DWORD), entry);
                        }
                        LeaveCriticalSection(&shaper->reverse_index.lock);

                        break;
                    }
                }
            }

            // If we found a matching rule, apply its policies
            if (match) {
                // Check if this direction is blocked for the matched rule
                if ((addr.Outbound && (match->flags & RULE_FLAG_UL_BLOCKED)) ||
                    (!addr.Outbound && (match->flags & RULE_FLAG_DL_BLOCKED))) {
                    // Blocked - drop packet immediately
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }

                // Check quotas
                if (addr.Outbound && (match->flags & RULE_FLAG_QUOTA_OUT_EXHAUSTED)) {
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }
                if (!addr.Outbound && (match->flags & RULE_FLAG_QUOTA_IN_EXHAUSTED)) {
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }
            }

            // Select token bucket (per-process -> global fallback)
            TokenBucket *bucket = NULL;
            if (match) {
                // Check direction-specific bucket independently
                TokenBucket *rule_buckets = addr.Outbound ? match->ul_buckets : match->dl_buckets;
                if (rule_buckets && nic_index >= 0 && nic_index < (int)shaper->params.nic_count) {
                    if (rule_buckets[nic_index].rate > 0) {
                        bucket = &rule_buckets[nic_index];
                    }
                }
            }

            if (!bucket) {
                // Fall back to global bucket
                if (addr.Outbound) {
                    if (shaper->params.upload_limits[nic_index] > 0) {
                        bucket = &shaper->upload_buckets[nic_index];
                    }
                } else {
                    if (shaper->params.download_limits[nic_index] > 0) {
                        bucket = &shaper->download_buckets[nic_index];
                    }
                }
            }

            // Parse headers (needed for TCP/UDP rate limiting)
            char local_ip[INET6_ADDRSTRLEN] = {0};
            char remote_ip[INET6_ADDRSTRLEN] = {0};
            UINT local_port = 0, remote_port = 0;
            BYTE protocol = 0;

            if (!parse_packet_headers(packet, packet_len, (bool)addr.Outbound,
                                      local_ip, remote_ip, &local_port, &remote_port,
                                      &protocol, sizeof(local_ip))) {
                invalid = true;
                packet_handled = true;
                goto stats_update;
            }

            // TCP connection limit
            if (shaper->max_tcp_connections > 0 && protocol == IPPROTO_TCP) {
                if (!check_packet_rate_limit(&shaper->processparams, &shaper->global_lock,
                                             local_ip, local_port,
                                             (int)shaper->max_tcp_connections)) {
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }
            }

            // UDP rate limit
            if (shaper->max_udp_packets_per_second > 0 && protocol == IPPROTO_UDP) {
                if (!check_packet_rate_limit(&shaper->processparams, &shaper->global_lock,
                                             local_ip, local_port,
                                             (int)shaper->max_udp_packets_per_second)) {
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }
            }

            // Token bucket consume
            if (bucket != NULL) {
                if (!token_bucket_consume(bucket, (int)packet_len)) {
                    dropped_rate = true;
                    packet_handled = true;
                    goto stats_update;
                }
                // Per-rule traffic accounting
                if (match) {
                    if (addr.Outbound) {
                        InterlockedAdd64(&match->ul_bytes, packet_len);
                        InterlockedIncrement(&match->ul_packets);
                    } else {
                        InterlockedAdd64(&match->dl_bytes, packet_len);
                        InterlockedIncrement(&match->dl_packets);
                    }
                }
            }

            // Simulate packet loss
            if (should_drop_packet(shaper->packet_loss, NULL)) {  // Pass NULL to avoid stats
                dropped_loss = true;
                packet_handled = true;
                goto stats_update;
            }

            // Simulate latency via delay buffer
            if (shaper->latency_ms > 0) {
                LONGLONG delay_ticks = (LONGLONG)(shaper->latency_ms * shaper->perf_frequency / 1000.0);
                if (delay_buffer_add(&shaper->delay_buffer, &shaper->global_lock,
                                      packet, packet_len, &addr, delay_ticks, NULL)) {  // NULL to avoid stats
                    delayed = true;
                    packet_handled = true;
                    goto stats_update;
                }
                // If delay_buffer_add fails, fall through to reinject
            }

            // If we get here, packet should be reinjected normally
            reinject_packet(handle, packet, packet_len, &addr, NULL);

        stats_update:
            // Update all stats in one batch
            update_batch_stats(shaper, packet_len, dropped_rate, dropped_loss, delayed, invalid);
        } else {
            // Rules are being updated - wait a bit and retry
            Sleep(1);
            continue;
        }
    }

    // Final delayed packet flush - handle still valid at this point
    delay_buffer_process(&shaper->delay_buffer, &shaper->global_lock, handle);

    // Final flush before exit
    flush_batch_stats_final(shaper);

    if (!shutdown_message_printed) {
        CORE_PRINTF(shaper, "Shutdown initiated...\n");
        shutdown_message_printed = true;
        Sleep(100);
    }
}

// -----------------------------------------------------------------------
// Per-PID / per-rule statistics
// -----------------------------------------------------------------------
// Fill a PidStats snapshot from a rule pointer (caller holds the lock).
// Note: caller must hold global_lock!
static void fill_pid_stats(const ProcessRule *r, DWORD pid, PidStats *out) {
    memset(out, 0, sizeof(*out));
    out->has_rule = true;
    out->pid = pid;
    out->dl_rate_limit = r->dl_rate;
    out->ul_rate_limit = r->ul_rate;
    out->dl_bytes = (uint64_t)InterlockedCompareExchange64(
                       (volatile LONGLONG *)&r->dl_bytes, 0, 0);
    out->ul_bytes = (uint64_t)InterlockedCompareExchange64(
                       (volatile LONGLONG *)&r->ul_bytes, 0, 0);
    out->dl_packets = (uint64_t)(ULONG)InterlockedExchangeAdd(
                         (volatile LONG *)&r->dl_packets, 0);
    out->ul_packets = (uint64_t)(ULONG)InterlockedExchangeAdd(
                         (volatile LONG *)&r->ul_packets, 0);
    strncpy(out->rule_name, r->name, sizeof(out->rule_name) - 1);
    out->rule_name[sizeof(out->rule_name) - 1] = '\0';
}

void shaper_reset_pid_stats(ShaperInstance *shaper, DWORD pid) {
    if (!shaper) return;
    if (!shaper->lock_initialized) return;
    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r, *tmp;
    HASH_ITER(hh, shaper->rules, r, tmp) {
        bool reset_this = (pid == 0) || is_pid_in_map(r->pids, (int)pid);
        if (reset_this) {
            // Reset rule traffic counters
            InterlockedExchange64(&r->dl_bytes, 0);
            InterlockedExchange64(&r->ul_bytes, 0);
            InterlockedExchange(&r->dl_packets, 0);
            InterlockedExchange(&r->ul_packets, 0);
            if (pid != 0) break; // only one rule per PID
        }
    }
    LeaveCriticalSection(&shaper->global_lock);
}

bool shaper_get_pid_traffic(ShaperInstance *shaper, DWORD pid,
                            uint64_t *dl_bytes, uint64_t *ul_bytes) {
    if (!shaper || !dl_bytes || !ul_bytes) return false;
    *dl_bytes = 0;
    *ul_bytes = 0;

    if (!shaper->pid_traffic_shards_initialized) return false;

    int shard_idx = pid_shard(pid);

    EnterCriticalSection(&shaper->pid_traffic_locks[shard_idx]);
    PidTraffic *pt;
    HASH_FIND(hh, shaper->pid_traffic_shards[shard_idx], &pid, sizeof(DWORD), pt);
    if (pt) {
        *dl_bytes = (uint64_t)InterlockedCompareExchange64(
                        (volatile LONGLONG *)&pt->dl_bytes, 0, 0);
        *ul_bytes = (uint64_t)InterlockedCompareExchange64(
                        (volatile LONGLONG *)&pt->ul_bytes, 0, 0);
    }
    LeaveCriticalSection(&shaper->pid_traffic_locks[shard_idx]);

    return (pt != NULL);
}

void shaper_update_pid_traffic(ShaperInstance *shaper, DWORD pid, 
                               int packet_len, bool outbound) {
    if (!shaper || !shaper->pid_traffic_shards_initialized) return; 

    int shard_idx = pid_shard(pid);
    EnterCriticalSection(&shaper->pid_traffic_locks[shard_idx]);

    PidTraffic *pt;
    HASH_FIND(hh, shaper->pid_traffic_shards[shard_idx], &pid, sizeof(DWORD), pt);

    if (!pt) {
        pt = calloc(1, sizeof(PidTraffic));
        if (pt) {
            pt->pid = pid;
            pt->last_active = time(NULL);
            pt->last_snapshot_dl = 0;
            pt->last_snapshot_ul = 0;
            HASH_ADD(hh, shaper->pid_traffic_shards[shard_idx], pid, sizeof(DWORD), pt);
        }
    }
    if (pt) {
        if (outbound) {
            pt->ul_bytes += packet_len;
        }
        else {
            pt->dl_bytes += packet_len;
        }
        pt->last_active = time(NULL);  // Update activity timestamp on every packet
    }
    LeaveCriticalSection(&shaper->pid_traffic_locks[shard_idx]);
}

// -----------------------------------------------------------------------
// Per-process rule query / remove / quota
// -----------------------------------------------------------------------
// Internal helper: normalize identifier to the internal rule name format
static void normalize_identifier(const char *identifier, char *out, size_t out_size) {
    // Check if it's a pure numeric PID
    bool is_pid = true;
    for (const char *c = identifier; *c; c++) {
        if (!isdigit((unsigned char)*c)) { is_pid = false; break; }
    }

    if (is_pid) {
        snprintf(out, out_size, "__PID_%s__", identifier);
    } else {
        strncpy(out, identifier, out_size - 1);
        out[out_size - 1] = '\0';
    }
}

bool shaper_has_process_rule(ShaperInstance *shaper, const char *identifier) {
    if (!shaper || !identifier) return false;
    if (!shaper->lock_initialized) return false;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(identifier, norm_name, sizeof(norm_name));

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);
    LeaveCriticalSection(&shaper->global_lock);

    return (r != NULL);
}

bool shaper_remove_process_rule(ShaperInstance *shaper, const char *identifier) {
    if (!shaper || !identifier) return false;
    if (!shaper->lock_initialized) return false;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(identifier, norm_name, sizeof(norm_name));

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);

    if (r) {
        HASH_DEL(shaper->rules, r);
        shaper->rule_count--;

        // Remove from reverse index first
        clear_rule_from_reverse_index(shaper, r);

        // Also remove from flat_rules.array if present
        EnterCriticalSection(&shaper->flat_rules.lock);
        for (int i = 0; i < shaper->flat_rules.count; i++) {
            if (shaper->flat_rules.array[i] == r) {
                // Swap with last element and decrement count
                shaper->flat_rules.array[i] = shaper->flat_rules.array[shaper->flat_rules.count - 1];
                shaper->flat_rules.count--;
                break;
            }
        }
        LeaveCriticalSection(&shaper->flat_rules.lock);

        // Free resources
        free_pid_map_pool(r->pids, &g_pid_pool);
        if (r->dl_buckets) {
            for (int i = 0; i < shaper->params.nic_count; i++)
                token_bucket_destroy(&r->dl_buckets[i]);
            free(r->dl_buckets);
        }
        if (r->ul_buckets) {
            for (int i = 0; i < shaper->params.nic_count; i++)
                token_bucket_destroy(&r->ul_buckets[i]);
            free(r->ul_buckets);
        }
        free(r);
    }
    LeaveCriticalSection(&shaper->global_lock);

    return (r != NULL);
}

bool shaper_set_process_quota(ShaperInstance *shaper,
                               const char *identifier,
                               uint64_t quota_in,
                               uint64_t quota_out) {
    if (!shaper || !identifier) return false;
    if (!shaper->lock_initialized) return false;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(identifier, norm_name, sizeof(norm_name));

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);

    if (r) {
        r->quota_in = quota_in;
        r->quota_out = quota_out;

        // Update flags
        if (quota_in > 0) {
            r->flags |= RULE_FLAG_HAS_QUOTA_IN;
            r->flags &= ~RULE_FLAG_QUOTA_IN_EXHAUSTED;  // Reset exhausted flag
        } else {
            r->flags &= ~RULE_FLAG_HAS_QUOTA_IN;
            r->flags &= ~RULE_FLAG_QUOTA_IN_EXHAUSTED;
        }

        if (quota_out > 0) {
            r->flags |= RULE_FLAG_HAS_QUOTA_OUT;
            r->flags &= ~RULE_FLAG_QUOTA_OUT_EXHAUSTED;
        } else {
            r->flags &= ~RULE_FLAG_HAS_QUOTA_OUT;
            r->flags &= ~RULE_FLAG_QUOTA_OUT_EXHAUSTED;
        }

        // If quota-only (no rates), set blocked flags appropriately,
        // but preserve any explicit block settings
        if (quota_in > 0 && r->dl_rate == 0) {
            r->flags |= RULE_FLAG_DL_BLOCKED;
        }
        if (quota_out > 0 && r->ul_rate == 0) {
            r->flags |= RULE_FLAG_UL_BLOCKED;
        }
    }
    LeaveCriticalSection(&shaper->global_lock);

    return (r != NULL);
}

bool shaper_get_process_quota(ShaperInstance *shaper,
                               const char *identifier,
                               uint64_t *quota_in,
                               uint64_t *quota_out,
                               bool *in_reached,
                               bool *out_reached) {
    if (!shaper || !identifier) return false;
    if (!shaper->lock_initialized) return false;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(identifier, norm_name, sizeof(norm_name));

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);

    if (r) {
        if (quota_in) *quota_in = r->quota_in;
        if (quota_out) *quota_out = r->quota_out;
        if (in_reached) *in_reached = (r->flags & RULE_FLAG_QUOTA_IN_EXHAUSTED) != 0;
        if (out_reached) *out_reached = (r->flags & RULE_FLAG_QUOTA_OUT_EXHAUSTED) != 0;
    }
    LeaveCriticalSection(&shaper->global_lock);

    return (r != NULL);
}

bool shaper_reset_process_quota(ShaperInstance *shaper,
                                 const char *identifier,
                                 bool clear_counters) {
    if (!shaper || !identifier) return false;
    if (!shaper->lock_initialized) return false;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(identifier, norm_name, sizeof(norm_name));

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);

    if (r) {
        // Reset exhausted flags
        r->flags &= ~RULE_FLAG_QUOTA_IN_EXHAUSTED;
        r->flags &= ~RULE_FLAG_QUOTA_OUT_EXHAUSTED;

        // Restore blocked state based on:
        // 1. Original explicit block flags (preserved from creation)
        // 2. Or quota-only rules (rate=0 with quota)
        // 3. Otherwise clear blocked flags

        // Handle download direction
        if (r->flags & RULE_FLAG_DL_EXPLICITLY_BLOCKED) {
            // Was explicitly blocked at creation - keep it blocked
            r->flags |= RULE_FLAG_DL_BLOCKED;
        } else if (r->dl_rate == 0.0 && (r->flags & RULE_FLAG_HAS_QUOTA_IN)) {
            // Quota-only rule with no rate
            r->flags |= RULE_FLAG_DL_BLOCKED;
        } else {
            // Normal rule - clear blocked flag
            r->flags &= ~RULE_FLAG_DL_BLOCKED;
        }

        // Handle upload direction
        if (r->flags & RULE_FLAG_UL_EXPLICITLY_BLOCKED) {
            // Was explicitly blocked at creation - keep it blocked
            r->flags |= RULE_FLAG_UL_BLOCKED;
        } else if (r->ul_rate == 0.0 && (r->flags & RULE_FLAG_HAS_QUOTA_OUT)) {
            // Quota-only rule with no rate
            r->flags |= RULE_FLAG_UL_BLOCKED;
        } else {
            // Normal rule - clear blocked flag
            r->flags &= ~RULE_FLAG_UL_BLOCKED;
        }

        if (clear_counters) {
            InterlockedExchange64(&r->dl_bytes, 0);
            InterlockedExchange64(&r->ul_bytes, 0);
            InterlockedExchange(&r->dl_packets, 0);
            InterlockedExchange(&r->ul_packets, 0);
        }
    }
    LeaveCriticalSection(&shaper->global_lock);

    return (r != NULL);
}

// Check if a rule's schedule is currently active
// Returns true if rule should be active, false if suspended
static bool check_rule_schedule(ProcessRule *rule) {
    if (!(rule->flags & RULE_FLAG_HAS_SCHEDULE)) {
        return true;  // No schedule = always active
    }

    time_t now = time(NULL);

    // Rate limit schedule checks (once per second max)
    if (now - rule->last_schedule_check < 1) {
        return (rule->flags & RULE_FLAG_SCHEDULE_ACTIVE) != 0;
    }

    rule->last_schedule_check = now;

    bool active = schedule_is_active_now(&rule->schedule);
    if (active) {
        rule->flags |= RULE_FLAG_SCHEDULE_ACTIVE;
    } else {
        rule->flags &= ~RULE_FLAG_SCHEDULE_ACTIVE;
    }

    return active;
}

// Check if global schedule is active
bool shaper_is_global_schedule_active(ShaperInstance *shaper) {
    if (!shaper || schedule_is_empty(&shaper->global_schedule)) {
        return true;  // No schedule = always active
    }

    time_t now = time(NULL);

    // Rate limit schedule checks
    if (now - shaper->last_global_schedule_check < 1) {
        return shaper->global_schedule_active;
    }

    shaper->last_global_schedule_check = now;
    shaper->global_schedule_active = schedule_is_active_now(&shaper->global_schedule);

    return shaper->global_schedule_active;
}

// -----------------------------------------------------------------------
// Process name-based traffic aggregation
// -----------------------------------------------------------------------
bool shaper_get_process_traffic_by_name(ShaperInstance *shaper,
                                         const char *process_name,
                                         uint64_t *total_dl,
                                         uint64_t *total_ul) {
    if (!shaper || !process_name || !total_dl || !total_ul) return false;
    if (!shaper->pid_traffic_shards_initialized) return false;

    *total_dl = 0;
    *total_ul = 0;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(process_name, norm_name, sizeof(norm_name));

    // Single lock section to get PIDs
    DWORD temp_pids[MAX_TEMP_PIDS];
    int pid_count = 0;

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);
    if (r) {
        pid_count = collect_rule_pids_locked(r, temp_pids, MAX_TEMP_PIDS);
    }
    LeaveCriticalSection(&shaper->global_lock);

    if (!r) return false;
    if (pid_count == 0) return true;

    // Sum traffic using shaper_get_pid_traffic
    for (int i = 0; i < pid_count; i++) {
        uint64_t dl = 0, ul = 0;
        if (shaper_get_pid_traffic(shaper, temp_pids[i], &dl, &ul)) {
            *total_dl += dl;
            *total_ul += ul;
        }
    }

    return true;
}

bool shaper_get_process_pids(ShaperInstance *shaper,
                             const char *process_name,
                             DWORD *pid_array,
                             int *count) {
    if (!shaper || !process_name || !count) return false;
    if (!shaper->lock_initialized) return false;

    char norm_name[MAX_PROCESS_NAME_LEN];
    normalize_identifier(process_name, norm_name, sizeof(norm_name));

    EnterCriticalSection(&shaper->global_lock);
    ProcessRule *r = NULL;
    HASH_FIND(hh, shaper->rules, norm_name, strlen(norm_name), r);

    if (!r) {
        LeaveCriticalSection(&shaper->global_lock);
        return false;
    }

    // Count PIDs in the rule's PID map
    int actual_count = 0;

    PIDEntry *p, *tmp;
    HASH_ITER(hh, r->pids, p, tmp) {
        if (pid_array && actual_count < *count) {
            pid_array[actual_count] = (DWORD)p->pid;
        }
        actual_count++;
    }

    LeaveCriticalSection(&shaper->global_lock);

    bool was_truncated = (pid_array != NULL && actual_count > *count);
    *count = actual_count;

    return true;  // Rule found, even if 0 PIDs
}

// -----------------------------------------------------------------------
// Cleanup function for stale PID entries
void shaper_cleanup_pid_traffic(ShaperInstance *shaper, int interval_seconds, int max_age_seconds) {
    if (!shaper || !shaper->pid_traffic_shards_initialized) return;

    if (interval_seconds <= 0) interval_seconds = 30;  // Default 30 seconds
    if (max_age_seconds <= 0) max_age_seconds = 15;    // Default 15 seconds

    // Prevent multiple cleanups
    if (InterlockedExchange(&shaper->cleanup_in_progress, 1) != 0) {
        return;
    }

    time_t now = time(NULL);

    // Rate limit cleanup runs
    if (now - shaper->last_cleanup_time < interval_seconds) {
        InterlockedExchange(&shaper->cleanup_in_progress, 0);
        return;
    }

    // Clean up each shard
    for (int shard = 0; shard < PID_CACHE_SHARDS; shard++) {
        EnterCriticalSection(&shaper->pid_traffic_locks[shard]);
        PidTraffic *pt, *ptmp;
        HASH_ITER(hh, shaper->pid_traffic_shards[shard], pt, ptmp) {
            // Check if there's been any activity since last cleanup
            LONGLONG current_dl = InterlockedCompareExchange64(&pt->dl_bytes, 0, 0);
            LONGLONG current_ul = InterlockedCompareExchange64(&pt->ul_bytes, 0, 0);
            LONGLONG last_dl = InterlockedCompareExchange64(&pt->last_snapshot_dl, 0, 0);
            LONGLONG last_ul = InterlockedCompareExchange64(&pt->last_snapshot_ul, 0, 0);

            bool has_new_activity = (current_dl != last_dl) || (current_ul != last_ul);

            if (has_new_activity) {
                // Update snapshots and activity timestamp
                InterlockedExchange64(&pt->last_snapshot_dl, current_dl);
                InterlockedExchange64(&pt->last_snapshot_ul, current_ul);
                pt->last_active = now;
            }
            // Remove stale, inactive PIDs (no activity since last cleanup)
            else if ((now - pt->last_active) > max_age_seconds) {
                HASH_DEL(shaper->pid_traffic_shards[shard], pt);
                free(pt);
            }
        }
        LeaveCriticalSection(&shaper->pid_traffic_locks[shard]);
    }

    shaper->last_cleanup_time = now;
    InterlockedExchange(&shaper->cleanup_in_progress, 0);
}

void shaper_reset_pid_traffic(ShaperInstance *shaper, DWORD pid) {
    if (!shaper || !shaper->pid_traffic_shards_initialized) return;

    if (pid == 0) {
        // Reset all shards
        for (int shard = 0; shard < PID_CACHE_SHARDS; shard++) {
            EnterCriticalSection(&shaper->pid_traffic_locks[shard]);
            PidTraffic *pt, *ptmp;
            HASH_ITER(hh, shaper->pid_traffic_shards[shard], pt, ptmp) {
                InterlockedExchange64(&pt->dl_bytes, 0);
                InterlockedExchange64(&pt->ul_bytes, 0);
                pt->last_active = time(NULL); // Reset active time too
            }
            LeaveCriticalSection(&shaper->pid_traffic_locks[shard]);
        }
    } else {
        int shard_idx = pid_shard(pid);
        EnterCriticalSection(&shaper->pid_traffic_locks[shard_idx]);
        PidTraffic *pt;
        HASH_FIND(hh, shaper->pid_traffic_shards[shard_idx], &pid, sizeof(DWORD), pt);
        if (pt) {
            InterlockedExchange64(&pt->dl_bytes, 0);
            InterlockedExchange64(&pt->ul_bytes, 0);
            pt->last_active = time(NULL);
        }
        LeaveCriticalSection(&shaper->pid_traffic_locks[shard_idx]);
    }
}

// Periodic PID traffic cleanup
void shaper_periodic_cleanup(ShaperInstance *shaper, int interval_seconds, int max_age_seconds) {
    if (!shaper) return;
    shaper_cleanup_pid_traffic(shaper, interval_seconds, max_age_seconds);
}

bool shaper_reload_rules(ShaperInstance *shaper) {
    if (!shaper || !shaper->is_running) {
        set_error(shaper, "Cannot reload rules: shaper not running");
        return false;
    }

    // Prevent concurrent rule updates
    EnterCriticalSection(&shaper->rule_update_lock);

    // Phase 1: Snapshot rule names under lock
    RuleNameSnapshot *rules_to_refresh = NULL;
    int rule_count = 0;
    int rule_capacity = 0;

    EnterCriticalSection(&shaper->global_lock);

    ProcessRule *r, *tmp;
    HASH_ITER(hh, shaper->rules, r, tmp) {
        if (r->flags & RULE_FLAG_IS_PID) continue;

        if (rule_count >= rule_capacity) {
            int new_cap = rule_capacity == 0 ? 16 : rule_capacity * 2;
            RuleNameSnapshot *new_arr = realloc(rules_to_refresh, 
                                                new_cap * sizeof(RuleNameSnapshot));
            if (!new_arr) {
                LeaveCriticalSection(&shaper->global_lock);
                free(rules_to_refresh);
                LeaveCriticalSection(&shaper->rule_update_lock);
                set_error(shaper, "Out of memory during rule reload");
                return false;
            }
            rules_to_refresh = new_arr;
            rule_capacity = new_cap;
        }

        rules_to_refresh[rule_count].rule = r;
        strncpy(rules_to_refresh[rule_count].name, r->name, MAX_PROCESS_NAME_LEN - 1);
        rules_to_refresh[rule_count].name[MAX_PROCESS_NAME_LEN - 1] = '\0';
        rule_count++;
    }

    LeaveCriticalSection(&shaper->global_lock);

    // Phase 2: Resolve PIDs outside any lock
    PidSwap *swaps = NULL;
    int swap_count = 0;
    bool success = true;

    for (int i = 0; i < rule_count && success; i++) {
        int *pid_list = NULL;
        int count = get_pids_from_name(rules_to_refresh[i].name, &pid_list);

        if (count > 0) {
            PIDEntry *new_map = NULL;
            for (int j = 0; j < count; j++) {
                add_pid_to_map_pool(&new_map, pid_list[j], &g_pid_pool);
            }

            PidSwap *new_swaps = realloc(swaps, (swap_count + 1) * sizeof(PidSwap));
            if (!new_swaps) {
                for (int k = 0; k < swap_count; k++) {
                    free_pid_map_pool(swaps[k].new_pid_map, &g_pid_pool);
                }
                free(swaps);
                free_pid_map_pool(new_map, &g_pid_pool);
                free(pid_list);
                free(rules_to_refresh);
                LeaveCriticalSection(&shaper->rule_update_lock);
                set_error(shaper, "Out of memory during rule reload");
                return false;
            }

            swaps = new_swaps;
            swaps[swap_count].rule = rules_to_refresh[i].rule;
            swaps[swap_count].new_pid_map = new_map;
            swap_count++;
        }

        if (pid_list) free(pid_list);
    }

    free(rules_to_refresh);

    if (!success) {
        for (int i = 0; i < swap_count; i++) {
            free_pid_map_pool(swaps[i].new_pid_map, &g_pid_pool);
        }
        free(swaps);
        LeaveCriticalSection(&shaper->rule_update_lock);
        return false;
    }

    // Phase 3: Update under both locks
    EnterCriticalSection(&shaper->global_lock);
    EnterCriticalSection(&shaper->reverse_index.lock);

    // Clear old reverse index entries
    for (int i = 0; i < swap_count; i++) {
        ProcessRule *rule = swaps[i].rule;
        PIDToRuleMap *entry, *tmp;
        HASH_ITER(hh, shaper->reverse_index.pid_to_rule, entry, tmp) {
            if (entry->rule == rule) {
                HASH_DEL(shaper->reverse_index.pid_to_rule, entry);
                free(entry);
            }
        }
    }

    // Swap in new PID maps and add fresh reverse index entries
    for (int i = 0; i < swap_count; i++) {
        ProcessRule *rule = swaps[i].rule;
        free_pid_map_pool(rule->pids, &g_pid_pool);
        rule->pids = swaps[i].new_pid_map;

        PIDEntry *p, *ptmp;
        HASH_ITER(hh, rule->pids, p, ptmp) {
            PIDToRuleMap *entry = malloc(sizeof(PIDToRuleMap));
            if (entry) {
                entry->pid = (DWORD)p->pid;
                entry->rule = rule;
                HASH_ADD(hh, shaper->reverse_index.pid_to_rule, pid, sizeof(DWORD), entry);
            }
        }
    }

    LeaveCriticalSection(&shaper->reverse_index.lock);
    LeaveCriticalSection(&shaper->global_lock);

    free(swaps);
    LeaveCriticalSection(&shaper->rule_update_lock);

    return success;
}

// -----------------------------------------------------------------------
// Status / introspection
// -----------------------------------------------------------------------
bool shaper_is_running(const ShaperInstance *shaper) {
    return shaper && shaper->is_running;
}

void shaper_get_stats(ShaperInstance *shaper, ShaperStats *out) {
    if (!shaper || !out) return;
    flush_batch_stats(shaper);  // Flush any pending batch stats to get accurate counts
    out->packets_processed = (uint64_t)InterlockedExchangeAdd(&shaper->stats.packets_processed, 0);
    out->packets_dropped_rate_limit = (uint64_t)InterlockedExchangeAdd(&shaper->stats.packets_dropped_rate_limit, 0);
    out->packets_dropped_loss = (uint64_t)InterlockedExchangeAdd(&shaper->stats.packets_dropped_loss, 0);
    out->packets_delayed = (uint64_t)InterlockedExchangeAdd(&shaper->stats.packets_delayed, 0);
    out->bytes_processed = (uint64_t)InterlockedCompareExchange64(&shaper->stats.bytes_processed, 0, 0);
    out->bytes_throttled = (uint64_t)InterlockedCompareExchange64(&shaper->total_bytes_throttled, 0, 0);
    out->invalid_packets = (uint64_t)InterlockedExchangeAdd(&shaper->stats.invalid_packets, 0);
    out->is_running = shaper->is_running;
    out->cap_reached = shaper->cap_reached;
}

const char *shaper_get_last_error(const ShaperInstance *shaper) {
    return shaper ? shaper->error_buf : "NULL shaper";
}

ShaperThreadState shaper_get_thread_state(const ShaperInstance *shaper) {
    return shaper ? shaper->thread_state : SHAPER_THREAD_IDLE;
}

HANDLE shaper_get_thread_handle(const ShaperInstance *shaper) {
    return (shaper && shaper->is_running) ? shaper->worker_thread : NULL;
}

bool shaper_snapshot_traffic(ShaperInstance *shaper, TrafficSnapshot *snapshot) {
    if (!shaper || !snapshot) return false;

    // First pass: count total PIDs
    int total_pids = 0;
    for (int i = 0; i < PID_CACHE_SHARDS; i++) {
        EnterCriticalSection(&shaper->pid_traffic_locks[i]);
        PidTraffic *pt;
        for (pt = shaper->pid_traffic_shards[i]; pt != NULL; pt = pt->hh.next) {
            total_pids++;
        }
        LeaveCriticalSection(&shaper->pid_traffic_locks[i]);
    }

    if (total_pids == 0) {
        snapshot->entries = NULL;
        snapshot->count = 0;
        snapshot->capacity = 0;
        snapshot->timestamp = GetTickCount64();
        return true;
    }

    // Allocate exact size needed
    snapshot->entries = malloc(sizeof(TrafficSnapshotEntry) * total_pids);
    if (!snapshot->entries) return false;
    snapshot->capacity = total_pids;
    snapshot->count = 0;
    snapshot->truncated = false;
    snapshot->timestamp = GetTickCount64();

    // Second pass: fill data
    for (int i = 0; i < PID_CACHE_SHARDS; i++) {
        EnterCriticalSection(&shaper->pid_traffic_locks[i]);
        PidTraffic *pt;
        for (pt = shaper->pid_traffic_shards[i]; pt != NULL; pt = pt->hh.next) {
            snapshot->entries[snapshot->count].pid = pt->pid;
            snapshot->entries[snapshot->count].dl_bytes = 
                (uint64_t)InterlockedCompareExchange64(
                    (volatile LONGLONG *)&pt->dl_bytes, 0, 0);
            snapshot->entries[snapshot->count].ul_bytes = 
                (uint64_t)InterlockedCompareExchange64(
                    (volatile LONGLONG *)&pt->ul_bytes, 0, 0);
            snapshot->count++;
        }
        LeaveCriticalSection(&shaper->pid_traffic_locks[i]);
    }

    return true;
}

void shaper_free_traffic_snapshot(TrafficSnapshot *snapshot) {
    if (!snapshot) return;

    // Safe free - handles NULL, already-freed, or never-allocated
    if (snapshot->entries) {
        free(snapshot->entries);
        snapshot->entries = NULL;  // Prevent double-free
    }
    snapshot->count = 0;
    snapshot->capacity = 0;
}
