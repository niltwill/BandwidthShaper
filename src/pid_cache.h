#ifndef PID_CACHE_H
#define PID_CACHE_H

#include "common.h"

// ------------------------------------------------------------------
// PID hash-map entry
// ------------------------------------------------------------------
typedef struct {
    int pid;              // Process ID (hash key)
    UT_hash_handle hh;
} PIDEntry;

// ------------------------------------------------------------------
// PID memory pool
// ------------------------------------------------------------------
typedef struct PIDEntryArena {
    struct PIDEntryArena *next;
    int capacity;
    int used;
    PIDEntry entries[];  // Flexible array member
} PIDEntryArena;

typedef struct {
    PIDEntryArena *first_arena;
    PIDEntryArena *current_arena;
    CRITICAL_SECTION lock;
    bool initialized;
    
    // Free list of indices within arenas
    struct {
        PIDEntryArena *arena;
        int index;
    } *free_list;
    int free_list_capacity;
    int free_list_count;
} PIDEntryPool;

// Global PID pool singleton
extern PIDEntryPool g_pid_pool;

// ------------------------------------------------------------------
// Cached TCP/UDP owner-PID tables
// ------------------------------------------------------------------
typedef struct {
    void *tcp4_table;
    void *tcp6_table;
    void *udp4_table;
    void *udp6_table;
    LONGLONG last_refresh_ticks;
    LONGLONG ttl_ticks;   // How long the cache stays valid
} PidTableCache;

// ------------------------------------------------------------------
// PID hash-map helpers
// ------------------------------------------------------------------

// Initialize the PID entry pool
bool pid_pool_init_once(PIDEntryPool *pool, int initial_size);
bool pid_pool_init(PIDEntryPool *pool, int initial_size);

// Clean up the pool
void pid_pool_cleanup(PIDEntryPool *pool);

// Allocate a PID entry from the pool
PIDEntry* pid_pool_alloc(PIDEntryPool *pool);

// Return a PID entry to the pool
void pid_pool_free(PIDEntryPool *pool, PIDEntry *entry);

// Replace the old add_pid_to_map with a pool-aware version
void add_pid_to_map_pool(PIDEntry **pid_map, int pid, PIDEntryPool *pool);

// Returns non-zero if pid is in pid_map.
int is_pid_in_map(PIDEntry *pid_map, unsigned int pid);

// Free all entries in pid map (pool-aware version)
void free_pid_map_pool(PIDEntry *map, PIDEntryPool *pool);

// Free all entries in pid_map (legacy - unused, but kept just in case)
//void free_pid_map(PIDEntry *pid_map);

// ------------------------------------------------------------------
// Process enumeration helpers
// ------------------------------------------------------------------

// Fill *pid_list with all PIDs whose base name matches process_name
// (case-insensitive).  Caller must free(*pid_list).
// Returns the number of matching PIDs (0 on failure/no match).
int get_pids_from_name(const char *process_name, int **pid_list);

// Returns true if the process with the given PID is currently alive.
bool is_process_alive(int pid);

// ------------------------------------------------------------------
// Cached TCP/UDP table refresh
// ------------------------------------------------------------------

// Initialize the global cache.  Must be called once before
// refresh_pid_cache() / get_packet_pid().
void pid_cache_init(PidTableCache *cache, double cache_ttl_ms,
                    double perf_frequency);

// Free all tables inside cache (does NOT free the struct itself).
void pid_cache_cleanup(PidTableCache *cache);

// Refresh the four OS connection tables if the TTL has expired.
// Uses the global g_pid_cache; call pid_cache_init() first.
void refresh_pid_cache(PidTableCache *cache);

// Look up the owning PID of a packet using the cached tables.
// Returns 0 if unknown.
DWORD get_packet_pid(PidTableCache *cache,
                     const WINDIVERT_ADDRESS *addr,
                     const char *packet, UINT packet_len);

#endif // PID_CACHE_H
