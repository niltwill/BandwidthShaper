// pid_cache.c
// PID hash-map helpers, process enumeration, and cached TCP/UDP
// owner-PID table management.

#include "pid_cache.h"

// -----------------------------------------------------------------------
// PID entry memory pools
// -----------------------------------------------------------------------

// Global PID pool singleton
PIDEntryPool g_pid_pool = {0};

// Initialization state for the global PID pool
static LONG g_pool_init_state = 0;  // 0 = uninitialized, 1 = initializing, 2 = done

bool pid_pool_init_once(PIDEntryPool *pool, int initial_size) {
    // Fast path
    if (g_pool_init_state == 2) return true;
    
    // Try to become the initializer
    LONG prev = InterlockedCompareExchange(&g_pool_init_state, 1, 0);
    if (prev == 2) {
        return true;  // Another thread finished
    }
    if (prev == 1) {
        // Another thread is initializing, wait
        while (g_pool_init_state != 2) {
            Sleep(1);
        }
        return true;
    }
    
    // We are the initializer (prev == 0)
    bool ok = pid_pool_init(pool, initial_size);
    InterlockedExchange(&g_pool_init_state, ok ? 2 : 0);  // Mark done or reset to allow retry
    return ok;
}

bool pid_pool_init(PIDEntryPool *pool, int initial_size) {
    if (!pool) return false;

    memset(pool, 0, sizeof(*pool));

    if (initial_size < 16) initial_size = 16;

    // Allocate first arena
    pool->first_arena = malloc(sizeof(PIDEntryArena) + initial_size * sizeof(PIDEntry));
    if (!pool->first_arena) return false;

    pool->first_arena->next = NULL;
    pool->first_arena->capacity = initial_size;
    pool->first_arena->used = 0;
    pool->current_arena = pool->first_arena;

    // Initialize free list
    pool->free_list_capacity = initial_size;
    pool->free_list = malloc(initial_size * sizeof(*pool->free_list));
    if (!pool->free_list) {
        free(pool->first_arena);
        return false;
    }
    pool->free_list_count = 0;

    if (!InitializeCriticalSectionAndSpinCount(&pool->lock, 4000)) {
        free(pool->first_arena);
        free(pool->free_list);
        return false;
    }

    pool->initialized = true;
    return true;
}

void pid_pool_cleanup(PIDEntryPool *pool) {
    if (!pool || !pool->initialized) return;

    EnterCriticalSection(&pool->lock);

    // Free all arenas
    PIDEntryArena *arena = pool->first_arena;
    while (arena) {
        PIDEntryArena *next = arena->next;
        free(arena);
        arena = next;
    }

    free(pool->free_list);
    pool->first_arena = NULL;
    pool->current_arena = NULL;
    pool->free_list = NULL;
    pool->free_list_capacity = 0;
    pool->free_list_count = 0;

    LeaveCriticalSection(&pool->lock);
    DeleteCriticalSection(&pool->lock);
    pool->initialized = false;
}

void pid_pool_cleanup_global(void) {
    pid_pool_cleanup(&g_pid_pool);
    g_pool_init_state = 0;  // Reset for potential re-init
}

PIDEntry* pid_pool_alloc(PIDEntryPool *pool) {
    if (!pool || !pool->initialized) {
        return calloc(1, sizeof(PIDEntry));
    }

    EnterCriticalSection(&pool->lock);

    PIDEntry *entry = NULL;

    // Try free list first
    if (pool->free_list_count > 0) {
        pool->free_list_count--;
        PIDEntryArena *arena = pool->free_list[pool->free_list_count].arena;
        int index = pool->free_list[pool->free_list_count].index;
        entry = &arena->entries[index];
        memset(entry, 0, sizeof(PIDEntry));
        LeaveCriticalSection(&pool->lock);
        return entry;
    }

    // Find arena with free space
    PIDEntryArena *arena = pool->current_arena;
    while (arena && arena->used >= arena->capacity) {
        arena = arena->next;
    }

    if (!arena) {
        // Need new arena
        int new_capacity = pool->current_arena->capacity * 2;
        PIDEntryArena *new_arena = malloc(sizeof(PIDEntryArena) + new_capacity * sizeof(PIDEntry));
        if (!new_arena) {
            LeaveCriticalSection(&pool->lock);
            return calloc(1, sizeof(PIDEntry));  // Fallback
        }

        new_arena->next = NULL;
        new_arena->capacity = new_capacity;
        new_arena->used = 0;

        // Link to current arena chain
        pool->current_arena->next = new_arena;
        pool->current_arena = new_arena;
        arena = new_arena;

        // Expand free list if needed
        if (pool->free_list_count + new_capacity > pool->free_list_capacity) {
            int new_fl_capacity = pool->free_list_capacity * 2;
            void *new_fl = realloc(pool->free_list, new_fl_capacity * sizeof(*pool->free_list));
            if (!new_fl) {
                // If we can't expand free list, we can still use the new arena
                // but won't be able to free entries from it later
                // For simplicity, we'll still proceed but log a warning
                fprintf(stderr, "Warning: Could not expand PID free list\n");
            } else {
                pool->free_list = new_fl;
                pool->free_list_capacity = new_fl_capacity;
            }
        }
    }

    if (arena && arena->used < arena->capacity) {
        entry = &arena->entries[arena->used++];
        memset(entry, 0, sizeof(PIDEntry));
    }

    LeaveCriticalSection(&pool->lock);
    return entry;
}

void pid_pool_free(PIDEntryPool *pool, PIDEntry *entry) {
    if (!pool || !pool->initialized || !entry) {
        free(entry);
        return;
    }

    EnterCriticalSection(&pool->lock);

    // Find which arena this entry belongs to
    PIDEntryArena *arena = pool->first_arena;
    while (arena) {
        if (entry >= arena->entries && entry < arena->entries + arena->used) {
            ptrdiff_t index = entry - arena->entries;
            if (index >= 0 && index < arena->used) {
                // Valid entry found - add to free list
                if (pool->free_list_count >= pool->free_list_capacity) {
                    // Expand free list
                    int new_capacity = pool->free_list_capacity * 2;
                    void *new_fl = realloc(pool->free_list, 
                                           new_capacity * sizeof(*pool->free_list));
                    if (new_fl) {
                        pool->free_list = new_fl;
                        pool->free_list_capacity = new_capacity;
                    } else {
                        // Can't expand - log warning once and leak (better than crashing)
                        static bool warned = false;
                        if (!warned) {
                            fprintf(stderr, "Warning: PID free list full, memory will leak until shutdown\n");
                            warned = true;
                        }
                        LeaveCriticalSection(&pool->lock);
                        return;
                    }
                }

                pool->free_list[pool->free_list_count].arena = arena;
                pool->free_list[pool->free_list_count].index = (int)index;
                pool->free_list_count++;

                LeaveCriticalSection(&pool->lock);
                return;
            }
        }
        arena = arena->next;
    }

    // Entry not found in any arena - must be from malloc fallback
    LeaveCriticalSection(&pool->lock);
    free(entry);
}

// -----------------------------------------------------------------------
// PID hash-map helpers
// -----------------------------------------------------------------------

int is_pid_in_map(PIDEntry *pid_map, unsigned int pid) {
    PIDEntry *entry;
    HASH_FIND_INT(pid_map, &pid, entry);
    return entry != NULL;
}

void free_pid_map_pool(PIDEntry *map, PIDEntryPool *pool) {
    if (!map) return;
    PIDEntry *current, *tmp;
    HASH_ITER(hh, map, current, tmp) {
        HASH_DEL(map, current);
        pid_pool_free(pool, current);
    }
}

// Pool-aware version of add_pid_to_map
void add_pid_to_map_pool(PIDEntry **pid_map, int pid, PIDEntryPool *pool) {
    PIDEntry *entry;
    HASH_FIND_INT(*pid_map, &pid, entry);
    if (entry) return; // Already present

    entry = pid_pool_alloc(pool);
    if (!entry) {
        fprintf(stderr, "add_pid_to_map_pool: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    entry->pid = pid;
    HASH_ADD_INT(*pid_map, pid, entry);
}

// Legacy: for maps whose entries came from plain malloc/calloc only (unused)
/*
void free_pid_map(PIDEntry *map) {
    if (!map) return;
    PIDEntry *current, *tmp;
    HASH_ITER(hh, map, current, tmp) {
        HASH_DEL(map, current);
        free(current);
    }
}
*/

// -----------------------------------------------------------------------
// Process enumeration
// -----------------------------------------------------------------------

int get_pids_from_name(const char *process_name, int **pid_list) {
    DWORD *processes = NULL;
    DWORD buf_size = 1024 * sizeof(DWORD);
    DWORD needed = 0;

    // Grow buffer until EnumProcesses returns all results
    while (1) {
        processes = realloc(processes, buf_size);
        if (!processes) {
            fprintf(stderr, "get_pids_from_name: memory allocation failed\n");
            return 0;
        }
        if (!EnumProcesses(processes, buf_size, &needed)) {
            fprintf(stderr, "get_pids_from_name: EnumProcesses failed\n");
            free(processes);
            return 0;
        }
        if (needed < buf_size) break;
        buf_size *= 2;
    }

    DWORD count = needed / sizeof(DWORD);
    int pid_count = 0;
    int *pids = malloc(count * sizeof(int));
    if (!pids) {
        free(processes);
        return 0;
    }

    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH] = {0};
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess) {
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseNameA(hProcess, hMod, name, sizeof(name));
                if (_stricmp(name, process_name) == 0)
                    pids[pid_count++] = processes[i];
            }
            CloseHandle(hProcess);
        }
    }

    free(processes);

    if (pid_count == 0) { free(pids); *pid_list = NULL; return 0; }
    int *trimmed = realloc(pids, pid_count * sizeof(int));
    *pid_list = trimmed ? trimmed : pids;
    return pid_count;
}

bool is_process_alive(int pid) {
    if (pid <= 0) return false;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!hProcess) return false;

    // Check if the process handle is signaled (i.e., it has exited)
    DWORD waitResult = WaitForSingleObject(hProcess, 0);
    if (waitResult == WAIT_OBJECT_0) {
        CloseHandle(hProcess);
        return false;
    }

    // Double-check via exit code (catches zombies)
    DWORD exitCode;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        if (exitCode != STILL_ACTIVE) {
            CloseHandle(hProcess);
            return false;
        }
    } else {
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}

// -----------------------------------------------------------------------
// PID table cache - lifecycle
// -----------------------------------------------------------------------

void pid_cache_init(PidTableCache *cache, double cache_ttl_ms,
                    double perf_frequency) {
    memset(cache, 0, sizeof(*cache));
    cache->ttl_ticks = (LONGLONG)(cache_ttl_ms * perf_frequency / 1000.0);
}

void pid_cache_cleanup(PidTableCache *cache) {
    if (!cache) return;
    free(cache->tcp4_table); cache->tcp4_table = NULL;
    free(cache->tcp6_table); cache->tcp6_table = NULL;
    free(cache->udp4_table); cache->udp4_table = NULL;
    free(cache->udp6_table); cache->udp6_table = NULL;
}

// -----------------------------------------------------------------------
// PID table cache - refresh
// -----------------------------------------------------------------------

// Internal:  fetch one extended table generically.
// family:    AF_INET or AF_INET6
// get_fn:    GetExtendedTcpTable or GetExtendedUdpTable
// class_id:  TCP_TABLE_OWNER_PID_ALL or UDP_TABLE_OWNER_PID
// is_tcp:    true for TCP, false for UDP
static void *fetch_owner_pid_table(int family, int class_id, bool is_tcp) {
    DWORD size = 0;
    DWORD result;

    if (is_tcp)
        result = GetExtendedTcpTable(NULL, &size, FALSE, family, class_id, 0);
    else
        result = GetExtendedUdpTable(NULL, &size, FALSE, family, class_id, 0);

    if (result != ERROR_INSUFFICIENT_BUFFER) return NULL;

    void *table = malloc(size);
    if (!table) return NULL;

    if (is_tcp)
        result = GetExtendedTcpTable(table, &size, FALSE, family, class_id, 0);
    else
        result = GetExtendedUdpTable(table, &size, FALSE, family, class_id, 0);

    if (result != NO_ERROR) { free(table); return NULL; }
    return table;
}

void refresh_pid_cache(PidTableCache *cache) {
    LONGLONG now = get_time_ticks();

    if (now - cache->last_refresh_ticks < cache->ttl_ticks) return;

    // Free stale tables
    free(cache->tcp4_table); cache->tcp4_table = NULL;
    free(cache->tcp6_table); cache->tcp6_table = NULL;
    free(cache->udp4_table); cache->udp4_table = NULL;
    free(cache->udp6_table); cache->udp6_table = NULL;

    cache->tcp4_table = fetch_owner_pid_table(AF_INET, TCP_TABLE_OWNER_PID_ALL, true);
    cache->tcp6_table = fetch_owner_pid_table(AF_INET6, TCP_TABLE_OWNER_PID_ALL, true);
    cache->udp4_table = fetch_owner_pid_table(AF_INET, UDP_TABLE_OWNER_PID, false);
    cache->udp6_table = fetch_owner_pid_table(AF_INET6, UDP_TABLE_OWNER_PID, false);

    cache->last_refresh_ticks = now;
}

// -----------------------------------------------------------------------
// PID lookup from a captured packet
// -----------------------------------------------------------------------

DWORD get_packet_pid(PidTableCache *cache,
                     const WINDIVERT_ADDRESS *addr,
                     const char *packet, UINT packet_len) {
    PWINDIVERT_IPHDR ip_hdr = NULL;
    PWINDIVERT_IPV6HDR ipv6_hdr = NULL;
    PWINDIVERT_TCPHDR tcp_hdr = NULL;
    PWINDIVERT_UDPHDR udp_hdr = NULL;
    UINT8 protocol = 0;

    refresh_pid_cache(cache);

    if (!WinDivertHelperParsePacket((PVOID)packet, packet_len, &ip_hdr, &ipv6_hdr,
                                    &protocol, NULL, NULL,
                                    &tcp_hdr, &udp_hdr,
                                    NULL, NULL, NULL, NULL)) {
        return 0;
    }

    UINT8 local_addr[16] = {0};
    UINT16 local_port = 0;
    BOOL outbound = addr->Outbound;
    BOOL is_ipv6 = addr->IPv6;

    if (ip_hdr && !is_ipv6) {
        if (outbound) {
            memcpy(local_addr, &ip_hdr->SrcAddr, 4);
            if (tcp_hdr) local_port = ntohs(tcp_hdr->SrcPort);
            else if (udp_hdr) local_port = ntohs(udp_hdr->SrcPort);
        } else {
            memcpy(local_addr, &ip_hdr->DstAddr, 4);
            if (tcp_hdr) local_port = ntohs(tcp_hdr->DstPort);
            else if (udp_hdr) local_port = ntohs(udp_hdr->DstPort);
        }
    } else if (ipv6_hdr && is_ipv6) {
        if (outbound) {
            memcpy(local_addr, &ipv6_hdr->SrcAddr, 16);
            if (tcp_hdr) local_port = ntohs(tcp_hdr->SrcPort);
            else if (udp_hdr) local_port = ntohs(udp_hdr->SrcPort);
        } else {
            memcpy(local_addr, &ipv6_hdr->DstAddr, 16);
            if (tcp_hdr) local_port = ntohs(tcp_hdr->DstPort);
            else if (udp_hdr) local_port = ntohs(udp_hdr->DstPort);
        }
    } else {
        return 0; // Not an IP packet
    }

    DWORD pid = 0;

    if (tcp_hdr) {
        if (!is_ipv6 && cache->tcp4_table) {
            PMIB_TCPTABLE_OWNER_PID t = (PMIB_TCPTABLE_OWNER_PID)cache->tcp4_table;
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID *row = &t->table[i];
                if (ntohs((UINT16)row->dwLocalPort) == local_port &&
                    row->dwLocalAddr == *(DWORD *)local_addr) {
                    pid = row->dwOwningPid;
                    break;
                }
            }
        } else if (is_ipv6 && cache->tcp6_table) {
            PMIB_TCP6TABLE_OWNER_PID t = (PMIB_TCP6TABLE_OWNER_PID)cache->tcp6_table;
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                MIB_TCP6ROW_OWNER_PID *row = &t->table[i];
                if (ntohs((UINT16)row->dwLocalPort) == local_port &&
                    memcmp(row->ucLocalAddr, local_addr, 16) == 0) {
                    pid = row->dwOwningPid;
                    break;
                }
            }
        }
    } else if (udp_hdr) {
        if (!is_ipv6 && cache->udp4_table) {
            PMIB_UDPTABLE_OWNER_PID t = (PMIB_UDPTABLE_OWNER_PID)cache->udp4_table;
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID *row = &t->table[i];
                if (ntohs((UINT16)row->dwLocalPort) == local_port &&
                    row->dwLocalAddr == *(DWORD *)local_addr) {
                    pid = row->dwOwningPid;
                    break;
                }
            }
        } else if (is_ipv6 && cache->udp6_table) {
            PMIB_UDP6TABLE_OWNER_PID t = (PMIB_UDP6TABLE_OWNER_PID)cache->udp6_table;
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                MIB_UDP6ROW_OWNER_PID *row = &t->table[i];
                if (ntohs((UINT16)row->dwLocalPort) == local_port &&
                    memcmp(row->ucLocalAddr, local_addr, 16) == 0) {
                    pid = row->dwOwningPid;
                    break;
                }
            }
        }
    }

    return pid;
}
