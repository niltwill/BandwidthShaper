// Process ListView: display, sorting, cell editing, context menu

#include "gui_constants.h"
#include "gui_state.h"
#include "gui_proc_list.h"
#include "gui_utils.h"
#include "gui_dialogs.h"
#include "resource.h"
#include "shaper_core.h"
#include "schedule.h"
#include <commctrl.h>
#include <psapi.h>
#include <shellapi.h>

static volatile LONG g_updating_limits = 0;  // Used in UpdateProcessLimits

// ---------------------------------------------------------------------------
// Static data (g_processes, g_rows, g_cellEdit, etc.)
// ---------------------------------------------------------------------------
ProcessEntry g_processes[MAX_PROCESSES];
static DisplayRow g_rows[MAX_DISPLAY_ROWS];
static int g_row_count = 0;
static CellEditState g_cellEdit = {0};
static int ListView_ColumnCount = 10;

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------
HWND GetProcessListHWND(void) {
    return g_app.hProcessList;
}

int GetSortColumn(void) {
    return g_app.sort_column;
}

bool GetSortAscending(void) {
    return g_app.sort_ascending;
}

ProcFilter GetProcFilter(void) {
    return g_app.proc_filter;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
void CreateProcessList(HWND hWnd) {
    g_app.hProcessList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
        0, 0, 0, 0, hWnd, (HMENU)IDC_PROCESS_LIST, g_hInst, NULL);

    ListView_SetExtendedListViewStyle(g_app.hProcessList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    // Add columns (same as before)
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    wchar_t header_text[64];

    struct { const wchar_t* text; int width; } cols[] = {  // make sure to keep this consistent in "onDpiChanged()"
        {L"Process",   S(170)},
        {L"PID",       S(55)},
        {L"Download",  S(75)},
        {L"Upload",    S(75)},
        {L"DL Limit",  S(75)},
        {L"UL Limit",  S(75)},
        {L"Quota In",  S(80)},
        {L"Quota Out", S(80)},
        {L"Schedule",  S(100)},
        {L"Actions",   S(70)}
    };

    for (int i = 0; i < ListView_ColumnCount; i++) {  // Need to have the same number as the defined columns
        lvc.iSubItem = i;

        // Add sort arrow to the default sort column (Process) with up arrow for ascending
        if (i == 0) {
            swprintf(header_text, 64, L"%s %s", cols[i].text, UP_ARROW);
            lvc.pszText = header_text;
        } else {
            lvc.pszText = (LPWSTR)cols[i].text;
        }

        lvc.cx = cols[i].width;
        ListView_InsertColumn(g_app.hProcessList, i, &lvc);
    }

    // Dark mode for the listview if applicable
    if (g_app.dark_mode) {
        // Remove grid lines in dark mode as they don't contrast well
        ListView_SetExtendedListViewStyle(g_app.hProcessList,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    } else {
        ListView_SetExtendedListViewStyle(g_app.hProcessList,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    }

}

void InitProcessListColumns(void) {
    // Column initialization if needed separate from creation
}

// ---------------------------------------------------------------------------
// Refresh the process list from system
// ---------------------------------------------------------------------------
void RefreshProcessList(void) {
    if (!g_app.hProcessList) return;

    // Never interrupt an in-progress cell edit
    if (g_cellEdit.hEdit) return;

    // Honour the interaction-pause flag (with safety auto-expiry)
    if (g_app.pause_refresh) {
        if ((LONG)(GetTickCount() - g_app.pause_until_tick) < 0)
            return;   // still within pause window
        // Safety expiry elapsed – resume automatically
        g_app.pause_refresh = false;
    }

    // ----------------------------------------------------------------
    // Save current state so we can merge it back after the enumeration.
    // We copy the full ProcessEntry array onto the heap.
    // ----------------------------------------------------------------
    ProcessEntry *old_procs = malloc(sizeof(ProcessEntry) * MAX_PROCESSES);
    if (!old_procs) return;  // Fail gracefully on OOM
    
    // Save current state under lock
    EnterCriticalSection(&g_app.process_lock);

    memcpy(old_procs, g_app.processes, sizeof(ProcessEntry) * MAX_PROCESSES);
    int old_count = g_app.process_count;

    // Save selection and scroll position
    int sel = ListView_GetNextItem(g_app.hProcessList, -1, LVNI_SELECTED);
    wchar_t selName[MAX_PATH] = {0};
    if (sel >= 0 && sel < g_row_count)
        wcsncpy(selName, g_app.processes[g_rows[sel].proc_idx].name, MAX_PATH);

    SCROLLINFO si = {sizeof(si), SIF_POS};
    GetScrollInfo(g_app.hProcessList, SB_VERT, &si);
    int savedScrollPos = si.nPos;

    LeaveCriticalSection(&g_app.process_lock);

    // Create shared image list
	//HIMAGELIST hImgList = ImageList_Create(GetSystemMetrics(SM_CXSMICON),
    //                                   GetSystemMetrics(SM_CYSMICON),
    //                                   ILC_COLOR32 | ILC_MASK, 256, 1);
    HIMAGELIST hImgList = ImageList_Create(process_iconSize, process_iconSize, ILC_COLOR32 | ILC_MASK, 256, 1);
    HIMAGELIST hOld = ListView_SetImageList(g_app.hProcessList, hImgList, LVSIL_SMALL);
    if (hOld) ImageList_Destroy(hOld);

    // ----------------------------------------------------------------
    // First pass: enumerate all running processes into rawProcs[]
    // ----------------------------------------------------------------
    RawProcess *rawProcs = malloc(sizeof(RawProcess) * MAX_PROCESSES);
    if (!rawProcs) {
        free(old_procs);
        return;  // Fail gracefully on OOM
    }
    int rawCount = 0;

    DWORD pids[1024];
    DWORD needed = 0;

    if (!EnumProcesses(pids, sizeof(pids), &needed)) {
        free(old_procs);
        free(rawProcs);
        return;
    }

    int pidCount = (int)(needed / sizeof(DWORD));

    for (int i = 0; i < pidCount && rawCount < MAX_PROCESSES; i++) {
        DWORD pid = pids[i];
        if (pid == 0) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                   FALSE, pid);
        if (!hProc) continue;

        wchar_t path[MAX_PATH] = {0};
        DWORD pathLen = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &pathLen)) {
            RawProcess *raw = &rawProcs[rawCount];
            raw->pid = pid;
            wcsncpy(raw->path, path, MAX_PATH);

            wchar_t *name = wcsrchr(path, L'\\');
            name = name ? name + 1 : path;
            wcsncpy(raw->name, name, MAX_PATH);

            // Strip .exe extension
            wchar_t *ext = raw->name;
            while ((ext = wcschr(ext, L'.')) != NULL) {
                if (_wcsicmp(ext, L".exe") == 0) { *ext = L'\0'; break; }
                ext++;
            }
            rawCount++;
        }
        CloseHandle(hProc);
    }

    // ----------------------------------------------------------------
    // Second pass: group by name, building a fresh g_app.processes[]
    // ----------------------------------------------------------------

    // Build fresh process list under lock
    EnterCriticalSection(&g_app.process_lock);

    memset(g_app.processes, 0, sizeof(ProcessEntry) * MAX_PROCESSES);
    g_app.process_count = 0;

    for (int i = 0; i < rawCount; i++) {
        // Find existing group for this name
        int existingIdx = -1;
        for (int j = 0; j < g_app.process_count; j++) {
            if (_wcsicmp(g_app.processes[j].name, rawProcs[i].name) == 0) {
                existingIdx = j;
                break;
            }
        }

        if (existingIdx >= 0) {
            ProcessEntry *entry = &g_app.processes[existingIdx];
            if (entry->pid_count < MAX_PID_FOR_PROCESS) {
                entry->pids[entry->pid_count++] = rawProcs[i].pid;
            } else {
                // Log warning - too many instances of same process
                wchar_t s[128];
                swprintf(s, 128, L"Warning: Process has more than %u instances, some ignored\n", MAX_PID_FOR_PROCESS);
                OutputDebugStringW(s);
            }
        } else {
            ProcessEntry *entry = &g_app.processes[g_app.process_count];
            entry->pids[0] = rawProcs[i].pid;
            entry->pid_count = 1;
            wcsncpy(entry->name, rawProcs[i].name, MAX_PATH);
            wcsncpy(entry->path, rawProcs[i].path, MAX_PATH);

            // Icon (first instance only)
            SHFILEINFOW sfi = {0};
            if (SHGetFileInfoW(rawProcs[i].path, 0, &sfi, sizeof(sfi),
                               SHGFI_ICON | SHGFI_SMALLICON)) {
                entry->icon_index = ImageList_AddIcon(hImgList, sfi.hIcon);
                DestroyIcon(sfi.hIcon);
            } else {
                entry->icon_index = -1;
            }
            g_app.process_count++;
        }
    }

    // Sort by name before merging so ordering is stable
    qsort(g_app.processes, g_app.process_count, sizeof(ProcessEntry),
          CompareProcessEntry);

    // ----------------------------------------------------------------
    // Third pass: merge preserved state from old_procs[] by name.
    // This restores expanded state, group limits, per-PID limits, and
    // the byte-snapshot arrays used for rate calculation.
    // ----------------------------------------------------------------
    for (int i = 0; i < g_app.process_count; i++) {
        ProcessEntry *entry = &g_app.processes[i];

        // Mark as running (it has live PIDs)
        entry->is_running = true;

        // Find matching old entry by name
        const ProcessEntry *old = NULL;
        for (int j = 0; j < old_count; j++) {
            if (_wcsicmp(old_procs[j].name, entry->name) == 0) {
                old = &old_procs[j];
                break;
            }
        }
        if (!old) {
            // Brand-new process: check if it matches a sticky entry and inherit its limits
            wchar_t norm[MAX_PATH];
            NormaliseProcessName(entry->name, norm, MAX_PATH);
            int si = FindStickyProc(norm);
            if (si >= 0) {
                entry->is_sticky = true;
                entry->dl_limit = g_app.sticky_procs[si].dl_limit;
                entry->ul_limit = g_app.sticky_procs[si].ul_limit;
                entry->quota_in = g_app.sticky_procs[si].quota_in;
                entry->quota_out = g_app.sticky_procs[si].quota_out;
                entry->schedule = g_app.sticky_procs[si].schedule;
                // Update stored path if we have a fresher one from the live exe
                if (entry->path[0] && !g_app.sticky_procs[si].path[0])
                    wcsncpy(g_app.sticky_procs[si].path, entry->path, MAX_PATH);
                // Propagate group limits to each PID
                for (int p = 0; p < entry->pid_count; p++) {
                    entry->pid_dl_limit[p] = entry->dl_limit;
                    entry->pid_ul_limit[p] = entry->ul_limit;
                    entry->pid_dl_limit_from_group[p] = (entry->dl_limit != 0.0);
                    entry->pid_ul_limit_from_group[p] = (entry->ul_limit != 0.0);
                }
            }
            continue;
        }

        // Restore user-visible state
        entry->expanded = old->expanded;
        entry->dl_limit = old->dl_limit;
        entry->ul_limit = old->ul_limit;
        entry->is_sticky = old->is_sticky;
        entry->quota_in = old->quota_in;
        entry->quota_out = old->quota_out;
        entry->quota_in_used = old->quota_in_used;
        entry->quota_out_used = old->quota_out_used;
        entry->schedule = old->schedule;

        // Restore per-PID limits and byte snapshots, matched by PID value
        for (int p = 0; p < entry->pid_count; p++) {
            bool found = false;
            for (int q = 0; q < old->pid_count; q++) {
                if (entry->pids[p] == old->pids[q]) {
                    // Found matching PID - restore its settings
                    entry->pid_dl_limit[p] = old->pid_dl_limit[q];
                    entry->pid_ul_limit[p] = old->pid_ul_limit[q];
                    entry->pid_dl_bytes_last[p] = old->pid_dl_bytes_last[q];
                    entry->pid_ul_bytes_last[p] = old->pid_ul_bytes_last[q];
                    entry->pid_dl_rate[p] = old->pid_dl_rate[q];
                    entry->pid_ul_rate[p] = old->pid_ul_rate[q];

                    entry->pid_dl_limit_from_group[p] = old->pid_dl_limit_from_group[q];
                    entry->pid_ul_limit_from_group[p] = old->pid_ul_limit_from_group[q];

                    found = true;
                    break;
                }
            }
            if (!found) {
                // New PID - initialize with group limits
                entry->pid_dl_limit[p] = entry->dl_limit;
                entry->pid_ul_limit[p] = entry->ul_limit;
                entry->pid_dl_bytes_last[p] = 0;
                entry->pid_ul_bytes_last[p] = 0;
                entry->pid_dl_rate[p] = 0;
                entry->pid_ul_rate[p] = 0;

                entry->pid_dl_limit_from_group[p] = (entry->dl_limit != 0.0);
                entry->pid_ul_limit_from_group[p] = (entry->ul_limit != 0.0);
            }
        }

        // Aggregate rates
        entry->dl_rate = 0;
        entry->ul_rate = 0;
        for (int p = 0; p < entry->pid_count; p++) {
            entry->dl_rate += entry->pid_dl_rate[p];
            entry->ul_rate += entry->pid_ul_rate[p];
        }
    }

    // ----------------------------------------------------------------
    // Fourth pass: inject ghost rows for sticky entries whose process is
    // not currently running.  We also try to load their icon from the
    // saved path so the icon appears even when the exe is absent.
    // ----------------------------------------------------------------
    for (int si = 0; si < g_app.sticky_count && g_app.process_count < MAX_PROCESSES; si++) {
        StickyEntry *se = &g_app.sticky_procs[si];

        // Check if already present as a live entry
        bool live = false;
        for (int i = 0; i < g_app.process_count; i++) {
            wchar_t norm[MAX_PATH];
            NormaliseProcessName(g_app.processes[i].name, norm, MAX_PATH);
            if (_wcsicmp(norm, se->name) == 0) {
                live = true;
                break;
            }
        }
        if (live) continue;

        // Also check old_procs for a just-exited process whose state we want to preserve
        const ProcessEntry *old_ghost = NULL;
        for (int j = 0; j < old_count; j++) {
            wchar_t norm[MAX_PATH];
            NormaliseProcessName(old_procs[j].name, norm, MAX_PATH);
            if (_wcsicmp(norm, se->name) == 0) {
                old_ghost = &old_procs[j];
                break;
            }
        }

        ProcessEntry *ghost = &g_app.processes[g_app.process_count];
        memset(ghost, 0, sizeof(*ghost));

        // Reconstruct display name: use stored original-case name if we have it
        // from a previous live sighting (old_ghost), otherwise capitalise first letter.
        if (old_ghost) {
            wcsncpy(ghost->name, old_ghost->name, MAX_PATH);
            ghost->expanded = old_ghost->expanded;
            ghost->quota_in = old_ghost->quota_in;
            ghost->quota_out = old_ghost->quota_out;
            ghost->quota_in_used = old_ghost->quota_in_used;
            ghost->quota_out_used = old_ghost->quota_out_used;
            // Restore schedule from sticky registry
            int _si2 = FindStickyProc(se->name);
            if (_si2 >= 0) ghost->schedule = g_app.sticky_procs[_si2].schedule;
        } else {
            wcsncpy(ghost->name, se->name, MAX_PATH);
            ghost->name[0] = towupper(ghost->name[0]);
        }

        wcsncpy(ghost->path, se->path, MAX_PATH);
        ghost->pid_count = 0;
        ghost->is_sticky = true;
        ghost->is_running = false;
        ghost->dl_limit = se->dl_limit;
        ghost->ul_limit = se->ul_limit;
        ghost->icon_index = -1;

        // Try to load icon from the saved exe path even when not running
        if (se->path[0]) {
            SHFILEINFOW sfi = {0};
            if (SHGetFileInfoW(se->path, 0, &sfi, sizeof(sfi),
                               SHGFI_ICON | SHGFI_SMALLICON)) {
                ghost->icon_index = ImageList_AddIcon(hImgList, sfi.hIcon);
                DestroyIcon(sfi.hIcon);
            }
        }

        g_app.process_count++;
    }

    // Re-sort after ghost injection (ghosts were appended at the end)
    qsort(g_app.processes, g_app.process_count, sizeof(ProcessEntry),
          CompareProcessEntry);

    LeaveCriticalSection(&g_app.process_lock);

    // Free heap allocations before returning
    free(old_procs);
    free(rawProcs);

    // Rebuild display rows (honours expanded flags we just restored)
    RebuildDisplayRows();

    // Restore selection by name
    if (selName[0] != L'\0') {
        for (int r = 0; r < g_row_count; r++) {
            if (g_rows[r].pid_sub == -1 &&
                _wcsicmp(g_app.processes[g_rows[r].proc_idx].name, selName) == 0) {
                ListView_SetItemState(g_app.hProcessList, r,
                                      LVIS_SELECTED | LVIS_FOCUSED,
                                      LVIS_SELECTED | LVIS_FOCUSED);
                break;
            }
        }
    }

    // Restore scroll
    si.nPos = savedScrollPos;
    SetScrollInfo(g_app.hProcessList, SB_VERT, &si, TRUE);

    // Update status bar
    wchar_t status[64];
    swprintf(status, 64, L"%d processes (%d instances)", g_app.process_count, rawCount);
    SendMessage(g_app.hStatusBar, SB_SETTEXT, 1, (LPARAM)status);
}

void UpdateProcessRatesFromStats(void) {
    if (!g_app.shaper) return;

    // Take atomic snapshot of all traffic
    TrafficSnapshot snapshot = {0};
    if (!shaper_snapshot_traffic(g_app.shaper, &snapshot)) {
        return;  // Snapshot failed
    }

    uint64_t now = snapshot.timestamp;
    static uint64_t lastTime = 0;
    uint64_t elapsed = (lastTime > 0 && now > lastTime) ? (now - lastTime) : 0;
    lastTime = now;

    if (elapsed == 0) {
        shaper_free_traffic_snapshot(&snapshot);
        return;
    }

    // Build quick lookup map from PID to snapshot entry
    // Use a simple array-based lookup for small snapshot sizes
    // Since snapshot.count is typically small (< 1000), O(n) lookup is fine
    bool need_rule_update = false;

    // Lock while reading process list
    EnterCriticalSection(&g_app.process_lock);

    // Update all processes using the snapshot
    for (int i = 0; i < g_app.process_count; i++) {
        ProcessEntry* proc = &g_app.processes[i];
        
        // Make a local copy of pid_count to prevent TOCTOU issues
        int pid_count = proc->pid_count;
        if (pid_count > MAX_PID_FOR_PROCESS) pid_count = MAX_PID_FOR_PROCESS;  // Safety clamp

        DWORD local_pids[MAX_PID_FOR_PROCESS];
        memcpy(local_pids, proc->pids, pid_count * sizeof(DWORD));

        proc->dl_rate = 0;
        proc->ul_rate = 0;

        for (int p = 0; p < pid_count; p++) {
            DWORD pid = local_pids[p];

            // Linear search through snapshot entries
            const TrafficSnapshotEntry *e = NULL;
            for (int s = 0; s < snapshot.count; s++) {
                if (snapshot.entries[s].pid == pid) {
                    e = &snapshot.entries[s];
                    break;
                }
            }

            if (e) {
                // Calculate deltas from last snapshot
                uint64_t dl_delta = e->dl_bytes >= proc->pid_dl_bytes_last[p] 
                                   ? e->dl_bytes - proc->pid_dl_bytes_last[p] : 0;
                uint64_t ul_delta = e->ul_bytes >= proc->pid_ul_bytes_last[p] 
                                   ? e->ul_bytes - proc->pid_ul_bytes_last[p] : 0;

                // Safe rate calculation with overflow protection
                if (dl_delta > UINT64_MAX / 1000) {
                    proc->pid_dl_rate[p] = (double)UINT64_MAX / (double)elapsed;
                } else {
                    proc->pid_dl_rate[p] = (double)(dl_delta * 1000) / (double)elapsed;
                }

                if (ul_delta > UINT64_MAX / 1000) {
                    proc->pid_ul_rate[p] = (double)UINT64_MAX / (double)elapsed;
                } else {
                    proc->pid_ul_rate[p] = (double)(ul_delta * 1000) / (double)elapsed;
                }

                // Update last seen bytes
                proc->pid_dl_bytes_last[p] = e->dl_bytes;
                proc->pid_ul_bytes_last[p] = e->ul_bytes;
            } else {
                // PID not found in snapshot - assume zero
                proc->pid_dl_rate[p] = 0;
                proc->pid_ul_rate[p] = 0;
            }

            proc->dl_rate += proc->pid_dl_rate[p];
            proc->ul_rate += proc->pid_ul_rate[p];
        }

        // Quota handling remains similar, but now using snapshot data
        if (proc->quota_in > 0 || proc->quota_out > 0) {
            bool prev_in_exhausted = (proc->quota_in  > 0 && proc->quota_in_used  >= proc->quota_in);
            bool prev_out_exhausted = (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out);

            // Aggregate traffic across all PIDs from snapshot
            uint64_t total_dl = 0, total_ul = 0;
            for (int p = 0; p < proc->pid_count; p++) {
                DWORD pid = proc->pids[p];
                for (int s = 0; s < snapshot.count; s++) {
                    if (snapshot.entries[s].pid == pid) {
                        total_dl += snapshot.entries[s].dl_bytes;
                        total_ul += snapshot.entries[s].ul_bytes;
                        break;
                    }
                }
            }

            proc->quota_in_used = total_dl;
            proc->quota_out_used = total_ul;

            bool now_in_exhausted = (proc->quota_in  > 0 && proc->quota_in_used  >= proc->quota_in);
            bool now_out_exhausted = (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out);

            if (prev_in_exhausted != now_in_exhausted || prev_out_exhausted != now_out_exhausted)
                need_rule_update = true;
        }
    }

    LeaveCriticalSection(&g_app.process_lock);

    shaper_free_traffic_snapshot(&snapshot);

    if (need_rule_update)
        UpdateProcessLimits();
}

// ---------------------------------------------------------------------------
// Update shaper rules based on process list limits
// ---------------------------------------------------------------------------
void UpdateProcessLimits(void) {
    if (!g_app.shaper) return;

    // Use atomic flag to prevent re-entrancy
    if (InterlockedCompareExchange(&g_updating_limits, 1, 0) != 0) {
        return;
    }

    // Check shaper state
    if (!shaper_is_running(g_app.shaper) || 
        shaper_get_thread_state(g_app.shaper) != SHAPER_THREAD_RUNNING) {
        InterlockedExchange(&g_updating_limits, 0);
        return;
    }

    // First, collect all rule data under process lock (heap allocation)
    int max_rules = MAX_PROCESSES * MAX_PID_FOR_PROCESS;
    RuleBuf *local_rules = malloc(sizeof(RuleBuf) * max_rules);
    if (!local_rules) {
        InterlockedExchange(&g_updating_limits, 0);
        return;
    }
    int local_rule_count = 0;

    EnterCriticalSection(&g_app.process_lock);

    for (int i = 0; i < g_app.process_count && local_rule_count < MAX_PROCESSES * 16; i++) {
        ProcessEntry* proc = &g_app.processes[i];

        if (proc->pid_count == 0) continue;

        // Schedule check
        if (proc->is_sticky && !schedule_is_empty(&proc->schedule)) {
            if (!schedule_is_active_now(&proc->schedule)) continue;
        }

        bool quota_in_exhausted = (proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in);
        bool quota_out_exhausted = (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out);

        for (int p = 0; p < proc->pid_count; p++) {
            double dl = 0.0, ul = 0.0;
            bool dl_blocked = false, ul_blocked = false;

            if (quota_in_exhausted) dl_blocked = true;
            if (quota_out_exhausted) ul_blocked = true;

            // Rate limits (only if not quota-blocked)
            if (!dl_blocked) {
                if (proc->pid_dl_limit[p] != 0.0) {
                    dl = (proc->pid_dl_limit[p] < 0) ? 0 : proc->pid_dl_limit[p];
                    dl_blocked = (proc->pid_dl_limit[p] < 0);
                } else if (proc->dl_limit != 0.0) {
                    dl = (proc->dl_limit < 0) ? 0 : proc->dl_limit;
                    dl_blocked = (proc->dl_limit < 0);
                }
            }

            if (!ul_blocked) {
                if (proc->pid_ul_limit[p] != 0.0) {
                    ul = (proc->pid_ul_limit[p] < 0) ? 0 : proc->pid_ul_limit[p];
                    ul_blocked = (proc->pid_ul_limit[p] < 0);
                } else if (proc->ul_limit != 0.0) {
                    ul = (proc->ul_limit < 0) ? 0 : proc->ul_limit;
                    ul_blocked = (proc->ul_limit < 0);
                }
            }

            if (dl_blocked || ul_blocked || dl != 0.0 || ul != 0.0) {
                RuleBuf* r = &local_rules[local_rule_count++];
                snprintf(r->pidStr, sizeof(r->pidStr), "%lu", proc->pids[p]);
                r->dl = dl;
                r->ul = ul;
                r->dl_blocked = dl_blocked;
                r->ul_blocked = ul_blocked;
                r->quota_in = proc->quota_in;
                r->quota_out = proc->quota_out;
                r->schedule = proc->schedule;
            }
        }
    }

    LeaveCriticalSection(&g_app.process_lock);

    // Now apply rules to shaper without holding any locks
    if (local_rule_count > 0) {
        shaper_clear_process_rules(g_app.shaper);

        for (int i = 0; i < local_rule_count; i++) {
            RuleBuf* r = &local_rules[i];
            if (shaper_add_process_rule(g_app.shaper, r->pidStr, r->dl, r->ul,
                                        r->dl_blocked, r->ul_blocked, r->quota_in, r->quota_out, &r->schedule)) {
                if (r->quota_in > 0 || r->quota_out > 0) {
                    shaper_set_process_quota(g_app.shaper, r->pidStr,
                                             r->quota_in, r->quota_out);
                }
            }
        }

        if (g_app.shaper && shaper_is_running(g_app.shaper)) {
            shaper_reload_rules(g_app.shaper);
        }
    }

    // Free heap allocation
    free(local_rules);

    InterlockedExchange(&g_updating_limits, 0);
}

// ---------------------------------------------------------------------------
// Sorting/display
// ---------------------------------------------------------------------------
// Function to sort the processes themselves (not the display rows)
void SortProcesses(void) {
    if (g_app.process_count <= 1) return;

    // Create index array for sorting
    int* indices = malloc(g_app.process_count * sizeof(int));
    if (!indices) return;

    for (int i = 0; i < g_app.process_count; i++) {
        indices[i] = i;
    }

    // Sort indices based on process comparison
    for (int i = 0; i < g_app.process_count - 1; i++) {
        for (int j = i + 1; j < g_app.process_count; j++) {
            ProcessEntry* proc_a = &g_app.processes[indices[i]];
            ProcessEntry* proc_b = &g_app.processes[indices[j]];

            int result = 0;
            switch (g_app.sort_column) {
            case 0: // Process name
                result = _wcsicmp(proc_a->name, proc_b->name);
                break;

            case 1: // PID (use first PID for process-level sorting)
                {
                    DWORD pid_a = proc_a->pid_count > 0 ? proc_a->pids[0] : 0;
                    DWORD pid_b = proc_b->pid_count > 0 ? proc_b->pids[0] : 0;
                    if (pid_a < pid_b) result = -1;
                    else if (pid_a > pid_b) result = 1;
                }
                break;

            case 2: // Download rate (process total)
                if (proc_a->dl_rate < proc_b->dl_rate) result = -1;
                else if (proc_a->dl_rate > proc_b->dl_rate) result = 1;
                break;

            case 3: // Upload rate (process total)
                if (proc_a->ul_rate < proc_b->ul_rate) result = -1;
                else if (proc_a->ul_rate > proc_b->ul_rate) result = 1;
                break;

            case 4: // DL Limit
                {
                    double limit_a = proc_a->dl_limit;
                    double limit_b = proc_b->dl_limit;

                    if (limit_a < 0 && limit_b >= 0) result = 1;
                    else if (limit_a >= 0 && limit_b < 0) result = -1;
                    else if (limit_a == 0 && limit_b > 0) result = -1;
                    else if (limit_a > 0 && limit_b == 0) result = 1;
                    else {
                        if (limit_a < limit_b) result = -1;
                        else if (limit_a > limit_b) result = 1;
                    }
                }
                break;

            case 5: // UL Limit
                {
                    double limit_a = proc_a->ul_limit;
                    double limit_b = proc_b->ul_limit;

                    if (limit_a < 0 && limit_b >= 0) result = 1;
                    else if (limit_a >= 0 && limit_b < 0) result = -1;
                    else if (limit_a == 0 && limit_b > 0) result = -1;
                    else if (limit_a > 0 && limit_b == 0) result = 1;
                    else {
                        if (limit_a < limit_b) result = -1;
                        else if (limit_a > limit_b) result = 1;
                    }
                }
                break;

            case 9: // Actions (sort by whether limited or not)
                {
                    bool limited_a = (proc_a->dl_limit != 0 || proc_a->ul_limit != 0);
                    bool limited_b = (proc_b->dl_limit != 0 || proc_b->ul_limit != 0);

                    if (limited_a && !limited_b) result = 1;
                    else if (!limited_a && limited_b) result = -1;
                }
                break;
            }

            // Apply sort direction and swap if needed
            if (g_app.sort_ascending ? (result > 0) : (result < 0)) {
                int temp = indices[i];
                indices[i] = indices[j];
                indices[j] = temp;
            }
        }
    }

    // Create a temporary array for sorting
    ProcessEntry* temp_array = malloc(g_app.process_count * sizeof(ProcessEntry));
    if (!temp_array) {
        free(indices);
        return;
    }

    // Copy processes in sorted order to temp array
    for (int i = 0; i < g_app.process_count; i++) {
        temp_array[i] = g_app.processes[indices[i]];
    }

    // Copy back to original array
    for (int i = 0; i < g_app.process_count; i++) {
        g_app.processes[i] = temp_array[i];
    }

    // Update process indices in any active cell editor
    if (g_cellEdit.hEdit) {
        // Find where the edited process moved to
        for (int i = 0; i < g_app.process_count; i++) {
            if (indices[i] == g_cellEdit.proc_idx) {
                g_cellEdit.proc_idx = i;
                break;
            }
        }
    }

    free(temp_array);
    free(indices);
}

// Rebuild g_rows from current process list (called after any expand/collapse change)
void RebuildDisplayRows(void) {
    g_cellEdit.suppress_killfocus = true;

    // First, ensure processes are sorted
    SortProcesses();

    // Build flat list in sorted process order
    g_row_count = 0;
    for (int i = 0; i < g_app.process_count && g_row_count < MAX_DISPLAY_ROWS; i++) {
        ProcessEntry *proc = &g_app.processes[i];

        // Apply view filter
        if (g_app.proc_filter == PROC_FILTER_STICKY_ONLY  && !proc->is_sticky)  continue;
        if (g_app.proc_filter == PROC_FILTER_RUNNING_ONLY && !proc->is_running) continue;

        // Add parent row
        g_rows[g_row_count].proc_idx = i;
        g_rows[g_row_count].pid_sub = -1;
        g_row_count++;

        // Add child rows if expanded
        if (g_app.processes[i].expanded && g_app.processes[i].pid_count > 1) {
            // For child rows, we need to sort them within the parent
            // Create array of child indices
            int* child_indices = malloc(g_app.processes[i].pid_count * sizeof(int));
            if (child_indices) {
                for (int p = 0; p < g_app.processes[i].pid_count; p++) {
                    child_indices[p] = p;
                }

                // Sort child indices based on the same column
                for (int ci = 0; ci < g_app.processes[i].pid_count - 1; ci++) {
                    for (int cj = ci + 1; cj < g_app.processes[i].pid_count; cj++) {
                        int result = 0;

                        switch (g_app.sort_column) {
                        case 1: // PID
                            {
                                DWORD pid_a = g_app.processes[i].pids[child_indices[ci]];
                                DWORD pid_b = g_app.processes[i].pids[child_indices[cj]];
                                if (pid_a < pid_b) result = -1;
                                else if (pid_a > pid_b) result = 1;
                            }
                            break;

                        case 2: // Download rate
                            {
                                double rate_a = g_app.processes[i].pid_dl_rate[child_indices[ci]];
                                double rate_b = g_app.processes[i].pid_dl_rate[child_indices[cj]];
                                if (rate_a < rate_b) result = -1;
                                else if (rate_a > rate_b) result = 1;
                            }
                            break;

                        case 3: // Upload rate
                            {
                                double rate_a = g_app.processes[i].pid_ul_rate[child_indices[ci]];
                                double rate_b = g_app.processes[i].pid_ul_rate[child_indices[cj]];
                                if (rate_a < rate_b) result = -1;
                                else if (rate_a > rate_b) result = 1;
                            }
                            break;

                        case 4: // DL Limit
                            {
                                double limit_a = g_app.processes[i].pid_dl_limit[child_indices[ci]];
                                double limit_b = g_app.processes[i].pid_dl_limit[child_indices[cj]];

                                if (limit_a == 0) limit_a = g_app.processes[i].dl_limit;
                                if (limit_b == 0) limit_b = g_app.processes[i].dl_limit;

                                if (limit_a < 0 && limit_b >= 0) result = 1;
                                else if (limit_a >= 0 && limit_b < 0) result = -1;
                                else if (limit_a == 0 && limit_b > 0) result = -1;
                                else if (limit_a > 0 && limit_b == 0) result = 1;
                                else {
                                    if (limit_a < limit_b) result = -1;
                                    else if (limit_a > limit_b) result = 1;
                                }
                            }
                            break;

                        case 5: // UL Limit
                            {
                                double limit_a = g_app.processes[i].pid_ul_limit[child_indices[ci]];
                                double limit_b = g_app.processes[i].pid_ul_limit[child_indices[cj]];

                                if (limit_a == 0) limit_a = g_app.processes[i].ul_limit;
                                if (limit_b == 0) limit_b = g_app.processes[i].ul_limit;

                                if (limit_a < 0 && limit_b >= 0) result = 1;
                                else if (limit_a >= 0 && limit_b < 0) result = -1;
                                else if (limit_a == 0 && limit_b > 0) result = -1;
                                else if (limit_a > 0 && limit_b == 0) result = 1;
                                else {
                                    if (limit_a < limit_b) result = -1;
                                    else if (limit_a > limit_b) result = 1;
                                }
                            }
                            break;
                        }

                        if (g_app.sort_ascending ? (result > 0) : (result < 0)) {
                            int temp = child_indices[ci];
                            child_indices[ci] = child_indices[cj];
                            child_indices[cj] = temp;
                        }
                    }
                }

                // Add child rows in sorted order
                for (int p = 0; p < g_app.processes[i].pid_count && g_row_count < MAX_DISPLAY_ROWS; p++) {
                    g_rows[g_row_count].proc_idx = i;
                    g_rows[g_row_count].pid_sub = child_indices[p];
                    g_row_count++;
                }

                free(child_indices);
            } else {
                // Fallback: add in original order (still better than nothing)
                for (int p = 0; p < g_app.processes[i].pid_count && g_row_count < MAX_DISPLAY_ROWS; p++) {
                    g_rows[g_row_count].proc_idx = i;
                    g_rows[g_row_count].pid_sub = p;
                    g_row_count++;
                }
            }
        }
    }

    ListView_SetItemCountEx(g_app.hProcessList, g_row_count, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

    g_cellEdit.suppress_killfocus = false;

    // Reposition in-place editor if open
    if (g_cellEdit.hEdit) {
        int target_row = -1;
        int target_col = g_cellEdit.is_dl ? IDC_PL_DL_LIMIT : IDC_PL_UL_LIMIT;
        for (int r = 0; r < g_row_count; r++) {
            if (g_rows[r].proc_idx == g_cellEdit.proc_idx
             && g_rows[r].pid_sub  == g_cellEdit.pid_sub) {
                target_row = r;
                break;
            }
        }
        if (target_row < 0) {
            CellEdit_Cancel();
        } else {
            RECT rc = {0};
            rc.left = target_col;
            if (ListView_GetSubItemRect(g_app.hProcessList, target_row, target_col,
                                        LVIR_BOUNDS, &rc)) {
                HWND hParent = GetParent(g_cellEdit.hEdit);
                MapWindowPoints(g_app.hProcessList, hParent, (LPPOINT)&rc, 2);
                SetWindowPos(g_cellEdit.hEdit, HWND_TOP,
                             rc.left, rc.top,
                             rc.right - rc.left, rc.bottom - rc.top,
                             SWP_NOACTIVATE | SWP_NOZORDER);
            }
        }
    }
}

// View > Processes filter
void ApplyProcFilter(ProcFilter f) {
    g_app.proc_filter = f;

    HMENU hBar = GetMenu(g_app.hMainWnd);
    if (hBar) {
        HMENU hView = GetSubMenu(hBar, 1);  // "View" is the second top-level item
        for (int i = 0; hView && i < GetMenuItemCount(hView); i++) {
            HMENU sub = GetSubMenu(hView, i);
            if (sub && GetMenuState(sub, ID_PROC_SHOW_ALL, MF_BYCOMMAND) != (UINT)-1) {
                CheckMenuItem(sub, ID_PROC_SHOW_ALL,
                    MF_BYCOMMAND | (f == PROC_FILTER_ALL ? MF_CHECKED : MF_UNCHECKED));
                CheckMenuItem(sub, ID_PROC_SHOW_CUSTOM,
                    MF_BYCOMMAND | (f == PROC_FILTER_STICKY_ONLY ? MF_CHECKED : MF_UNCHECKED));
                CheckMenuItem(sub, ID_PROC_SHOW_RUNNING,
                    MF_BYCOMMAND | (f == PROC_FILTER_RUNNING_ONLY ? MF_CHECKED : MF_UNCHECKED));
                break;
            }
        }
    }

    RebuildDisplayRows();
    InvalidateRect(g_app.hProcessList, NULL, FALSE);
}

// ---------------------------------------------------------------------------
// Cell editing
// ---------------------------------------------------------------------------
// Open (or re-open) a floating edit box over the given cell in the ListView.
// row is the display-row index; col is IDC_PL_DL_LIMIT or IDC_PL_UL_LIMIT.
void ShowSetLimitDialog(HWND hParent, int proc_idx, int pid_sub, bool is_dl) {
    // If the same cell is already being edited, just refocus it
    if (g_cellEdit.hEdit
     && g_cellEdit.proc_idx == proc_idx
     && g_cellEdit.pid_sub == pid_sub
     && g_cellEdit.is_dl == is_dl) {
        SetFocus(g_cellEdit.hEdit);
        return;
    }

    // Commit (not cancel) any editor that's open on a different cell
    if (g_cellEdit.hEdit) CellEdit_Commit();

    // Pause periodic refresh; it auto-resumes on commit/cancel
    g_app.pause_refresh = true;
    g_app.pause_until_tick = GetTickCount() + TIMER_PAUSE_UNTIL_TICK;

    // Find which display row this proc/pid maps to so we can get the cell rect
    int target_row = -1;
    int target_col = is_dl ? IDC_PL_DL_LIMIT : IDC_PL_UL_LIMIT;
    for (int r = 0; r < g_row_count; r++) {
        if (g_rows[r].proc_idx == proc_idx && g_rows[r].pid_sub == pid_sub) {
            target_row = r;
            break;
        }
    }
    if (target_row < 0) return;

    // Get the bounding rect of that sub-item in ListView client coords
    RECT rc = {0};
    rc.left = target_col;  // ListView_GetSubItemRect uses left for column index
    rc.top  = 0;
    if (!ListView_GetSubItemRect(g_app.hProcessList, target_row, target_col,
                                 LVIR_BOUNDS, &rc))
        return;

    // Convert to screen coords then to hParent client coords so we can
    // parent the edit box to hParent (gives correct z-order over the list)
    MapWindowPoints(g_app.hProcessList, hParent, (LPPOINT)&rc, 2);

    // Pre-fill with existing value (read under lock)
    double cur = 0;
    EnterCriticalSection(&g_app.process_lock);
    if (proc_idx >= 0 && proc_idx < g_app.process_count) {
        ProcessEntry* proc = &g_app.processes[proc_idx];
        cur = (pid_sub >= 0 && pid_sub < proc->pid_count)
            ? (is_dl ? proc->pid_dl_limit[pid_sub] : proc->pid_ul_limit[pid_sub])
            : (is_dl ? proc->dl_limit : proc->ul_limit);
    }
    LeaveCriticalSection(&g_app.process_lock);

    wchar_t initText[64] = {0};
    if (cur > 0)
        swprintf(initText, 64, L"%.2f", cur / UNIT_MULTIPLIERS[g_app.current_unit]);

    // Create the floating edit control
    g_cellEdit.hEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        initText,
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_LEFT,
        rc.left, rc.top,
        rc.right - rc.left, rc.bottom - rc.top,
        hParent, NULL, g_hInst, NULL);

    if (!g_cellEdit.hEdit) return;

    // Store context
    g_cellEdit.proc_idx = proc_idx;
    g_cellEdit.pid_sub = pid_sub;
    g_cellEdit.column = target_col;
    g_cellEdit.is_dl = is_dl;
    g_cellEdit.is_quota_edit = false;

    // Dark-theme the floating edit box so it matches the listview
    if (g_app.dark_mode)
        SetWindowTheme(g_cellEdit.hEdit, L"DarkMode_CFD", NULL);

    // Use a slightly larger font to match the ListView
    HFONT hFont = (HFONT)SendMessage(g_app.hProcessList, WM_GETFONT, 0, 0);
    if (hFont) SendMessage(g_cellEdit.hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Subclass to intercept keys and focus-loss
    SetWindowSubclass(g_cellEdit.hEdit, CellEditSubclassProc, 0, 0);

    // Select all text and give focus
    SendMessage(g_cellEdit.hEdit, EM_SETSEL, 0, -1);
    SetFocus(g_cellEdit.hEdit);
}

// Function for quota inline editing
void ShowSetQuotaDialog(HWND hParent, int proc_idx, int pid_sub, bool is_in) {
    // Quota can only be set on group rows, not PID sub-rows
    if (pid_sub >= 0) {
        MSGBOX(hParent,
            L"Quotas can only be set on the process group level, not on individual PIDs.",
            L"Set Quota", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // If the same cell is already being edited, just refocus it
    if (g_cellEdit.hEdit
     && g_cellEdit.proc_idx == proc_idx
     && g_cellEdit.pid_sub == pid_sub
     && g_cellEdit.is_quota_edit
     && g_cellEdit.is_dl == is_in) {  // is_dl reused as is_in
        SetFocus(g_cellEdit.hEdit);
        return;
    }

    // Commit (not cancel) any editor that's open on a different cell
    if (g_cellEdit.hEdit) CellEdit_Commit();

    // Pause periodic refresh; it auto-resumes on commit/cancel
    g_app.pause_refresh = true;
    g_app.pause_until_tick = GetTickCount() + TIMER_PAUSE_UNTIL_TICK;

    // Find which display row this proc maps to
    int target_row = -1;
    int target_col = is_in ? IDC_PL_QUOTA_IN : IDC_PL_QUOTA_OUT;
    for (int r = 0; r < g_row_count; r++) {
        if (g_rows[r].proc_idx == proc_idx && g_rows[r].pid_sub == -1) {
            target_row = r;
            break;
        }
    }
    if (target_row < 0) return;

    // Get the bounding rect of that sub-item in ListView client coords
    RECT rc = {0};
    rc.left = target_col;
    rc.top  = 0;
    if (!ListView_GetSubItemRect(g_app.hProcessList, target_row, target_col,
                                 LVIR_BOUNDS, &rc))
        return;

    // Convert to screen coords then to hParent client coords
    MapWindowPoints(g_app.hProcessList, hParent, (LPPOINT)&rc, 2);

    // Pre-fill with existing value (read under lock)
    uint64_t cur = 0;
    double cur_mb = 0;
    EnterCriticalSection(&g_app.process_lock);
    if (proc_idx >= 0 && proc_idx < g_app.process_count) {
        ProcessEntry* proc = &g_app.processes[proc_idx];
        cur = is_in ? proc->quota_in : proc->quota_out;
        cur_mb = cur / (1024.0 * 1024.0);
    }
    LeaveCriticalSection(&g_app.process_lock);

    wchar_t initText[64] = {0};
    if (cur_mb > 0)
        swprintf(initText, 64, L"%.1f", cur_mb);

    // Create the floating edit control
    g_cellEdit.hEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        initText,
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_LEFT,
        rc.left, rc.top,
        rc.right - rc.left, rc.bottom - rc.top,
        hParent, NULL, g_hInst, NULL);

    if (!g_cellEdit.hEdit) return;

    // Store context (reusing is_dl flag to indicate in/out)
    g_cellEdit.proc_idx = proc_idx;
    g_cellEdit.pid_sub = -1;  // Quotas only on group level
    g_cellEdit.column = target_col;
    g_cellEdit.is_dl = is_in;
    g_cellEdit.is_quota_edit = true;

    // Dark-theme the floating edit box so it matches the listview
    if (g_app.dark_mode)
        SetWindowTheme(g_cellEdit.hEdit, L"DarkMode_CFD", NULL);

    // Use a slightly larger font to match the ListView
    HFONT hFont = (HFONT)SendMessage(g_app.hProcessList, WM_GETFONT, 0, 0);
    if (hFont) SendMessage(g_cellEdit.hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Subclass to intercept keys and focus-loss
    SetWindowSubclass(g_cellEdit.hEdit, CellEditSubclassProc, 0, 0);

    // Select all text and give focus
    SendMessage(g_cellEdit.hEdit, EM_SETSEL, 0, -1);
    SetFocus(g_cellEdit.hEdit);
}

void ShowScheduleDialog(HWND hParent, int proc_idx) {
    if (proc_idx < 0 || proc_idx >= g_app.process_count) return;
    ProcessEntry *proc = &g_app.processes[proc_idx];
    if (!proc->is_sticky) return;

    // Minimal DLGTEMPLATE with cx=cy=0.
    // The dialog manager creates the window at the OS default size;
    // we immediately resize it in WM_INITDIALOG via SetWindowPos.
#pragma pack(push, 2)
    struct {
        DLGTEMPLATE tmpl;
        WORD        menu;      // 0 = no menu
        WORD        winClass;  // 0 = predefined dialog class
        WCHAR       title[1];  // empty; we set it in WM_INITDIALOG
    } dlgBuf = {0};
#pragma pack(pop)

    dlgBuf.tmpl.style = DS_MODALFRAME | WS_CAPTION | WS_POPUP | WS_SYSMENU;
    dlgBuf.tmpl.cx = 0;  // sized in WM_INITDIALOG
    dlgBuf.tmpl.cy = 0;
    dlgBuf.tmpl.cdit = 0;

    ScheduleDlgCtx *ctx = (ScheduleDlgCtx *)calloc(1, sizeof(*ctx));
    if (!ctx) return;
    ctx->proc_idx = proc_idx;
    ctx->initial = proc->schedule;
    ctx->current = proc->schedule;

    DialogBoxIndirectParamW(g_hInst,
                            &dlgBuf.tmpl,
                            hParent,
                            ScheduleDlgProc,
                            (LPARAM)ctx);
    // ctx is freed in WM_NCDESTROY!
}

// ---------------------------------------------------------------------------
// Context menu commands
// ---------------------------------------------------------------------------
// File > Locate process...
void Cmd_LocateProcess(HWND hWnd) {
    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrTitle = L"Locate Process Executable";
    if (!GetOpenFileNameW(&ofn)) return;

    wchar_t *fname = wcsrchr(path, L'\\');
    fname = fname ? fname + 1 : path;

    int si = UpsertStickyProc(fname, path);
    if (si < 0) {
        MSGBOX(hWnd, L"Sticky process list is full (max 64).",
                    L"Locate Process", MB_OK | MB_ICONWARNING);
        return;
    }
    RefreshProcessList();
    Sticky_Save();
    wchar_t msg[MAX_PATH + 64];
    swprintf(msg, MAX_PATH + 64, L"Sticky entry added: %s",
             g_app.sticky_procs[si].name);
    SendMessageW(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)msg);
}

// File > Specify process...
void Cmd_SpecifyProcess(HWND hWnd) {
    wchar_t name[MAX_PATH] = {0};
    INT_PTR res = DialogBoxParamW(g_hInst,
                                  MAKEINTRESOURCE(IDD_SPECIFY_PROC),
                                  hWnd,
                                  SpecifyProcDlgProc,
                                  (LPARAM)name);
    if (res != IDOK || name[0] == L'\0') return;

    int si = UpsertStickyProc(name, NULL);
    if (si < 0) {
        MSGBOX(hWnd, L"Sticky process list is full (max 64).",
                    L"Specify Process", MB_OK | MB_ICONWARNING);
        return;
    }
    RefreshProcessList();
    Sticky_Save();
    wchar_t msg[MAX_PATH + 64];
    swprintf(msg, MAX_PATH + 64, L"Sticky entry added: %s",
             g_app.sticky_procs[si].name);
    SendMessageW(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)msg);
}

// File > Remove sticky entry  (acts on the selected row)
void Cmd_RemoveStickyEntry(HWND hWnd) {
    int sel = ListView_GetNextItem(g_app.hProcessList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= g_row_count) return;

    DisplayRow *dr = &g_rows[sel];

    EnterCriticalSection(&g_app.process_lock);
    ProcessEntry *proc = &g_app.processes[dr->proc_idx];

    if (!proc->is_sticky) {
        LeaveCriticalSection(&g_app.process_lock);
        MSGBOX(hWnd,
            L"The selected process is not a sticky entry.\n\n"
            L"Right-click a running process and choose \x201CPin as sticky \u25CC\x201D "
            L"to make it persistent, or use File \x203A Locate / Specify process.",
            L"Remove Sticky Entry", MB_OK | MB_ICONINFORMATION);
        return;
    }

    wchar_t proc_name[MAX_PATH];
    wcsncpy(proc_name, proc->name, MAX_PATH);
    LeaveCriticalSection(&g_app.process_lock);

    wchar_t confirm[MAX_PATH + 128];
    swprintf(confirm, MAX_PATH + 128,
             L"Remove sticky entry for \"%s\"?\n\n"
             L"Saved limits will be discarded. "
             L"If the process is currently running it will stay in the list until it exits.",
             proc_name);
    if (MSGBOX(hWnd, confirm, L"Remove Sticky Entry",
                    MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    wchar_t norm[MAX_PATH];
    NormaliseProcessName(proc_name, norm, MAX_PATH);
    int ci = FindStickyProc(norm);
    if (ci >= 0) RemoveStickyProc(ci);

    EnterCriticalSection(&g_app.process_lock);
    // Update the process entry after registry change
    for (int i = 0; i < g_app.process_count; i++) {
        if (_wcsicmp(g_app.processes[i].name, proc_name) == 0) {
            g_app.processes[i].is_sticky = false;
            break;
        }
    }
    LeaveCriticalSection(&g_app.process_lock);

    Sticky_Save();
    RefreshProcessList();
}

// ---------------------------------------------------------------------------
// Sticky process registry
// ---------------------------------------------------------------------------
void Sticky_Load(void) {
    wchar_t cfg[MAX_PATH];
    if (!Settings_GetPath(cfg, MAX_PATH)) return;
    const wchar_t *S = L"StickyProcesses";
    wchar_t key[32], buf[MAX_PATH];

    GetPrivateProfileStringW(S, L"Count", L"0", buf, 8, cfg);
    int count = _wtoi(buf);
    if (count <= 0 || count > MAX_STICKY_PROCS) count = 0;

    for (int i = 0; i < count; i++) {
        swprintf(key, 32, L"Name%d", i);
        GetPrivateProfileStringW(S, key, L"", buf, MAX_PATH, cfg);
        if (buf[0] == L'\0') {
            // Skip empty entries but don't break the loop
            continue;
        }

        // Only increment if we actually add an entry
        StickyEntry *se = &g_app.sticky_procs[g_app.sticky_count];
        memset(se, 0, sizeof(*se));
        wcsncpy(se->name, buf, MAX_PATH);

        swprintf(key, 32, L"Path%d", i);
        GetPrivateProfileStringW(S, key, L"", buf, MAX_PATH, cfg);
        wcsncpy(se->path, buf, MAX_PATH);

        swprintf(key, 32, L"DL%d", i);
        GetPrivateProfileStringW(S, key, L"0", buf, 32, cfg);
        se->dl_limit = _wtof(buf);

        swprintf(key, 32, L"UL%d", i);
        GetPrivateProfileStringW(S, key, L"0", buf, 32, cfg);
        se->ul_limit = _wtof(buf);

        swprintf(key, 32, L"QuotaIn%d", i);
        GetPrivateProfileStringW(S, key, L"0", buf, 32, cfg);
        se->quota_in = (uint64_t)_wcstoui64(buf, NULL, 10);

        swprintf(key, 32, L"QuotaOut%d", i);
        GetPrivateProfileStringW(S, key, L"0", buf, 32, cfg);
        se->quota_out = (uint64_t)_wcstoui64(buf, NULL, 10);

        swprintf(key, 32, L"Schedule%d", i);
        GetPrivateProfileStringW(S, key, L"", buf, SCHEDULE_STR_MAX, cfg);
        schedule_parsew(buf, &se->schedule);

        se->is_sticky = true;  // Loaded entries are sticky
        g_app.sticky_count++;
    }
}

void Sticky_Save(void) {
    if (!g_app.options.save_sticky_settings || !g_app.options.save_settings) return;
    wchar_t cfg[MAX_PATH];
    if (!Settings_GetPath(cfg, MAX_PATH)) return;
    const wchar_t *S = L"StickyProcesses";
    wchar_t key[32], buf[MAX_PATH + 32];

    // Delete the entire section to start fresh
    WritePrivateProfileStringW(S, NULL, NULL, cfg);

    if (!g_app.options.save_sticky_settings) return;

    // Count how many entries are actually sticky
    int actual_sticky_count = 0;
    for (int i = 0; i < g_app.sticky_count; i++) {
        if (g_app.sticky_procs[i].is_sticky) {
            actual_sticky_count++;
        }
    }

    if (actual_sticky_count != 0) {
        swprintf(buf, 64, L"%d", g_app.sticky_count);
        WritePrivateProfileStringW(S, L"Count", buf, cfg);
    }

    for (int i = 0; i < g_app.sticky_count; i++) {
        if (!g_app.sticky_procs[i].is_sticky) continue;

        const StickyEntry *se = &g_app.sticky_procs[i];

        swprintf(key, 32, L"Name%d", i);
        WritePrivateProfileStringW(S, key, se->name, cfg);

        swprintf(key, 32, L"Path%d", i);
        WritePrivateProfileStringW(S, key, se->path, cfg);

        swprintf(key, 32, L"DL%d", i);
        swprintf(buf, 32, L"%.0f", se->dl_limit);
        WritePrivateProfileStringW(S, key, buf, cfg);

        swprintf(key, 32, L"UL%d", i);
        swprintf(buf, 32, L"%.0f", se->ul_limit);
        WritePrivateProfileStringW(S, key, buf, cfg);

        swprintf(key, 32, L"QuotaIn%d", i);
        swprintf(buf, 32, L"%llu", (unsigned long long)se->quota_in);
        WritePrivateProfileStringW(S, key, buf, cfg);

        swprintf(key, 32, L"QuotaOut%d", i);
        swprintf(buf, 32, L"%llu", (unsigned long long)se->quota_out);
        WritePrivateProfileStringW(S, key, buf, cfg);

        swprintf(key, 32, L"Schedule%d", i);
        wchar_t sched_buf[SCHEDULE_STR_MAX];
        schedule_formatw(&se->schedule, sched_buf, SCHEDULE_STR_MAX);
        WritePrivateProfileStringW(S, key, sched_buf, cfg);
    }
}

// Strip .exe and lowercase into dst.  Returns dst.
wchar_t *NormaliseProcessName(const wchar_t *src, wchar_t *dst, int len) {
    wcsncpy(dst, src, len - 1);
    dst[len - 1] = L'\0';
    wchar_t *dot = dst;
    while ((dot = wcschr(dot, L'.')) != NULL) {
        if (_wcsicmp(dot, L".exe") == 0) { *dot = L'\0'; break; }
        dot++;
    }
    for (wchar_t *p = dst; *p; p++) *p = towlower(*p);
    return dst;
}

int FindStickyProc(const wchar_t *norm_name) {
    for (int i = 0; i < g_app.sticky_count; i++)
        if (_wcsicmp(g_app.sticky_procs[i].name, norm_name) == 0) return i;
    return -1;
}

// Add or update a sticky entry.  Returns its index, or -1 if the list is full.
// Existing limits are never overwritten by this call (they survive round-trips).
int UpsertStickyProc(const wchar_t *raw_name, const wchar_t *path) {
    wchar_t norm[MAX_PATH];
    NormaliseProcessName(raw_name, norm, MAX_PATH);
    int idx = FindStickyProc(norm);
    if (idx >= 0) {
        // Update path if we didn't have one yet
        if (path && path[0] && !g_app.sticky_procs[idx].path[0])
            wcsncpy(g_app.sticky_procs[idx].path, path, MAX_PATH);
        // Ensure it's marked as sticky
        g_app.sticky_procs[idx].is_sticky = true;
        return idx;
    }
    if (g_app.sticky_count >= MAX_STICKY_PROCS) return -1;
    StickyEntry *se = &g_app.sticky_procs[g_app.sticky_count];
    memset(se, 0, sizeof(*se));
    wcsncpy(se->name, norm, MAX_PATH);
    if (path) wcsncpy(se->path, path, MAX_PATH);
    se->is_sticky = true;  // New entries are sticky by default
    return g_app.sticky_count++;
}

void RemoveStickyProc(int idx) {
    if (idx < 0 || idx >= g_app.sticky_count) return;
    g_app.sticky_procs[idx].is_sticky = false;
    for (int i = idx; i < g_app.sticky_count - 1; i++)
        g_app.sticky_procs[i] = g_app.sticky_procs[i + 1];
    g_app.sticky_count--;
}

void SyncStickyLimits(const ProcessEntry *proc) {
    if (!proc->is_sticky) return;
    wchar_t norm[MAX_PATH];
    NormaliseProcessName(proc->name, norm, MAX_PATH);
    int idx = FindStickyProc(norm);
    if (idx < 0) return;
    g_app.sticky_procs[idx].dl_limit = proc->dl_limit;
    g_app.sticky_procs[idx].ul_limit = proc->ul_limit;
    g_app.sticky_procs[idx].quota_in = proc->quota_in;
    g_app.sticky_procs[idx].quota_out = proc->quota_out;
    g_app.sticky_procs[idx].schedule = proc->schedule;
    if (proc->path[0] && !g_app.sticky_procs[idx].path[0])
        wcsncpy(g_app.sticky_procs[idx].path, proc->path, MAX_PATH);
}

// ---------------------------------------------------------------------------
// Notification handler
// ---------------------------------------------------------------------------
BOOL onProcessListNotify(HWND hWnd, LPARAM lParam) {
    LPNMHDR pnmh = (LPNMHDR)lParam;

    if (pnmh->idFrom == IDC_PROCESS_LIST) {
        switch (pnmh->code) {

        case LVN_COLUMNCLICK: {
            LPNMLISTVIEW pListView = (LPNMLISTVIEW)lParam;
            int clicked_column = pListView->iSubItem;

            // Toggle sort direction if clicking same column
            if (clicked_column == g_app.sort_column) {
                g_app.sort_ascending = !g_app.sort_ascending;
            } else {
                g_app.sort_column = clicked_column;
                g_app.sort_ascending = true;
            }

            // Update all column headers to remove arrows and add to new sort column
            LVCOLUMNW lvc = {0};
            lvc.mask = LVCF_TEXT;
            wchar_t header_text[64];

            // Column definitions (same as in CreateProcessList)
            const wchar_t* col_names[] = {
                L"Process", L"PID", L"Download", L"Upload",
                L"DL Limit", L"UL Limit", L"Quota In", L"Quota Out", L"Schedule", L"Actions"
            };

            for (int i = 0; i < ListView_ColumnCount; i++) {
                if (i == g_app.sort_column) {
                    swprintf(header_text, 64, L"%s %s", col_names[i],
                            g_app.sort_ascending ? UP_ARROW : DOWN_ARROW);
                } else {
                    wcsncpy(header_text, col_names[i], 64);
                }

                lvc.pszText = header_text;
                ListView_SetColumn(g_app.hProcessList, i, &lvc);
            }

            // Refresh the display with new sort order
            RebuildDisplayRows();
            InvalidateRect(g_app.hProcessList, NULL, FALSE);

            // Update status bar
            wchar_t status[128];
            swprintf(status, 128, L"Sorted by %s (%s)",
                    col_names[g_app.sort_column],
                    g_app.sort_ascending ? L"ascending" : L"descending");
            SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)status);

            return 0;
        }

        case LVN_GETDISPINFO: {
            NMLVDISPINFO* pDispInfo = (NMLVDISPINFO*)lParam;
            LVITEM* pItem = &(pDispInfo)->item;
            int row = pItem->iItem;

            if (row < 0 || row >= g_row_count) break;

            DisplayRow* dr = &g_rows[row];
            ProcessEntry* proc = &g_app.processes[dr->proc_idx];
            bool is_sub = (dr->pid_sub >= 0);
            int psub = dr->pid_sub;

            if (pItem->mask & LVIF_TEXT) {
                switch (pItem->iSubItem) {
                case 0: // Process name / PID label
                    if (is_sub) {
                        // Indent with spaces to show hierarchy
                        swprintf(pItem->pszText, pItem->cchTextMax,
                                 L"    %s PID %lu", SUB_PID, proc->pids[psub]);
                    } else {
                        // Choose marker for sticky entries
                        const wchar_t *marker = L"";
                        if (proc->is_sticky)
                            marker = proc->is_running ? MARKER_RUNNING : MARKER_GHOST;

                        // Show +/- toggle if multiple PIDs
                        if (proc->pid_count > 1) {
                            swprintf(pItem->pszText, pItem->cchTextMax,
                                     L"%s%s %s",
                                     marker,
                                     proc->expanded ? DOWN_ARROW : RIGHT_ARROW,
                                     proc->name);
                        } else {
                            swprintf(pItem->pszText, pItem->cchTextMax,
                                     L"%s%s", marker, proc->name);
                        }
                    }
                    break;
                case 1: // PID column
                    if (is_sub) {
                        swprintf(pItem->pszText, pItem->cchTextMax, L"%lu", proc->pids[psub]);
                    } else if (proc->pid_count == 0) {
                        wcsncpy(pItem->pszText, MARKER_NOTRUNNING, pItem->cchTextMax);
                    } else if (proc->pid_count == 1) {
                        swprintf(pItem->pszText, pItem->cchTextMax, L"%lu", proc->pids[0]);
                    } else {
                        swprintf(pItem->pszText, pItem->cchTextMax, L"%d inst.", proc->pid_count);
                    }
                    break;
                case 2: // Download rate
                    if (is_sub)
                        FormatRateFixed(pItem->pszText, pItem->cchTextMax, proc->pid_dl_rate[psub]);
                    else if (proc->pid_count == 0)
                        pItem->pszText[0] = L'\0';  // ghost: no rate
                    else
                        FormatRateFixed(pItem->pszText, pItem->cchTextMax, proc->dl_rate);
                    break;
                case 3: // Upload rate
                    if (is_sub)
                        FormatRateFixed(pItem->pszText, pItem->cchTextMax, proc->pid_ul_rate[psub]);
                    else if (proc->pid_count == 0)
                        pItem->pszText[0] = L'\0';  // ghost: no rate
                    else
                        FormatRateFixed(pItem->pszText, pItem->cchTextMax, proc->ul_rate);
                    break;
                case 4: { // DL Limit
                    double lim = 0.0;
                    wchar_t buf[32];

                    if (is_sub) {
                        // For sub-rows, show the actual PID limit if set, otherwise show group limit
                        if (proc->pid_dl_limit[psub] != 0.0) {
                            lim = proc->pid_dl_limit[psub];
                        } else {
                            lim = proc->dl_limit;
                        }

                        if (lim > 0)
                            FormatRateFixed(buf, sizeof(buf)/sizeof(wchar_t), lim);
                        else if (lim < 0)
                            wcsncpy(buf, L"Blocked", sizeof(buf)/sizeof(wchar_t));
                        else
                            wcsncpy(buf, L"-", sizeof(buf)/sizeof(wchar_t));
                    } else {
                        // For group row, show group limit
                        lim = proc->dl_limit;

                        // Check if there are mixed per-PID limits
                        bool has_per_pid_limits = false;
                        bool all_same = true;
                        double first_nonzero = 0.0;
                        bool first_found = false;

                        for (int p = 0; p < proc->pid_count; p++) {
                            if (proc->pid_dl_limit[p] != 0.0) {
                                has_per_pid_limits = true;
                                if (!first_found) {
                                    first_nonzero = proc->pid_dl_limit[p];
                                    first_found = true;
                                } else if (proc->pid_dl_limit[p] != first_nonzero) {
                                    all_same = false;
                                    break;
                                }
                            }
                        }

                        // Format the base limit
                        if (lim > 0)
                            FormatRateFixed(buf, sizeof(buf)/sizeof(wchar_t), lim);
                        else if (lim < 0)
                            wcsncpy(buf, L"Blocked", sizeof(buf)/sizeof(wchar_t));
                        else
                            wcsncpy(buf, L"-", sizeof(buf)/sizeof(wchar_t));

                        // Add asterisk if there are per-PID limits and they're not all the same
                        if (has_per_pid_limits && !all_same) {
                            wcsncat(buf, L" *", (sizeof(buf)/sizeof(wchar_t)) - wcslen(buf) - 1);
                        }
                    }

                    wcsncpy(pItem->pszText, buf, pItem->cchTextMax);
                    break;
                }
                case 5: { // UL Limit
                    double lim = 0.0;
                    wchar_t buf[32];

                    if (is_sub) {
                        // For sub-rows, show the actual PID limit if set, otherwise show group limit
                        if (proc->pid_ul_limit[psub] != 0.0) {
                            lim = proc->pid_ul_limit[psub];
                        } else {
                            lim = proc->ul_limit;
                        }

                        if (lim > 0)
                            FormatRateFixed(buf, sizeof(buf)/sizeof(wchar_t), lim);
                        else if (lim < 0)
                            wcsncpy(buf, L"Blocked", sizeof(buf)/sizeof(wchar_t));
                        else
                            wcsncpy(buf, L"-", sizeof(buf)/sizeof(wchar_t));
                    } else {
                        // For group row, show group limit
                        lim = proc->ul_limit;

                        // Check if there are mixed per-PID limits
                        bool has_per_pid_limits = false;
                        bool all_same = true;
                        double first_nonzero = 0.0;
                        bool first_found = false;

                        for (int p = 0; p < proc->pid_count; p++) {
                            if (proc->pid_ul_limit[p] != 0.0) {
                                has_per_pid_limits = true;
                                if (!first_found) {
                                    first_nonzero = proc->pid_ul_limit[p];
                                    first_found = true;
                                } else if (proc->pid_ul_limit[p] != first_nonzero) {
                                    all_same = false;
                                    break;
                                }
                            }
                        }

                        // Format the base limit
                        if (lim > 0)
                            FormatRateFixed(buf, sizeof(buf)/sizeof(wchar_t), lim);
                        else if (lim < 0)
                            wcsncpy(buf, L"Blocked", sizeof(buf)/sizeof(wchar_t));
                        else
                            wcsncpy(buf, L"-", sizeof(buf)/sizeof(wchar_t));

                        // Add asterisk if there are per-PID limits and they're not all the same
                        if (has_per_pid_limits && !all_same) {
                            wcsncat(buf, L" *", (sizeof(buf)/sizeof(wchar_t)) - wcslen(buf) - 1);
                        }
                    }

                    wcsncpy(pItem->pszText, buf, pItem->cchTextMax);
                    break;
                }
                case 6: { // Quota In
                    if (is_sub) {
                        pItem->pszText[0] = L'\0';
                        break;
                    }
                    if (proc->quota_in == 0) {
                        wcsncpy(pItem->pszText, L"-", pItem->cchTextMax);
                    } else {
                        bool exhausted = (proc->quota_in_used >= proc->quota_in);
                        double mb_limit = (double)proc->quota_in / (1024.0*1024.0);
                        double mb_used = (double)proc->quota_in_used / (1024.0*1024.0);
                        if (exhausted)
                            swprintf(pItem->pszText, pItem->cchTextMax,
                                     L"%.1f/%.1f MB !", mb_used, mb_limit);
                        else
                            swprintf(pItem->pszText, pItem->cchTextMax,
                                     L"%.1f/%.1f MB", mb_used, mb_limit);
                    }
                    break;
                }
                case 7: { // Quota Out
                    if (is_sub) {
                        pItem->pszText[0] = L'\0';
                        break;
                    }
                    if (proc->quota_out == 0) {
                        wcsncpy(pItem->pszText, L"-", pItem->cchTextMax);
                    } else {
                        bool exhausted = (proc->quota_out_used >= proc->quota_out);
                        double mb_limit = (double)proc->quota_out / (1024.0*1024.0);
                        double mb_used = (double)proc->quota_out_used / (1024.0*1024.0);
                        if (exhausted)
                            swprintf(pItem->pszText, pItem->cchTextMax,
                                     L"%.1f/%.1f MB !", mb_used, mb_limit);
                        else
                            swprintf(pItem->pszText, pItem->cchTextMax,
                                     L"%.1f/%.1f MB", mb_used, mb_limit);
                    }
                    break;
                }
                case 8: { // Schedule
                    if (is_sub) {
                        // Sub-rows (individual PIDs) never show the schedule
                        pItem->pszText[0] = L'\0';
                        break;
                    }
                    if (!proc->is_sticky) {
                        // Schedule is only relevant for sticky processes
                        pItem->pszText[0] = L'\0';
                        break;
                    }
                    wchar_t sched_buf[SCHEDULE_STR_MAX];
                    schedule_formatw(&proc->schedule, sched_buf, SCHEDULE_STR_MAX);
                    if (sched_buf[0] == L'\0') {
                        wcsncpy(pItem->pszText, L"-", pItem->cchTextMax);
                    } else {
                        wcsncpy(pItem->pszText, sched_buf, pItem->cchTextMax);
                    }
                    break;
                }
                case 9: // Actions
                    if (is_sub) {
                        pItem->pszText[0] = L'\0';
                    } else if (proc->dl_limit != 0 || proc->ul_limit != 0) {
                        wcsncpy(pItem->pszText, L"[Limited]", pItem->cchTextMax);
                    } else {
                        pItem->pszText[0] = L'\0';
                    }
                    break;
            }
            } // end if (LVIF_TEXT)

            if (pItem->mask & LVIF_IMAGE) {
                // Sub-rows never have icons; explicitly return -1 to prevent
                // the ListView caching the parent's icon index for these slots
                pItem->iImage = (!is_sub && proc->pid_count > 0) ? proc->icon_index : -1;
            }

            if (pItem->mask & LVIF_PARAM) {
                pItem->lParam = is_sub ? (LPARAM)proc->pids[psub] : (LPARAM)proc->pids[0];
            }

            return 0;
        }

        case NM_RCLICK: {
            LPNMITEMACTIVATE pItem = (LPNMITEMACTIVATE)lParam;
            int row = pItem->iItem;
            if (row < 0 || row >= g_row_count) return 0;

            DisplayRow* dr = &g_rows[row];
            ProcessEntry* proc = &g_app.processes[dr->proc_idx];
            bool is_sub = (dr->pid_sub >= 0);

            POINT pt;
            GetCursorPos(&pt);

            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, 1, L"Set Download Limit...");
            AppendMenuW(hMenu, MF_STRING, 2, L"Set Upload Limit...");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, 3, L"Remove Limits");
            AppendMenuW(hMenu, MF_STRING, 4, L"Block Process");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, 10, L"Set Quota In...");
            AppendMenuW(hMenu, MF_STRING, 11, L"Set Quota Out...");
            AppendMenuW(hMenu, MF_STRING, 12, L"Remove Quotas");
            // Schedule (sticky processes only, group row only)
            if (!is_sub && proc->is_sticky) {
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hMenu, MF_STRING, 20, L"Set Schedule...");
                if (!schedule_is_empty(&proc->schedule))
                    AppendMenuW(hMenu, MF_STRING, 21, L"Remove Schedule");
            }
            if (!is_sub && proc->pid_count > 1) {
                AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuW(hMenu, MF_STRING, 5,
                            proc->expanded ? L"Collapse PIDs" : L"Expand PIDs");
            }
            // Sticky toggle
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            if (proc->is_sticky) {
                AppendMenuW(hMenu, MF_STRING, 6, L"Remove sticky entry");
            } else {
                wchar_t menuText[64];
                swprintf(menuText, 64, L"Pin as sticky %s", MARKER_GHOST);
                AppendMenuW(hMenu, MF_STRING, 7, menuText);
            }

            SetForegroundWindow(hWnd);
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                    pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);

            switch (cmd) {
            case 1:  // Set DL limit
                ShowSetLimitDialog(hWnd, dr->proc_idx, dr->pid_sub, true);
                break;
            case 2:  // Set UL limit
                ShowSetLimitDialog(hWnd, dr->proc_idx, dr->pid_sub, false);
                break;
            case 3:  // Remove limits
                if (is_sub) {
                    // Remove limits for specific PID
                    proc->pid_dl_limit[dr->pid_sub] = 0;
                    proc->pid_ul_limit[dr->pid_sub] = 0;
                    proc->pid_dl_limit_from_group[dr->pid_sub] = false;
                    proc->pid_ul_limit_from_group[dr->pid_sub] = false;
                } else {
                    // Remove limits for entire group
                    proc->dl_limit = 0;
                    proc->ul_limit = 0;
                    for (int p = 0; p < proc->pid_count; p++) {
                        proc->pid_dl_limit[p] = 0;
                        proc->pid_ul_limit[p] = 0;
                        proc->pid_dl_limit_from_group[p] = false;
                        proc->pid_ul_limit_from_group[p] = false;
                    }
                }
                UpdateProcessLimits();
                SyncStickyLimits(proc);
                InvalidateRect(g_app.hProcessList, NULL, FALSE);
                break;
            case 4:  // Block
                if (is_sub) {
                    // Block specific PID
                    proc->pid_dl_limit[dr->pid_sub] = -1.0;
                    proc->pid_ul_limit[dr->pid_sub] = -1.0;
                } else {
                    // Block entire group
                    proc->dl_limit = -1.0;
                    proc->ul_limit = -1.0;
                    // Also block all PIDs in the group
                    for (int p = 0; p < proc->pid_count; p++) {
                        proc->pid_dl_limit[p] = -1.0;
                        proc->pid_ul_limit[p] = -1.0;
                    }
                }
                UpdateProcessLimits();
                InvalidateRect(g_app.hProcessList, NULL, FALSE);
                break;
            case 5:  // Toggle expand/collapse
            {
                int first_new_row = row + 1;
                proc->expanded = !proc->expanded;
                g_app.pause_refresh = true;
                g_app.pause_until_tick = GetTickCount() + TIMER_PAUSE_UNTIL_TICK;
                RebuildDisplayRows();
                ListView_RedrawItems(g_app.hProcessList, first_new_row, g_row_count - 1);
                InvalidateRect(g_app.hProcessList, NULL, FALSE);
                break;
            }
            case 6:  // Remove sticky
            {
                wchar_t norm[MAX_PATH];
                int ci;
                NormaliseProcessName(proc->name, norm, MAX_PATH);
                ci = FindStickyProc(norm);
                if (ci >= 0) RemoveStickyProc(ci);
                proc->is_sticky = false;
                Sticky_Save();
                RefreshProcessList();
                break;
            }
            case 7:  // Pin as sticky
            {
                int si = UpsertStickyProc(proc->name, proc->path);
                if (si >= 0) {
                    g_app.sticky_procs[si].dl_limit = proc->dl_limit;
                    g_app.sticky_procs[si].ul_limit = proc->ul_limit;
                    proc->is_sticky = true;
                    Sticky_Save();
                    InvalidateRect(g_app.hProcessList, NULL, FALSE);
                }
                break;
            }
            case 10: // Set Quota In
            {
                ShowSetQuotaDialog(hWnd, dr->proc_idx, dr->pid_sub, true);
                break;
            }
            case 11: // Set Quota Out
            {
                ShowSetQuotaDialog(hWnd, dr->proc_idx, dr->pid_sub, false);
                break;
            }
            case 12: // Remove Quotas
                proc->quota_in = 0;
                proc->quota_out = 0;
                proc->quota_in_used = 0;
                proc->quota_out_used = 0;
                // Also clear authoritative state in the core
                if (g_app.shaper) {
                    for (int p = 0; p < proc->pid_count; p++) {
                        char pidStr[16];
                        snprintf(pidStr, sizeof(pidStr), "%lu", proc->pids[p]);
                        shaper_reset_process_quota(g_app.shaper, pidStr, true);
                    }
                }
                SyncStickyLimits(proc);
                UpdateProcessLimits();
                InvalidateRect(g_app.hProcessList, NULL, FALSE);
                break;
            case 20: // Set Schedule
                if (!is_sub && proc->is_sticky)
                    ShowScheduleDialog(hWnd, dr->proc_idx);
                break;
            case 21: // Remove Schedule
                if (!is_sub && proc->is_sticky) {
                    schedule_init(&proc->schedule);
                    // Sync back to sticky registry
                    SyncStickyLimits(proc);
                    Sticky_Save();
                    InvalidateRect(g_app.hProcessList, NULL, FALSE);
                    // Re-arm so AnyScheduleActive() is re-evaluated promptly;
                    // if no schedules remain the timer settles to 30s.
                    RearmScheduleTimer(hWnd);
                }
                break;
            }
            return 0;
        }

        case NM_CLICK: {
            // Single click on arrow area for group rows toggles expand/collapse
            LPNMITEMACTIVATE pAct = (LPNMITEMACTIVATE)lParam;
            int row = pAct->iItem;
            if (row < 0 || row >= g_row_count) break;
            if (pAct->iSubItem != 0) break;

            DisplayRow* dr = &g_rows[row];
            if (dr->pid_sub >= 0) break;  // sub-row, nothing to toggle

            ProcessEntry* proc = &g_app.processes[dr->proc_idx];
            if (proc->pid_count <= 1) break;  // single PID, no expand/collapse

            // Get click position in client coordinates
            POINT pt;
            GetCursorPos(&pt);
            ScreenToClient(g_app.hProcessList, &pt);

            // Get the subitem rect to find the left edge
            RECT rc;
            if (!ListView_GetSubItemRect(g_app.hProcessList, row, 0, LVIR_BOUNDS, &rc))
                break;

            // Only toggle if click happens at the arrow marker (not icon or sticky marker)
            int arrowWidth = S(16);
            if (proc->is_sticky) arrowWidth += S(12);

            if (pt.x < (rc.left + arrowWidth) || pt.x > (rc.left + process_iconSize) + arrowWidth)
                break;  // Clicked outside arrow area

            proc->expanded = !proc->expanded;
            // Pause refresh so the user can click a sub-row
            {
                int first_new_row = row + 1;
                g_app.pause_refresh = true;
                g_app.pause_until_tick = GetTickCount() + TIMER_PAUSE_UNTIL_TICK;
                RebuildDisplayRows();
                ListView_RedrawItems(g_app.hProcessList, first_new_row, g_row_count - 1);
                InvalidateRect(g_app.hProcessList, NULL, FALSE);
            }
            return 0;
        }

        case NM_DBLCLK: {
            // Double-click on DL Limit, UL Limit, Quota In or Quota Out column opens inline edit dialog
            LPNMITEMACTIVATE pAct = (LPNMITEMACTIVATE)lParam;
            int row = pAct->iItem;
            if (row < 0 || row >= g_row_count) break;

            DisplayRow* dr = &g_rows[row];

            // Double-click on DL/UL Limit and Quota In/Out column opens inline edit
            if (pAct->iSubItem == IDC_PL_DL_LIMIT) {
                ShowSetLimitDialog(hWnd, dr->proc_idx, dr->pid_sub, true);
                return 0;
            } else if (pAct->iSubItem == IDC_PL_UL_LIMIT) {
                ShowSetLimitDialog(hWnd, dr->proc_idx, dr->pid_sub, false);
                return 0;
            } else if (pAct->iSubItem == IDC_PL_QUOTA_IN || pAct->iSubItem == IDC_PL_QUOTA_OUT) {
                ShowSetQuotaDialog(hWnd, dr->proc_idx, dr->pid_sub, pAct->iSubItem == IDC_PL_QUOTA_IN);
                return 0;
            } else if (pAct->iSubItem == IDC_PL_SCHEDULE) {
                // Only allow editing schedule for sticky processes
                ProcessEntry *proc = &g_app.processes[dr->proc_idx];
                if (proc->is_sticky && dr->pid_sub < 0) {
                    ShowScheduleDialog(hWnd, dr->proc_idx);
                }
                return 0;
            }

            // Double-click on Process column toggles expand/collapse for groups
            if (pAct->iSubItem == 0 && dr->pid_sub < 0) {
                ProcessEntry* proc = &g_app.processes[dr->proc_idx];
                if (proc->pid_count > 1) {
                    int first_new_row = row + 1;
                    proc->expanded = !proc->expanded;
                    g_app.pause_refresh = true;
                    g_app.pause_until_tick = GetTickCount() + TIMER_PAUSE_UNTIL_TICK;
                    RebuildDisplayRows();
                    ListView_RedrawItems(g_app.hProcessList, first_new_row, g_row_count - 1);
                    InvalidateRect(g_app.hProcessList, NULL, FALSE);
                    return 0;
                }
            }
            return 0;
        }

        // For darker highlight color
        case NM_CUSTOMDRAW: {
            LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;

            switch(lplvcd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;

            case CDDS_ITEMPREPAINT:
                if (g_app.dark_mode) {
                    lplvcd->clrText = DARK_TEXT_COLOR;
                    lplvcd->clrTextBk = DARK_LIST_COLOR;

                    // Check if this item is the one and only selected item
                    int selectedItem = ListView_GetNextItem(g_app.hProcessList, -1, LVNI_SELECTED);
                    if (!g_cellEdit.hEdit && 
                        (int)lplvcd->nmcd.dwItemSpec == selectedItem && 
                        selectedItem != -1) {

                        lplvcd->clrText = DEF_TEXT_COLOR;
                        lplvcd->clrTextBk = DEF_HIGHLIGHT_COLOR;
                    }

                    if (lplvcd->nmcd.uItemState & CDIS_SELECTED) {                  
                        // Tell Windows not to draw the default selection highlight
                        // by clearing the selection state in the draw struct
                        lplvcd->nmcd.uItemState &= ~CDIS_SELECTED;
                    }

                    // If editing, request subitem draw for the specific cell
                    if (g_cellEdit.hEdit &&
                        lplvcd->nmcd.dwItemSpec == (DWORD)g_cellEdit.proc_idx) {
                        return CDRF_NOTIFYSUBITEMDRAW;
                    }
                }
                return CDRF_NEWFONT;

            case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
                if (g_app.dark_mode) {
                    lplvcd->clrText = DARK_TEXT_COLOR;
                    lplvcd->clrTextBk = DARK_LIST_COLOR;

                    // Highlight the specific row being edited
                    if (g_cellEdit.hEdit &&
                        lplvcd->nmcd.dwItemSpec == (DWORD)g_cellEdit.proc_idx) {

                        lplvcd->clrTextBk = DARK_HIGHLIGHT_COLOR; // Dark blue highlight
                        lplvcd->clrText = DARK_TEXT_COLOR;        // White text
                    }
                }
                return CDRF_NEWFONT;				
            
            }
            break;
        }

        case LVN_ODCACHEHINT: {
            // Optional (TODO): Pre-fetch data for visible range
            // NMLVCACHEHINT* pCacheHint = (NMLVCACHEHINT*)lParam;
            // Preload icons or other data for range pCacheHint->iFrom to pCacheHint->iTo
            return 0;
        }

        case LVN_ODFINDITEM: {
            // Optional (TODO): Handle FindItem (Ctrl+F) for virtual lists
            // NMLVFINDITEM* pFindInfo = (NMLVFINDITEM*)lParam;
            // Return index of matching item or -1
            return 0;
        }

        } // end switch (pnmh->code)
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Accessors (for dialogs)
// ---------------------------------------------------------------------------
ProcessEntry* GetProcessEntry(int idx) {
    if (idx >= 0 && idx < g_app.process_count)
        return &g_app.processes[idx];
    return NULL;
}

int GetProcessCount(void) {
    return g_app.process_count;
}

// ---------------------------------------------------------------------------
// Cell edit helpers
// ---------------------------------------------------------------------------
// Commit the current value and destroy the edit box
void CellEdit_Commit(void) {
    if (!g_cellEdit.hEdit) return;
    wchar_t buf[64] = {0};
    GetWindowTextW(g_cellEdit.hEdit, buf, 64);

    // Capture context before DestroyWindow clears hEdit via WM_NCDESTROY
    int pidx = g_cellEdit.proc_idx;
    int psub = g_cellEdit.pid_sub;
    bool is_dl = g_cellEdit.is_dl;
    bool is_quota = g_cellEdit.is_quota_edit;
    HWND hParent = GetParent(g_cellEdit.hEdit);

    // Suppress killfocus during destroy so it doesn't re-enter
    g_cellEdit.suppress_killfocus = true;
    DestroyWindow(g_cellEdit.hEdit);
    g_cellEdit.hEdit = NULL;
    g_cellEdit.suppress_killfocus = false;

    // Update process under lock
    EnterCriticalSection(&g_app.process_lock);

    if (pidx < 0 || pidx >= g_app.process_count) {
        LeaveCriticalSection(&g_app.process_lock);
        return;
    }
    ProcessEntry* proc = &g_app.processes[pidx];

    if (is_quota) {
        double mb = _wtof(buf);
        uint64_t new_quota = 0;

        if (mb <= 0.0) {
            new_quota = 0;
        } else if (mb > 1e12) {
            LeaveCriticalSection(&g_app.process_lock);
            MSGBOX(hParent, 
                        L"Quota value too large (max 1 PB)", 
                        L"Invalid Input", MB_OK | MB_ICONWARNING);
            return;
        } else {
            new_quota = ParseQuotaInput(buf);
        }

        if (is_dl) {
            proc->quota_in = new_quota;
            if (new_quota == 0) proc->quota_in_used = 0;
        } else {
            proc->quota_out = new_quota;
            if (new_quota == 0) proc->quota_out_used = 0;
        }
        
        if (g_app.shaper && new_quota == 0) {
            for (int p = 0; p < proc->pid_count; p++) {
                char pidStr[16];
                snprintf(pidStr, sizeof(pidStr), "%lu", proc->pids[p]);
                shaper_reset_process_quota(g_app.shaper, pidStr, true);
            }
        }
    } else {
        double val = _wtof(buf) * UNIT_MULTIPLIERS[g_app.current_unit];
        if (psub >= 0 && psub < proc->pid_count) {
            if (is_dl) {
                proc->pid_dl_limit[psub] = val;
                proc->pid_dl_limit_from_group[psub] = false;
            } else {
                proc->pid_ul_limit[psub] = val;
                proc->pid_ul_limit_from_group[psub] = false;
            }
        } else {
            if (is_dl) {
                double old_limit = proc->dl_limit;
                proc->dl_limit = val;
                for (int p = 0; p < proc->pid_count; p++) {
                    if (proc->pid_dl_limit_from_group[p] ||
                        (proc->pid_dl_limit[p] == old_limit && old_limit != 0)) {
                        proc->pid_dl_limit[p] = val;
                        proc->pid_dl_limit_from_group[p] = true;
                    }
                }
            } else {
                double old_limit = proc->ul_limit;
                proc->ul_limit = val;
                for (int p = 0; p < proc->pid_count; p++) {
                    if (proc->pid_ul_limit_from_group[p] ||
                        (proc->pid_ul_limit[p] == old_limit && old_limit != 0)) {
                        proc->pid_ul_limit[p] = val;
                        proc->pid_ul_limit_from_group[p] = true;
                    }
                }
            }
        }
    }

    // Save sticky limits before releasing lock
    SyncStickyLimits(proc);

    LeaveCriticalSection(&g_app.process_lock);

    // Update shaper and UI outside lock
    PostMessage(g_app.hMainWnd, WM_APP_UPDATE_LIMITS, 0, 0);
    InvalidateRect(g_app.hProcessList, NULL, FALSE);
    g_app.pause_refresh = false;
}

void CellEdit_Cancel(void) {
    if (!g_cellEdit.hEdit) return;
    g_cellEdit.suppress_killfocus = true;
    DestroyWindow(g_cellEdit.hEdit);
    g_cellEdit.hEdit = NULL;
    g_cellEdit.suppress_killfocus = false;
    g_app.pause_refresh = false;   // resume periodic refresh
}

// Subclass proc: intercept Enter/Escape/Tab and focus loss
LRESULT CALLBACK CellEditSubclassProc(HWND hWnd, UINT msg,
                                              WPARAM wParam, LPARAM lParam,
                                              UINT_PTR uIdSubclass,
                                              DWORD_PTR dwRefData) {
    (void)uIdSubclass; (void)dwRefData; (void)lParam;
    switch (msg) {
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) { CellEdit_Commit(); return 0; }
        if (wParam == VK_ESCAPE) { CellEdit_Cancel(); return 0; }
        if (wParam == VK_TAB)    { CellEdit_Commit(); return 0; }
        break;

    case WM_KILLFOCUS: {
        if (g_cellEdit.suppress_killfocus) return 0;

        // wParam is the HWND that is receiving focus.
        // Keep the editor open if focus is staying within our own UI
        // (the ListView, the edit's parent window, or NULL during internal redraws).
        HWND focusTarget = (HWND)wParam;
        if (focusTarget == NULL
         || focusTarget == g_cellEdit.hEdit
         || focusTarget == GetParent(g_cellEdit.hEdit)) {
            // Focus is not leaving our window – keep the editor alive
            return 0;
        }

        // Focus is going to some other window - commit
        if (g_cellEdit.hEdit) CellEdit_Commit();
        return 0;
    }

    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, CellEditSubclassProc, 0);
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Process function helpers
// ---------------------------------------------------------------------------
// Update stats display (called when rates change)
void UpdateProcessList(void) {
    InvalidateRect(g_app.hProcessList, NULL, FALSE);
}

// Helper function for processes
int CompareProcessEntry(const void* a, const void* b) {
    const ProcessEntry* pa = (const ProcessEntry*)a;
    const ProcessEntry* pb = (const ProcessEntry*)b;
    return _wcsicmp(pa->name, pb->name);
}

// Unused function
/*
void UpdateProcessLimitForRow(int proc_idx, int pid_sub, bool is_dl, double new_limit) {
    EnterCriticalSection(&g_app.process_lock);

    if (proc_idx < 0 || proc_idx >= g_app.process_count) {
        LeaveCriticalSection(&g_app.process_lock);
        return;
    }
    ProcessEntry* proc = &g_app.processes[proc_idx];

    if (pid_sub >= 0 && pid_sub < proc->pid_count) {
        if (is_dl) {
            proc->pid_dl_limit[pid_sub] = new_limit;
            proc->pid_dl_limit_from_group[pid_sub] = false;
        } else {
            proc->pid_ul_limit[pid_sub] = new_limit;
            proc->pid_ul_limit_from_group[pid_sub] = false;
        }
    } else {
        if (is_dl) {
            double old_limit = proc->dl_limit;
            proc->dl_limit = new_limit;
            for (int p = 0; p < proc->pid_count; p++) {
                if (proc->pid_dl_limit_from_group[p] ||
                    (proc->pid_dl_limit[p] == old_limit && old_limit != 0)) {
                    proc->pid_dl_limit[p] = new_limit;
                    proc->pid_dl_limit_from_group[p] = true;
                }
            }
        } else {
            double old_limit = proc->ul_limit;
            proc->ul_limit = new_limit;
            for (int p = 0; p < proc->pid_count; p++) {
                if (proc->pid_ul_limit_from_group[p] ||
                    (proc->pid_ul_limit[p] == old_limit && old_limit != 0)) {
                    proc->pid_ul_limit[p] = new_limit;
                    proc->pid_ul_limit_from_group[p] = true;
                }
            }
        }
    }

    SyncStickyLimits(proc);
    LeaveCriticalSection(&g_app.process_lock);

    UpdateProcessLimits();
    InvalidateRect(g_app.hProcessList, NULL, FALSE);
}
*/