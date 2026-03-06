#ifndef GUI_TYPES_H
#define GUI_TYPES_H

#include "common.h"
#include "schedule.h"

// Unit conversion
typedef enum {
    UNIT_BYTES = 0,
    UNIT_KB,
    UNIT_MB,
    UNIT_GB,
    UNIT_COUNT
} RateUnit;

extern const double UNIT_MULTIPLIERS[UNIT_COUNT];
extern const wchar_t* UNIT_LABELS[UNIT_COUNT];

// View-filter for the process list
typedef enum {
    PROC_FILTER_ALL = 0,
    PROC_FILTER_STICKY_ONLY,
    PROC_FILTER_RUNNING_ONLY,
} ProcFilter;

// Sticky process registry
typedef struct StickyEntry {
    wchar_t name[MAX_PATH];
    wchar_t path[MAX_PATH];
    double dl_limit;
    double ul_limit;
    uint64_t quota_in;
    uint64_t quota_out;
    bool is_sticky;
    Schedule schedule;
} StickyEntry;

// Raw Process for RefreshProcessList
typedef struct RawProcess {
    DWORD pid;
    wchar_t name[MAX_PATH];
    wchar_t path[MAX_PATH];
} RawProcess;

// Display row for process list
typedef struct DisplayRow {
    int proc_idx;
    int pid_sub;
} DisplayRow;

// Cell edit state
typedef struct CellEditState {
    HWND hEdit;
    int proc_idx;
    int pid_sub;
    int column;
    bool is_dl;
    bool is_quota_edit;
    bool suppress_killfocus;
} CellEditState;

// Rule collection for shaper updates
typedef struct {
    char pidStr[16];
    double dl, ul;
    bool dl_blocked, ul_blocked;
    uint64_t quota_in, quota_out;
    Schedule schedule;
} RuleBuf;

// Sort entry for statistics
typedef struct {
    int idx;
    uint64_t total;
} SortEntry;

#endif
