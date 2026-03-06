#ifndef GUI_PROC_LIST_H
#define GUI_PROC_LIST_H

#include "gui_main.h"
#include "gui_state.h"
#include "gui_types.h"
#include "schedule.h"

// Accessors for AppState members needed by process list
HWND GetProcessListHWND(void);
int GetSortColumn(void);
bool GetSortAscending(void);
ProcFilter GetProcFilter(void);

// Process entry definition (only in this header)
typedef struct ProcessEntry {
    DWORD pids[MAX_PID_FOR_PROCESS];
    int pid_count;
    wchar_t name[MAX_PATH];
    wchar_t path[MAX_PATH];
    int icon_index;
    double dl_rate;
    double ul_rate;
    double dl_limit;
    double ul_limit;
    bool limited;
    bool expanded;
    bool is_sticky;
    bool is_running;

    double pid_dl_rate[MAX_PID_FOR_PROCESS];
    double pid_ul_rate[MAX_PID_FOR_PROCESS];
    double pid_dl_limit[MAX_PID_FOR_PROCESS];
    double pid_ul_limit[MAX_PID_FOR_PROCESS];
    bool pid_dl_limit_from_group[MAX_PID_FOR_PROCESS];
    bool pid_ul_limit_from_group[MAX_PID_FOR_PROCESS];

    uint64_t pid_dl_bytes_last[MAX_PID_FOR_PROCESS];
    uint64_t pid_ul_bytes_last[MAX_PID_FOR_PROCESS];

    uint64_t quota_in;
    uint64_t quota_out;
    uint64_t quota_in_used;
    uint64_t quota_out_used;

    Schedule schedule;
} ProcessEntry;

extern ProcessEntry g_processes[MAX_PROCESSES];
extern int g_process_count;

// Column IDs
enum {
    COL_PROCESS = 0,
    COL_PID,
    COL_DOWNLOAD,
    COL_UPLOAD,
    COL_DL_LIMIT,
    COL_UL_LIMIT,
    COL_QUOTA_IN,
    COL_QUOTA_OUT,
    COL_SCHEDULE,
    COL_ACTIONS,
    COL_COUNT
};

// Initialization
void CreateProcessList(HWND hParent);
void InitProcessListColumns(void);

// Refresh/update
void RefreshProcessList(void);
void UpdateProcessRatesFromStats(void);
void UpdateProcessLimits(void);
void UpdateProcessListDisplay(void);

// Sorting/display
void SortProcesses(void);
void RebuildDisplayRows(void);
void ApplyProcFilter(ProcFilter f);

// Cell editing
void ShowSetLimitDialog(HWND hParent, int proc_idx, int pid_sub, bool is_dl);
void ShowSetQuotaDialog(HWND hParent, int proc_idx, int pid_sub, bool is_in);
void ShowScheduleDialog(HWND hParent, int proc_idx);

// Context menu commands
void Cmd_LocateProcess(HWND hWnd);
void Cmd_SpecifyProcess(HWND hWnd);
void Cmd_RemoveStickyEntry(HWND hWnd);

// Sticky process registry
void Sticky_Load(void);
void Sticky_Save(void);
wchar_t *NormaliseProcessName(const wchar_t *src, wchar_t *dst, int len);
int FindStickyProc(const wchar_t *norm_name);
int UpsertStickyProc(const wchar_t *raw_name, const wchar_t *path);
void RemoveStickyProc(int idx);
void SyncStickyLimits(const ProcessEntry *proc);

// Notification handler
BOOL onProcessListNotify(HWND hWnd, LPARAM lParam);

// Accessors (for dialogs)
ProcessEntry* GetProcessEntry(int idx);
int GetProcessCount(void);

// Cell edit helpers
void CellEdit_Commit(void);
void CellEdit_Cancel(void);
LRESULT CALLBACK CellEditSubclassProc(HWND hWnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam,
                                      UINT_PTR uIdSubclass,
                                      DWORD_PTR dwRefData);

// Process function helpers
void UpdateProcessList(void);
int CompareProcessEntry(const void* a, const void* b);
// Unused function
//void UpdateProcessLimitForRow(int proc_idx, int pid_sub, bool is_dl, double new_limit);

#endif
