#ifndef GUI_STATE_H
#define GUI_STATE_H

#include "common.h"
#include "gui_constants.h"
#include "gui_types.h"
#include "schedule.h"
#include "shaper_core.h"
#include <shellapi.h>

// Forward declaration for ProcessEntry
typedef struct ProcessEntry ProcessEntry;

// Full AppState definition
typedef struct AppState {
    // Window handles
    HWND hMainWnd;
    HWND hToolbar;
    HWND hStatusBar;
    HWND hProcessList;
    HWND hUnitCombo;
    HWND hStatsWnd;

    // Core shaper
    ShaperInstance *shaper;

    // Process tracking
    ProcessEntry *processes;
    int process_count;

    // Process list lock
    CRITICAL_SECTION process_lock;
    bool process_lock_initialized;

    // Statistics history
    double dl_history[SPARKLINE_SAMPLES];
    double ul_history[SPARKLINE_SAMPLES];
    int history_head;
    uint64_t prev_bytes_dl;
    uint64_t prev_bytes_ul;
    uint64_t prev_tick;

    // Settings
    RateUnit current_unit;
    bool minimize_to_tray;
    bool options_window_open;

    // Options (persisted)
    struct {
        unsigned int dl_buffer;
        unsigned int ul_buffer;
        int burst_size;
        unsigned int update_interval;
        bool update_by_packets;
        unsigned int update_cooldown;
        uint64_t data_cap;
        unsigned int tcp_limit;
        unsigned int udp_limit;
        unsigned int latency;
        float packet_loss;
        int priority;
        double global_dl_limit;
        double global_ul_limit;
        wchar_t selected_nics[256];
        bool save_settings;
        bool save_sticky_settings;
        wchar_t config_dir[MAX_PATH];
        wchar_t snapshot_dir[MAX_PATH];
    } options;

    // DPI awareness
    UINT dpi;
    HFONT hUiFont;

    // Tray
    NOTIFYICONDATAW nid;
    bool tray_added;

    // Last known stats snapshot
    ShaperStats last_stats;
    bool has_last_stats;
    wchar_t last_stats_text[768];

    // Per-process accumulated data totals
    struct {
        wchar_t name[MAX_PATH];
        wchar_t description[256];
        uint64_t dl_bytes;
        uint64_t ul_bytes;
        uint64_t dl_bytes_snap[MAX_PID_FOR_PROCESS];
        uint64_t ul_bytes_snap[MAX_PID_FOR_PROCESS];
        int pid_count;
        DWORD pids[MAX_PID_FOR_PROCESS];
    } proc_stats[MAX_PROCESSES];
    int proc_stats_count;

    // Pause periodic process-list refresh
    bool pause_refresh;
    DWORD pause_until_tick;

    // Sorting state
    int sort_column;
    bool sort_ascending;

    // Frequency index
    int freq_idx;

    // Warning
    wchar_t missing_nic_warning[256];

    // Sticky process registry
    StickyEntry sticky_procs[MAX_STICKY_PROCS];
    int sticky_count;

    // Process list view filter
    ProcFilter proc_filter;

    // Dark mode
    bool dark_mode;
    HBRUSH hDarkBrush;
    HBRUSH hDarkListBrush;
    HBRUSH hDarkBtnBrush;
    HBRUSH hDarkToolbarBrush;
    COLORREF dark_bg;
    COLORREF dark_list_bg;
    COLORREF dark_text;
} AppState;

extern AppState g_app;
extern HINSTANCE g_hInst;

#endif
