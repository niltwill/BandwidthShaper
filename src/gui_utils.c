// Helper functions for the GUI

#include "gui_constants.h"
#include "gui_state.h"
#include "gui_utils.h"
#include "gui_proc_list.h"
#include "gui_main.h"
#include "gui_dialogs.h"
#include "resource.h"
#include "shaper_core.h"
#include "shaper_utils.h"
#include "external/UAHMenuBar.h"
#include <shellapi.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <windowsx.h>

// ---------------------------------------------------------------------------
// Acessors
// ---------------------------------------------------------------------------
HINSTANCE GetHInst(void) {
    return g_hInst;  // Need to make g_hInst accessible
}

UINT GetDPI(void) {
    return g_app.dpi;
}

HFONT GetUIFont(void) {
    return g_app.hUiFont;
}

bool IsDarkMode(void) {
    return g_app.dark_mode;
}

HBRUSH GetDarkBrush(int type) {
    switch(type) {
        case 0: return g_app.hDarkBrush;
        case 1: return g_app.hDarkListBrush;
        case 2: return g_app.hDarkBtnBrush;
        case 3: return g_app.hDarkToolbarBrush;
        default: return NULL;
    }
}

// ---------------------------------------------------------------------------
// Constant definitions
// ---------------------------------------------------------------------------
const UINT FREQ_INTERVALS[] = {
    1000,   // ID_FREQ_OFTEN
    2000,   // ID_FREQ_NORMAL
    15000,  // ID_FREQ_SLOWER
    45000,  // ID_FREQ_SCARCELY
    120000, // ID_FREQ_RARELY
    0,      // ID_FREQ_DISABLED  (0 = kill timer)
};

const double UNIT_MULTIPLIERS[UNIT_COUNT] = {1.0, 1000.0, 1000000.0, 1000000000.0};
const wchar_t* UNIT_LABELS[UNIT_COUNT] = {L"B/s", L"KB/s", L"MB/s", L"GB/s"};

// ---------------------------------------------------------------------------
// Admin privilege check and elevation helpers
// ---------------------------------------------------------------------------
bool IsUserAdmin(void) {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin != FALSE;
}

bool RelaunchAsAdmin(void) {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return false;

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";  // Triggers UAC
    sei.lpFile = exePath;
    sei.lpParameters = GetCommandLineW();  // Preserve command line
    sei.nShow = SW_NORMAL;
    sei.fMask = SEE_MASK_NO_CONSOLE | SEE_MASK_FLAG_NO_UI;  // SEE_MASK_FLAG_NO_UI prevents error dialogs

    return ShellExecuteExW(&sei);
}

// ---------------------------------------------------------------------------
// Initialize main window
// ---------------------------------------------------------------------------
void InitializeMainWindow(HWND hWnd) {
    LoadLibraryW(L"Msftedit.dll");    // provides RichEdit50W (Win8+, recommended to use)
    //LoadLibraryW(L"Riched20.dll");  // RichEdit20W for XP compatibility (fallback option)

    // Create toolbar placeholder (just a panel with buttons)
    g_app.hToolbar = CreateWindowExW(0, L"STATIC", NULL,
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, 0, 0, hWnd, (HMENU)IDC_TOOLBAR, g_hInst, NULL);
    SetWindowSubclass(g_app.hToolbar, ToolbarPanelSubclassProc, 0, 0);

    // Create buttons
    CreateWindowW(L"BUTTON", L"Start",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hWnd, (HMENU)IDC_START_BTN, g_hInst, NULL);

    CreateWindowW(L"BUTTON", L"Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        0, 0, 0, 0, hWnd, (HMENU)IDC_STOP_BTN, g_hInst, NULL);

    CreateWindowW(L"BUTTON", L"Reload",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        0, 0, 0, 0, hWnd, (HMENU)IDC_RELOAD_BTN, g_hInst, NULL);

    // Unit selector
    g_app.hUnitCombo = CreateWindowW(L"COMBOBOX", NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL | CBS_HASSTRINGS,
        0, 0, 0, S(100),  // Height 100 for dropdown list
        hWnd, (HMENU)IDC_UNIT_COMBO, g_hInst, NULL);

    for (int i = 0; i < UNIT_COUNT; i++) {
        SendMessageW(g_app.hUnitCombo, CB_ADDSTRING, 0, (LPARAM)UNIT_LABELS[i]);
    }
    SendMessage(g_app.hUnitCombo, CB_SETCURSEL, UNIT_KB, 0);

    // Create process list
    CreateProcessList(hWnd);

    // Create status bar
    CreateStatusBar(hWnd);

    // Put properly in the center
    CenterWindow(hWnd, GetParent(hWnd));

    // Apply dark mode if enabled
    if (g_app.dark_mode) {
        ApplyDarkModeToAllControls(hWnd, true);
    }
}

// Initialize status bar
void CreateStatusBar(HWND hWnd) {
    g_app.hStatusBar = CreateWindowExW(0, STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWnd, (HMENU)IDC_STATUS_BAR, g_hInst, NULL);

    int parts[] = {S(300), S(500), -1};
    SendMessage(g_app.hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Ready");

    // Colorize statusbar
    SetWindowSubclass(g_app.hStatusBar, StatusBarSubclassProc, 0, 0);
}

// ---------------------------------------------------------------------------
// Start, stop and reload functions
// ---------------------------------------------------------------------------
// Start the shaper with current settings
bool StartShaper(void) {
    if (g_app.shaper) return false;

    // Check if any NIC is selected
    if (g_app.options.selected_nics[0] == L'\0') {
        MSGBOX(g_app.hMainWnd,
            L"No network interface selected.\n\n"
            L"Please go to View > Options and select at least one network interface.",
            L"Configuration Required",
            MB_OK | MB_ICONWARNING);
        return false;
    }

    g_app.shaper = shaper_create();
    if (!g_app.shaper) {
        MSGBOX(g_app.hMainWnd, L"Failed to create shaper instance", L"Error", MB_OK);
        return false;
    }

    // Parse selected NICs from options
    unsigned int nicIndices[8] = {0};
    int nicCount = 0;

    if (wcslen(g_app.options.selected_nics) > 0) {
        wchar_t temp[256];
        wcscpy(temp, g_app.options.selected_nics);
        wchar_t* context = NULL;
        wchar_t* token = wcstok_s(temp, L",", &context);

        while (token != NULL && nicCount < 8) {
            nicIndices[nicCount++] = (unsigned int)_wtoi(token);
            token = wcstok_s(NULL, L",", &context);
        }
    }

    double dlLimits[8], ulLimits[8];
    for (int i = 0; i < nicCount; i++) {
        dlLimits[i] = g_app.options.global_dl_limit;
        ulLimits[i] = g_app.options.global_ul_limit;
    }

    ThrottlingParams throttling = {
        .nic_indices = nicIndices,
        .nic_count = nicCount,
        .download_limits = dlLimits,
        .upload_limits = ulLimits
    };

    ProcessParams process = {0};
    process.min_update_interval_ms = g_app.options.update_cooldown;
    if (g_app.options.update_by_packets) {
        process.packet_threshold = g_app.options.update_interval;
    } else {
        process.time_threshold_ms = g_app.options.update_interval;
    }

    bool ok = shaper_start(g_app.shaper,
                          &throttling,
                          &process,
                          g_app.options.global_dl_limit,
                          g_app.options.global_ul_limit,
                          g_app.options.dl_buffer,
                          g_app.options.ul_buffer,
                          g_app.options.tcp_limit,
                          g_app.options.udp_limit,
                          g_app.options.latency,
                          g_app.options.packet_loss,
                          g_app.options.priority,
                          g_app.options.burst_size,
                          g_app.options.data_cap,
                          15000,  // quota_check_interval_ms
                          NULL,   // global_schedule
                          false,  // quiet_mode
                          true);  // enable_statistics

    if (!ok) {
        char err[512];
        snprintf(err, 512, "Failed to start shaper: %s",
                shaper_get_last_error(g_app.shaper));
        wchar_t werr[512];
        MultiByteToWideChar(CP_UTF8, 0, err, -1, werr, 512);
        MSGBOX(g_app.hMainWnd, werr, L"Error", MB_OK);

        shaper_destroy(g_app.shaper);
        g_app.shaper = NULL;
        return false;
    }

    // Apply per-process rules
    UpdateProcessLimits();

    // Set timer for stats
    SetTimer(g_app.hMainWnd, TIMER_STATS_ID, TIMER_STATS_INTERVAL_MS, NULL);

    return true;
}

// Reload window procedure
bool ReloadShaperConfig(void) {
    if (!g_app.shaper || !shaper_is_running(g_app.shaper)) {
        return false;
    }

    // Rebuild throttling params from current settings
    unsigned int nicIndices[8] = {0};
    int nicCount = 0;
    double dlLimits[8], ulLimits[8];

    if (wcslen(g_app.options.selected_nics) > 0) {
        wchar_t temp[256];
        wcscpy(temp, g_app.options.selected_nics);
        wchar_t* context = NULL;
        wchar_t* token = wcstok_s(temp, L",", &context);

        while (token != NULL && nicCount < 8) {
            nicIndices[nicCount++] = (unsigned int)_wtoi(token);
            token = wcstok_s(NULL, L",", &context);
        }
    }

    for (int i = 0; i < nicCount; i++) {
        dlLimits[i] = g_app.options.global_dl_limit;
        ulLimits[i] = g_app.options.global_ul_limit;
    }

    ThrottlingParams throttling = {
        .nic_indices = nicIndices,
        .nic_count = nicCount,
        .download_limits = dlLimits,
        .upload_limits = ulLimits
    };

    ProcessParams process = {0};
    process.min_update_interval_ms = g_app.options.update_cooldown;
    if (g_app.options.update_by_packets) {
        process.packet_threshold = g_app.options.update_interval;
    } else {
        process.time_threshold_ms = g_app.options.update_interval;
    }

    bool ok = shaper_reload(g_app.shaper,
                           &throttling,
                           &process,
                           g_app.options.global_dl_limit,
                           g_app.options.global_ul_limit,
                           g_app.options.dl_buffer,
                           g_app.options.ul_buffer,
                           g_app.options.tcp_limit,
                           g_app.options.udp_limit,
                           g_app.options.latency,
                           g_app.options.packet_loss,
                           g_app.options.priority,
                           g_app.options.burst_size,
                           g_app.options.data_cap,
                           15000,  // quota_check_interval_ms
                           NULL,   // global_schedule
                           false,  // quiet_mode
                           true);  // enable_statistics

    if (ok) {
        UpdateProcessLimits();
    }

    return ok;
}

void StopShaper(void) {
    if (!g_app.shaper) return;

    // Close any open in-place editor first
    CellEdit_Cancel();

    // Take final atomic snapshot before stopping
    TrafficSnapshot final_snapshot = {0};
    bool have_final = shaper_snapshot_traffic(g_app.shaper, &final_snapshot);

    shaper_get_stats(g_app.shaper, &g_app.last_stats);
    g_app.has_last_stats = true;

    // Sum all PID traffic for accurate final DL/UL totals
    uint64_t total_dl_bytes = 0;
    uint64_t total_ul_bytes = 0;

    if (have_final) {
        for (int i = 0; i < final_snapshot.count; i++) {
            total_dl_bytes += final_snapshot.entries[i].dl_bytes;
            total_ul_bytes += final_snapshot.entries[i].ul_bytes;
        }
        shaper_free_traffic_snapshot(&final_snapshot);
    }

    // Check if any process quota was exhausted during the session
    wchar_t quota_msg[256] = L"";
    bool quota_exhausted = false;

    // Read quota status under lock
    EnterCriticalSection(&g_app.process_lock);

    for (int i = 0; i < g_app.process_count; i++) {
        ProcessEntry* proc = &g_app.processes[i];
        if ((proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in) ||
            (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out)) {

            if (!quota_exhausted) {
                wcsncpy(quota_msg, L"\r\n*** QUOTA EXHAUSTED PROCESSES ***\r\n", 255);
                quota_exhausted = true;
            }

            wchar_t line[128];
            swprintf(line, 128, L"  %s", proc->name);
            if (proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in)
                wcscat(line, L" (IN)");
            if (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out)
                wcscat(line, L" (OUT)");
            wcscat(line, L"\r\n");

            // Ensure we don't overflow quota_msg
            if (wcslen(quota_msg) + wcslen(line) < 255) {
                wcsncat(quota_msg, line, 255 - wcslen(quota_msg) - 1);
            }
        }
    }

    LeaveCriticalSection(&g_app.process_lock);

    // Build a frozen text copy for the stats dialog - matching new format
    swprintf(g_app.last_stats_text, 768,
        L"--- Session ended (stats frozen) ---\r\n"
        L"Packets processed:  %llu\r\n"
        L"Dropped (rate):     %llu\r\n"
        L"Dropped (loss):     %llu\r\n"
        L"Delayed:            %llu\r\n"
        L"Invalid:            %llu\r\n"
        L"\r\n"
        L"Total Bytes:        %llu (%.2f MB)\r\n"
        L"Download Bytes:     %llu (%.2f MB)\r\n"
        L"Upload Bytes:       %llu (%.2f MB)\r\n"
        L"%s%s%s",
        g_app.last_stats.packets_processed,
        g_app.last_stats.packets_dropped_rate_limit,
        g_app.last_stats.packets_dropped_loss,
        g_app.last_stats.packets_delayed,
        g_app.last_stats.invalid_packets,
        g_app.last_stats.bytes_processed,
        g_app.last_stats.bytes_processed / (1024.0 * 1024.0),
        total_dl_bytes,
        total_dl_bytes / (1024.0 * 1024.0),
        total_ul_bytes,
        total_ul_bytes / (1024.0 * 1024.0),
        g_app.last_stats.cap_reached ? L"\r\n*** DATA CAP REACHED ***" : L"",
        (g_app.last_stats.cap_reached && quota_exhausted) ? L"\r\n" : L"",
        quota_exhausted ? quota_msg : L"");

    // Stop timer for stats
    KillTimer(g_app.hMainWnd, TIMER_STATS_ID);

    shaper_stop(g_app.shaper);
    shaper_destroy(g_app.shaper);
    g_app.shaper = NULL;
}

// ---------------------------------------------------------------------------
// DPI scaling functions
// ---------------------------------------------------------------------------
int S(int px) {
    return MulDiv(px, g_app.dpi, 96);  // Scale a base-96-DPI pixel value to the current monitor DPI
}

void RecreateUiFont(void) {
    if (g_app.hUiFont) { DeleteObject(g_app.hUiFont); g_app.hUiFont = NULL; }
    g_app.hUiFont = CreateFontW(
        -S(13),  // height (negative = character height, not cell height)
        0, 0, 0,
        FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        L"Segoe UI");
}

static BOOL CALLBACK SetFontProc(HWND hWnd, LPARAM lParam) {
    SendMessage(hWnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

// Push the current font to every child control
void ApplyFontToChildren(HWND hParent) {
    EnumChildWindows(hParent, SetFontProc, (LPARAM)g_app.hUiFont);
}

// Helper function to center window
void CenterWindow(HWND hWnd, HWND hParent) {
    RECT rc;
    GetWindowRect(hWnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    // Determine which monitor to use
    POINT pt;
    if (hParent && IsWindow(hParent)) {
        // Use parent's center point
        RECT rcParent;
        GetWindowRect(hParent, &rcParent);
        pt.x = rcParent.left + (rcParent.right - rcParent.left) / 2;
        pt.y = rcParent.top + (rcParent.bottom - rcParent.top) / 2;
    } else {
        // Use cursor position
        GetCursorPos(&pt);
    }

    HMONITOR hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfo(hMon, &mi);

    int x = mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - w) / 2;
    int y = mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - h) / 2;

    SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// Clamp window to work area (DPI-related), to not overflow window
void ClampWindowToWorkArea(HWND hWnd) {
	RECT rcDlg;
	GetWindowRect(hWnd, &rcDlg);

	HMONITOR hMon = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
	MONITORINFO mi = { sizeof(mi) };
	GetMonitorInfo(hMon, &mi);
	RECT wa = mi.rcWork;  // work area excludes taskbar

	int dlgW = rcDlg.right - rcDlg.left;
	int dlgH = rcDlg.bottom - rcDlg.top;
	int waW = wa.right - wa.left;
	int waH = wa.bottom - wa.top;

	// Shrink if taller or wider than the work area
	int newW = (dlgW > waW) ? waW : dlgW;
	int newH = (dlgH > waH) ? waH : dlgH;

	// Re-centre within work area at the clamped size
	int newX = wa.left + (waW - newW) / 2;
	int newY = wa.top  + (waH - newH) / 2;

	SetWindowPos(hWnd, NULL, newX, newY, newW, newH,
				 SWP_NOZORDER | SWP_NOACTIVATE);
}

// ---------------------------------------------------------------------------
// Dark mode
// ---------------------------------------------------------------------------
// Dark mode uxtheme ordinal typedefs
typedef enum {
    AppMode_Default = 0,
    AppMode_AllowDark = 1,
    AppMode_ForceDark = 2,
    AppMode_ForceLight = 3,
    AppMode_Max = 4
} PreferredAppMode;

typedef bool (WINAPI *fnAllowDarkModeForWindow)(HWND hWnd, bool allow);
typedef bool (WINAPI *fnAllowDarkModeForApp)(bool allow);
typedef PreferredAppMode (WINAPI *fnSetPreferredAppMode)(PreferredAppMode appMode);
typedef void (WINAPI *fnRefreshImmersiveColorPolicyState)(void);

// Static storage - kept alive for the lifetime of the process
fnAllowDarkModeForWindow _AllowDarkModeForWindow = NULL;
fnRefreshImmersiveColorPolicyState _RefreshImmersiveColorPolicyState = NULL;

void InitializeDarkMode(void) {
    g_app.dark_bg = DARK_BG_COLOR;
    g_app.dark_list_bg = DARK_LIST_COLOR;
    g_app.dark_text = DARK_TEXT_COLOR;
    g_app.hDarkBrush = CreateSolidBrush(g_app.dark_bg);
    g_app.hDarkListBrush = CreateSolidBrush(g_app.dark_list_bg);
    g_app.hDarkBtnBrush = CreateSolidBrush(DARK_BTN_FACE);
    g_app.hDarkToolbarBrush = CreateSolidBrush(DARK_TOOLBAR_COLOR);
}

void CleanupDarkMode(void) {
    if (g_app.hDarkBrush) { DeleteObject(g_app.hDarkBrush); g_app.hDarkBrush = NULL; }
    if (g_app.hDarkListBrush) { DeleteObject(g_app.hDarkListBrush); g_app.hDarkListBrush = NULL; }
    if (g_app.hDarkBtnBrush) { DeleteObject(g_app.hDarkBtnBrush); g_app.hDarkBtnBrush = NULL; }
    if (g_app.hDarkToolbarBrush) { DeleteObject(g_app.hDarkToolbarBrush); g_app.hDarkToolbarBrush = NULL; }
}

// Reads AppsUseLightTheme from HKCU; returns TRUE if system is in dark mode.
bool DarkMode_SystemIsDark(void) {
    DWORD val = 1; // default: light
    DWORD cb  = sizeof(val);
    RegGetValueW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        L"AppsUseLightTheme",
        RRF_RT_REG_DWORD, NULL, &val, &cb);
    return (val == 0);
}

void DarkMode_InitUxtheme(void) {
    HMODULE hUx;
    FARPROC ord135;
    DWORD build = 0;
    DWORD cb = sizeof(build);

    hUx = LoadLibraryExW(L"uxtheme.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hUx) return;

    // Ordinal 133: AllowDarkModeForWindow - per-HWND opt-in
    _AllowDarkModeForWindow = (fnAllowDarkModeForWindow)
        GetProcAddress(hUx, MAKEINTRESOURCEA(133));

    // Ordinal 104: RefreshImmersiveColorPolicyState
    _RefreshImmersiveColorPolicyState = (fnRefreshImmersiveColorPolicyState)
        GetProcAddress(hUx, MAKEINTRESOURCEA(104));

    // Ordinal 135: SetPreferredAppMode (1903+) or AllowDarkModeForApp (1809)
    ord135 = GetProcAddress(hUx, MAKEINTRESOURCEA(135));
    if (ord135) {
        // Read CurrentBuildNumber from the registry
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"CurrentBuildNumber",
            RRF_RT_REG_SZ, NULL, NULL, &cb);
        {
            // cb now holds the byte size of the string
            wchar_t buildStr[16] = {0};
            cb = sizeof(buildStr);
            if (RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    L"CurrentBuildNumber",
                    RRF_RT_REG_SZ, NULL, buildStr, &cb) == ERROR_SUCCESS) {
                build = (DWORD)_wtoi(buildStr);
            }
        }

        if (build > 0 && build < 18362) {
            // Windows 1809 / RS5: ordinal 135 is AllowDarkModeForApp(bool)
            ((fnAllowDarkModeForApp)ord135)(TRUE);
        } else {
            // Windows 1903+ (build 18362+): SetPreferredAppMode(PreferredAppMode)
            ((fnSetPreferredAppMode)ord135)(AppMode_AllowDark);
        }
    }

    if (_RefreshImmersiveColorPolicyState)
        _RefreshImmersiveColorPolicyState();

    // Do not FreeLibrary here - keep hUx loaded so the function pointers remain valid
}

void ApplyDarkModeToAllControls(HWND hParent, bool enable) {
    if (enable) {
        SetClassLongPtr(hParent, GCLP_HBRBACKGROUND, (LONG_PTR)g_app.hDarkBrush);
    } else {
        SetClassLongPtr(hParent, GCLP_HBRBACKGROUND, (LONG_PTR)(COLOR_WINDOW + 1));
    }

    // Apply to all child windows
    EnumChildWindows(hParent, EnumChildProc, (LPARAM)enable);

    // Special handling for ListView headers
    if (enable && g_app.hProcessList) {
        ApplyDarkModeToListViewHeader(g_app.hProcessList);
    }

    // Force redraw
    InvalidateRect(hParent, NULL, TRUE);
    RedrawWindow(hParent, NULL, NULL,
                RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
}

void ApplyDarkModeToListViewHeader(HWND hListView) {
    if (!g_app.dark_mode) return;

    HWND hHeader = ListView_GetHeader(hListView);
    if (!hHeader) return;

    // Disable default theme to prevent interference
    SetWindowTheme(hHeader, L"", L"");

    // Subclass for custom drawing
    SetWindowSubclass(hHeader, HeaderSubclassProc, 0, 0);

    // Force immediate redraw
    InvalidateRect(hHeader, NULL, TRUE);
}

void ApplyDarkModeToDialog(HWND hDlg) {
    if (!g_app.dark_mode) return;
    // Apply dark theming to all child controls
    EnumChildWindows(hDlg, EnumChildProc, (LPARAM)TRUE);
    InvalidateRect(hDlg, NULL, TRUE);
}

// When changing themes
void DarkMode_ApplyToDialog(HWND hDlg) {
    g_app.dark_mode = DarkMode_SystemIsDark();
    EnumChildWindows(hDlg, EnumChildProc, (LPARAM)g_app.dark_mode);
    InvalidateRect(hDlg, NULL, TRUE);
    RedrawWindow(hDlg, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);

    // Main window
    if (g_app.hMainWnd && IsWindow(g_app.hMainWnd)) {
        ApplyDarkModeToAllControls(g_app.hMainWnd, g_app.dark_mode);
        //ApplyDarkModeToListViewHeader(g_app.hProcessList);
        InvalidateRect(g_app.hMainWnd, NULL, TRUE);
        RedrawWindow(g_app.hMainWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }

    // Statistics window
    if (g_app.hStatsWnd && IsWindow(g_app.hStatsWnd)) {
        ApplyDarkModeToAllControls(g_app.hStatsWnd, g_app.dark_mode);
        //ApplyDarkModeToListViewHeader(GetDlgItem(hDlg, IDC_STATS_TEXT));
        UpdateStatistics_RichBox();
        InvalidateRect(g_app.hStatsWnd, NULL, TRUE);
        RedrawWindow(g_app.hStatsWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }
}

// Update the richbox in the statistics
void UpdateStatistics_RichBox(void) {
    if (!g_app.hStatsWnd) return;

    HWND hRichEdit = GetDlgItem(g_app.hStatsWnd, IDC_STATS_TEXT);
    if (hRichEdit) {
        if (g_app.dark_mode) {
            SetWindowTheme(hRichEdit, L"DarkMode_Explorer", NULL);
            SendMessage(hRichEdit, EM_SETBKGNDCOLOR, 0, (LPARAM)g_app.dark_list_bg);

            CHARFORMAT2W cf = { sizeof(cf) };
            cf.dwMask = CFM_COLOR | CFM_BACKCOLOR;
            cf.crTextColor = g_app.dark_text;
            cf.crBackColor = g_app.dark_list_bg;
            cf.dwEffects = 0;
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        } else {
            SetWindowTheme(hRichEdit, L"Explorer", NULL);
            SendMessage(hRichEdit, EM_SETBKGNDCOLOR, 0, (LPARAM)GetSysColor(COLOR_WINDOW));

            CHARFORMAT2W cf = { sizeof(cf) };
            cf.dwMask = CFM_COLOR | CFM_BACKCOLOR;
            cf.crTextColor = GetSysColor(COLOR_WINDOWTEXT);
            cf.crBackColor = GetSysColor(COLOR_WINDOW);
            cf.dwEffects = 0;
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        }
        InvalidateRect(hRichEdit, NULL, TRUE);
    }
}

// Dark mode
BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam) {
    bool enable = (bool)lParam;

    wchar_t cls[128];
    GetClassNameW(hWnd, cls, 128);

    if (enable) {
        if (_wcsicmp(cls, L"SysListView32") == 0) {
            // Theme the listview and its header child separately
            SetWindowTheme(hWnd, L"DarkMode_Explorer", NULL);
            ListView_SetTextColor(hWnd, g_app.dark_text);
            ListView_SetTextBkColor(hWnd, g_app.dark_list_bg);
            ListView_SetBkColor(hWnd, g_app.dark_list_bg);
            // Theme the SysHeader32 that is a child of the ListView
            HWND hHdr = ListView_GetHeader(hWnd);
            if (hHdr) SetWindowTheme(hHdr, L"DarkMode_ItemsView", NULL);

            // Remove gridlines in dark mode (they don't contrast well)
            DWORD exStyle = ListView_GetExtendedListViewStyle(hWnd);
            exStyle &= ~LVS_EX_GRIDLINES;  // Remove gridlines
            ListView_SetExtendedListViewStyle(hWnd, exStyle);

            RedrawWindow(hWnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
        }
        else if (_wcsicmp(cls, L"SysHeader32") == 0) {
            // Direct header controls (not under a listview)
            SetWindowTheme(hWnd, L"DarkMode_ItemsView", NULL);
        }
        else if (_wcsicmp(cls, L"Edit") == 0) {
            SetWindowTheme(hWnd, L"DarkMode_CFD", NULL);
        }
        else if (_wcsicmp(cls, L"Button") == 0) {
            DWORD style = GetWindowLong(hWnd, GWL_STYLE);
            DWORD btnType = style & BS_TYPEMASK;
            if (btnType == BS_PUSHBUTTON || btnType == BS_DEFPUSHBUTTON) {
                // Switch to owner-draw so WM_DRAWITEM can paint the dark face.
                // Strip existing type bits and replace with BS_OWNERDRAW.
                SetWindowLong(hWnd, GWL_STYLE,
                    (style & ~BS_TYPEMASK) | BS_OWNERDRAW);
                SetWindowTheme(hWnd, L"", L""); // remove visual-style chrome
            } else {
                // Checkboxes, radio buttons, group boxes
                SetWindowTheme(hWnd, L"DarkMode_Explorer", NULL);
            }
        }
        else if (_wcsicmp(cls, L"ComboBox") == 0) {
            SetWindowTheme(hWnd, L"DarkMode_CFD", NULL);
        }
        else if (_wcsicmp(cls, L"msctls_statusbar32") == 0) {
            // Status bars ignore WM_CTLCOLOR; NM_CUSTOMDRAW is handled in WM_NOTIFY
            SetWindowTheme(hWnd, L"", L"");
        }
        else {
            SetWindowTheme(hWnd, L"DarkMode_Explorer", NULL);
        }
    } else {
        // Restore light mode
        if (_wcsicmp(cls, L"SysListView32") == 0) {
            SetWindowTheme(hWnd, L"Explorer", NULL);
            ListView_SetTextColor(hWnd, GetSysColor(COLOR_WINDOWTEXT));
            ListView_SetTextBkColor(hWnd, GetSysColor(COLOR_WINDOW));
            ListView_SetBkColor(hWnd, GetSysColor(COLOR_WINDOW));
            HWND hHdr = ListView_GetHeader(hWnd);
            if (hHdr) SetWindowTheme(hHdr, L"", NULL);

            // Re-enable gridlines in light mode
            DWORD exStyle = ListView_GetExtendedListViewStyle(hWnd);
            exStyle |= LVS_EX_GRIDLINES;  // Add gridlines back
            ListView_SetExtendedListViewStyle(hWnd, exStyle);
        }
        else if (_wcsicmp(cls, L"Button") == 0) {
            DWORD style = GetWindowLong(hWnd, GWL_STYLE);
            DWORD btnType = style & BS_TYPEMASK;
            if (btnType == BS_OWNERDRAW) {
                // Restore: default buttons become DEFPUSHBUTTON if id == IDOK/IDYES,
                // otherwise plain PUSHBUTTON.
                int ctlId = GetDlgCtrlID(hWnd);
                DWORD restore = (ctlId == IDOK || ctlId == IDYES)
                                ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON;
                SetWindowLong(hWnd, GWL_STYLE, (style & ~BS_TYPEMASK) | restore);
            }
            SetWindowTheme(hWnd, L"Explorer", NULL);
        }
        else if (_wcsicmp(cls, L"msctls_statusbar32") == 0) {
            SetWindowTheme(hWnd, L"Explorer", NULL);
        }
        else {
            SetWindowTheme(hWnd, L"Explorer", NULL);
        }
    }

    EnumChildWindows(hWnd, EnumChildProc, lParam);
    SetWindowPos(hWnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    InvalidateRect(hWnd, NULL, TRUE);
    return TRUE;
}

// Helper function to determine control type and return appropriate brush
LRESULT DarkMode_HandleCtlColor(HDC hdc, HWND hwndCtl, UINT msg) {
    if (!g_app.dark_mode) return FALSE;

    wchar_t cls[128];
    GetClassNameW(hwndCtl, cls, 128);

    // Set default text color
    SetTextColor(hdc, g_app.dark_text);

    // Edit controls and listboxes - light background
    if (_wcsicmp(cls, L"Edit") == 0 || 
        _wcsicmp(cls, L"ListBox") == 0 ||
        _wcsicmp(cls, L"ComboBox") == 0) {
        SetBkColor(hdc, g_app.dark_list_bg);
        SetBkMode(hdc, OPAQUE);
        return (LRESULT)g_app.hDarkListBrush;
    }

    // Static text controls
    if (_wcsicmp(cls, L"Static") == 0) {
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetStockObject(NULL_BRUSH);
    }

    // Button controls
    if (_wcsicmp(cls, L"Button") == 0) {
        DWORD style = GetWindowLong(hwndCtl, GWL_STYLE);
        DWORD btnType = style & BS_TYPEMASK;

        // Push buttons (including owner-draw) - use button face color
        if (btnType == BS_PUSHBUTTON || btnType == BS_DEFPUSHBUTTON || 
            btnType == BS_OWNERDRAW) {
            SetBkColor(hdc, DARK_BTN_FACE);
            SetBkMode(hdc, OPAQUE);
            return (LRESULT)g_app.hDarkBtnBrush;
        }

        // Group boxes - transparent with border
        if (btnType == BS_GROUPBOX) {
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }

        // Checkboxes, radio buttons - transparent
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetStockObject(NULL_BRUSH);
    }

    // Toolbar special case
    if (hwndCtl == g_app.hToolbar) {
        SetBkColor(hdc, DARK_TOOLBAR_COLOR);
        SetBkMode(hdc, OPAQUE);
        return (LRESULT)g_app.hDarkToolbarBrush;
    }

    // Default for other controls
    SetBkColor(hdc, g_app.dark_bg);
    SetBkMode(hdc, OPAQUE);
    return (LRESULT)g_app.hDarkBrush;
}

void DrawDarkButton(LPDRAWITEMSTRUCT dis) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    BOOL disabled = (dis->itemState & ODS_DISABLED) != 0;
    BOOL pressed = (dis->itemState & ODS_SELECTED) != 0;
    BOOL focused = (dis->itemState & ODS_FOCUS) != 0;
    BOOL hottrack = (dis->itemState & ODS_HOTLIGHT) != 0;

    // Choose face colour
    COLORREF face = disabled ? DARK_BG_COLOR
                  : pressed  ? DARK_BTN_PRESSED
                  : hottrack ? DARK_BTN_HOT
                             : DARK_BTN_FACE;

    // Fill background
    HBRUSH hFace = CreateSolidBrush(face);
    FillRect(hdc, &rc, hFace);
    DeleteObject(hFace);

    // Draw border (accent colour when focused)
    COLORREF borderColor = focused ? RGB(100, 150, 230) : DARK_BTN_BORDER;
    HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
    HPEN hOld = (HPEN)SelectObject(hdc, hPen);
    HBRUSH hNB = (HBRUSH)GetStockObject(NULL_BRUSH);
    HBRUSH hOB = (HBRUSH)SelectObject(hdc, hNB);
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, hOld);
    SelectObject(hdc, hOB);
    DeleteObject(hPen);

    // Focus dotted rectangle inside border
    if (focused && !pressed) {
        RECT frc = { rc.left + 3, rc.top + 3, rc.right - 3, rc.bottom - 3 };
        DrawFocusRect(hdc, &frc);
    }

    // Retrieve button label
    wchar_t text[128] = {0};
    GetWindowTextW(dis->hwndItem, text, 128);

    // Set up text drawing
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, disabled ? DARK_DISABLED_TEXT : DARK_TEXT_COLOR);

    HFONT hFont = (HFONT)SendMessage(dis->hwndItem, WM_GETFONT, 0, 0);
    HFONT hOldFont = hFont ? (HFONT)SelectObject(hdc, hFont) : NULL;

    // Shift content 1 px down/right when pressed for tactile feel
    RECT textRc = rc;
    if (pressed) OffsetRect(&textRc, 1, 1);

    DrawTextW(hdc, text, -1, &textRc,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);

    if (hOldFont) SelectObject(hdc, hOldFont);
}

// ---------------------------------------------------------------------------
// Dark mode - subclasses (custom dark theme overrides)
// ---------------------------------------------------------------------------
LRESULT CALLBACK ToolbarPanelSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    if (msg == WM_DRAWITEM) {
        // Forward to Main Window where the DrawDarkButton logic resides
        return SendMessage(g_app.hMainWnd, WM_DRAWITEM, wParam, lParam);
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

LRESULT CALLBACK StatusBarSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (msg) {
    case WM_PAINT: {
        if (!g_app.dark_mode)
            return DefSubclassProc(hWnd, msg, wParam, lParam);

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        // Fill background
        FillRect(hdc, &rcClient, g_app.hDarkBrush);

        // Draw TOP border line (separator from ListView above)
        HPEN hBorderPen = CreatePen(PS_SOLID, 1, DARK_BTN_BORDER);
        HPEN hOldPen = (HPEN)SelectObject(hdc, hBorderPen);

        MoveToEx(hdc, rcClient.left, rcClient.top, NULL);
        LineTo(hdc, rcClient.right, rcClient.top);

        // Draw bottom border line
        MoveToEx(hdc, rcClient.left, rcClient.bottom - 1, NULL);
        LineTo(hdc, rcClient.right, rcClient.bottom - 1);

        SelectObject(hdc, hOldPen);
        DeleteObject(hBorderPen);

        // Get number of parts
        int numParts = (int)SendMessage(hWnd, SB_GETPARTS, 0, 0);
        if (numParts <= 0) numParts = 1;

        int* parts = (int*)malloc(numParts * sizeof(int));
        if (!parts) {
            EndPaint(hWnd, &ps);
            return 0;
        }

        SendMessage(hWnd, SB_GETPARTS, numParts, (LPARAM)parts);

        int left = 0;
        for (int i = 0; i < numParts; i++) {
            RECT partRect;
            partRect.left = left;

            // Handle -1 (last part extends to window edge)
            if (parts[i] == -1) {
                partRect.right = rcClient.right;
            } else {
                partRect.right = parts[i];
            }

            partRect.top = rcClient.top;
            partRect.bottom = rcClient.bottom;

            // Get text for this part
            wchar_t text[256] = {0};
            DWORD len = (DWORD)SendMessage(hWnd, SB_GETTEXT, i, (LPARAM)text);

            // Draw vertical separator between parts
            // Don't draw at left edge of first part, and stay within top/bottom borders
            if (i > 0) {
                HPEN hSepPen = CreatePen(PS_SOLID, 1, DARK_BTN_BORDER);
                HPEN hOldSepPen = (HPEN)SelectObject(hdc, hSepPen);
                // Start below top border, end above bottom border
                MoveToEx(hdc, partRect.left, partRect.top + 1, NULL);
                LineTo(hdc, partRect.left, partRect.bottom - 1);
                SelectObject(hdc, hOldSepPen);
                DeleteObject(hSepPen);
            }

            // Draw text with padding
            if (len > 0 && text[0]) {
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, g_app.dark_text);

                HFONT hFont = (HFONT)SendMessage(hWnd, WM_GETFONT, 0, 0);
                HFONT hOldFont = NULL;
                if (hFont) {
                    hOldFont = (HFONT)SelectObject(hdc, hFont);
                }

                RECT textRect = partRect;
                textRect.left += 4;
                textRect.right -= 4;
                // Adjust for top/bottom borders
                textRect.top += 1;
                textRect.bottom -= 1;

                DrawTextW(hdc, text, -1, &textRect,
                         DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

                if (hOldFont) {
                    SelectObject(hdc, hOldFont);
                }
            }

            left = partRect.right;
        }

        free(parts);
        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        if (g_app.dark_mode) {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hWnd, &rc);
            FillRect(hdc, &rc, g_app.hDarkBrush);
            return 1;
        }
        break;

    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, StatusBarSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

// Custom draw for ListView header
LRESULT CALLBACK HeaderSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (msg) {
    case WM_ERASEBKGND: {
        if (!g_app.dark_mode)
            return DefSubclassProc(hWnd, msg, wParam, lParam);

        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, g_app.hDarkBrush);
        return 1; // Handled
    }

    case WM_PAINT: {
        if (!g_app.dark_mode)
            return DefSubclassProc(hWnd, msg, wParam, lParam);

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        // Fill background
        FillRect(hdc, &rcClient, g_app.hDarkBrush);

        // Get header item count
        int count = Header_GetItemCount(hWnd);

        // Draw each header item
        for (int i = 0; i < count; i++) {
            RECT rcItem;
            if (!Header_GetItemRect(hWnd, i, &rcItem))
                continue;

            // Check if this item is pressed/hot (for visual feedback)
            // HDITEM state can be retrieved but requires HDI_STATE mask

            // Draw item background (slightly different from main bg)
            FillRect(hdc, &rcItem, g_app.hDarkBtnBrush);

            // Draw right border (separator)
            HPEN hPen = CreatePen(PS_SOLID, 1, DARK_BTN_BORDER);
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            MoveToEx(hdc, rcItem.right - 1, rcItem.top + 2, NULL);
            LineTo(hdc, rcItem.right - 1, rcItem.bottom - 2);
            SelectObject(hdc, hOldPen);
            DeleteObject(hPen);

            // Get item text
            wchar_t text[256] = {0};
            HDITEM hdi = {0};
            hdi.mask = HDI_TEXT;
            hdi.pszText = text;
            hdi.cchTextMax = 256;

            if (Header_GetItem(hWnd, i, &hdi) && text[0]) {
                // Draw text
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, g_app.dark_text);

                RECT textRect = rcItem;
                textRect.left += 6;   // More padding
                textRect.right -= 6;

                // Check for sort arrow (simple check for Unicode arrows)
                if (wcsstr(text, UP_ARROW) || wcsstr(text, DOWN_ARROW)) {
                    // Draw arrow in accent color
                    wchar_t* arrowPos = wcsstr(text, UP_ARROW);
                    if (!arrowPos) arrowPos = wcsstr(text, DOWN_ARROW);

                    if (arrowPos) {
                        // Split text and arrow
                        wchar_t textOnly[256];
                        wcsncpy(textOnly, text, arrowPos - text);
                        textOnly[arrowPos - text] = L'\0';

                        // Draw main text
                        DrawTextW(hdc, textOnly, -1, &textRect,
                                DT_LEFT | DT_VCENTER | DT_SINGLELINE);

                        // Draw arrow in accent color on the right
                        SetTextColor(hdc, RGB(100, 150, 230)); // Accent blue
                        RECT arrowRect = rcItem;
                        arrowRect.left = rcItem.right - 20;
                        DrawTextW(hdc, arrowPos, -1, &arrowRect,
                                DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                    } else {
                        DrawTextW(hdc, text, -1, &textRect,
                                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                    }
                } else {
                    DrawTextW(hdc, text, -1, &textRect,
                            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                }
            }
        }

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, HeaderSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Tray icon functions
// ---------------------------------------------------------------------------
void TrayAdd(HWND hWnd) {
    g_app.nid.cbSize = sizeof(NOTIFYICONDATA);
    g_app.nid.hWnd = hWnd;
    g_app.nid.uID = IDI_TRAY_ICON;
    g_app.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_app.nid.uCallbackMessage = WM_TRAY_ICON;
    g_app.nid.hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(1));
    // Fallback to a stock icon if no app icon is embedded
    if (!g_app.nid.hIcon)
        g_app.nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcsncpy(g_app.nid.szTip, L"BandwidthShaper", ARRAYSIZE(g_app.nid.szTip));

    Shell_NotifyIcon(NIM_ADD, &g_app.nid);
    g_app.tray_added = true;
}

void TrayRemove(void) {
    if (g_app.tray_added) {
        Shell_NotifyIcon(NIM_DELETE, &g_app.nid);
        g_app.tray_added = false;
    }
}

void TrayShowMenu(HWND hWnd) {
    HMENU hMenu = CreatePopupMenu();
    bool running = (g_app.shaper != NULL);

    bool visible = IsWindowVisible(hWnd);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, visible ? L"Hide" : L"Show");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING | (running ? MF_GRAYED : 0), ID_TRAY_START, L"Start");
    AppendMenuW(hMenu, MF_STRING | (!running ? MF_GRAYED : 0), ID_TRAY_STOP, L"Stop");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_STATS, L"Statistics");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");

    SetForegroundWindow(hWnd);

    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
}

void MinimizeToTray(void) {
    ShowWindow(g_app.hMainWnd, SW_HIDE);
}

void RestoreFromTray(void) {
    ShowWindow(g_app.hMainWnd, SW_RESTORE);
    SetForegroundWindow(g_app.hMainWnd);
}

// ---------------------------------------------------------------------------
// Persistent settings helpers
// ---------------------------------------------------------------------------
// Build absolute path to "BandwidthShaper.cfg" next to the executable
// Returns false if GetModuleFileNameW fails
bool Settings_GetPath(wchar_t *path, DWORD cchPath) {
    if (!GetModuleFileNameW(NULL, path, cchPath)) return false;

    // Replace the filename portion with our config filename
    wchar_t *last_sep = wcsrchr(path, L'\\');
    if (!last_sep) last_sep = wcsrchr(path, L'/');
    if (last_sep) {
        *(last_sep + 1) = L'\0';
    } else {
        path[0] = L'\0';   // fallback: current directory
    }
    wcsncat(path, L"BandwidthShaper.cfg", cchPath - wcslen(path) - 1);
    return true;
}

// Settings_Save
// Writes every persisted field to the INI file
// (Does nothing if g_app.options.save_settings is false)
void Settings_Save(void) {
    if (!g_app.options.save_settings) return;

    wchar_t path[MAX_PATH];
    if (!Settings_GetPath(path, MAX_PATH)) return;

    const wchar_t *S = L"Settings";   // INI section name shorthand
    wchar_t buf[512];

    // Global limits (stored as bytes/sec, written as KB/s integers)
    swprintf(buf, 512, L"%u", (unsigned)(g_app.options.global_dl_limit / 1000.0 + 0.5));
    WritePrivateProfileStringW(S, L"GlobalDLLimit_KBs", buf, path);

    swprintf(buf, 512, L"%u", (unsigned)(g_app.options.global_ul_limit / 1000.0 + 0.5));
    WritePrivateProfileStringW(S, L"GlobalULLimit_KBs", buf, path);

    // NIC selection - stored as semicolon-separated Description strings
    {
        ULONG bufLen = 0;
        GetAdaptersInfo(NULL, &bufLen);
        IP_ADAPTER_INFO *pAdapters = (bufLen > 0) ? malloc(bufLen) : NULL;
        wchar_t desc_list[1024] = {0};

        if (pAdapters && GetAdaptersInfo(pAdapters, &bufLen) == NO_ERROR
                && wcslen(g_app.options.selected_nics) > 0) {

            wchar_t temp[256];
            wcscpy(temp, g_app.options.selected_nics);
            wchar_t *ctx = NULL;
            wchar_t *tok = wcstok_s(temp, L",", &ctx);

            while (tok) {
                DWORD target_idx = (DWORD)_wtoi(tok);
                IP_ADAPTER_INFO *p = pAdapters;
                while (p) {
                    if (p->Index == target_idx) {
                        wchar_t desc[128];
                        MultiByteToWideChar(CP_ACP, 0, p->Description, -1, desc, 128);
                        // Append to semicolon-separated list; escape any ';' in desc
                        // (in practice adapter descriptions never contain ';')
                        if (desc_list[0]) wcsncat(desc_list, L";", 1023 - wcslen(desc_list));
                        wcsncat(desc_list, desc, 1023 - wcslen(desc_list));
                        break;
                    }
                    p = p->Next;
                }
                tok = wcstok_s(NULL, L",", &ctx);
            }
        }
        free(pAdapters);

        WritePrivateProfileStringW(S, L"SelectedNICs", desc_list, path);
    }

    // Buffer / burst
    swprintf(buf, 512, L"%u", g_app.options.dl_buffer);
    WritePrivateProfileStringW(S, L"DLBuffer", buf, path);

    swprintf(buf, 512, L"%u", g_app.options.ul_buffer);
    WritePrivateProfileStringW(S, L"ULBuffer", buf, path);

    swprintf(buf, 512, L"%d", g_app.options.burst_size);
    WritePrivateProfileStringW(S, L"BurstSize", buf, path);

    // Process update interval
    swprintf(buf, 512, L"%u", g_app.options.update_interval);
    WritePrivateProfileStringW(S, L"UpdateInterval", buf, path);

    WritePrivateProfileStringW(S, L"UpdateByPackets",
                               g_app.options.update_by_packets ? L"1" : L"0", path);

    swprintf(buf, 512, L"%u", g_app.options.update_cooldown);
    WritePrivateProfileStringW(S, L"UpdateCooldown", buf, path);

    // UI preferences
    WritePrivateProfileStringW(S, L"MinimizeToTray",
                               g_app.minimize_to_tray ? L"1" : L"0", path);

    swprintf(buf, 512, L"%d", (int)g_app.current_unit);
    WritePrivateProfileStringW(S, L"DisplayUnit", buf, path);

    WritePrivateProfileStringW(S, L"SaveStickyProcesses",
                               g_app.options.save_sticky_settings ? L"1" : L"0", path);

    // Save-settings flag itself
    // Always write this last so the file is coherent even if we crash midway
    WritePrivateProfileStringW(S, L"SaveSettings", L"1", path);
}

// Settings_Load
// Reads persisted fields into g_app.
void Settings_Load(void) {
    wchar_t path[MAX_PATH];
    if (!Settings_GetPath(path, MAX_PATH)) return;

    const wchar_t *S = L"Settings";
    wchar_t buf[1024];

    // Has to happen before SaveSettings
    GetPrivateProfileStringW(S, L"SaveStickyProcesses", L"0", buf, 2, path);
    g_app.options.save_sticky_settings = (buf[0] == L'1');

    // Check whether the user previously turned saving on
    GetPrivateProfileStringW(S, L"SaveSettings", L"0", buf, 2, path);
    if (buf[0] != L'1') return;   // file absent or saving was off - use defaults
    g_app.options.save_settings = true;

    // Global limits
    GetPrivateProfileStringW(S, L"GlobalDLLimit_KBs", L"0", buf, 32, path);
    g_app.options.global_dl_limit = _wtof(buf) * 1000.0;

    GetPrivateProfileStringW(S, L"GlobalULLimit_KBs", L"0", buf, 32, path);
    g_app.options.global_ul_limit = _wtof(buf) * 1000.0;

    // NIC matching
    GetPrivateProfileStringW(S, L"SelectedNICs", L"", buf, 1024, path);
    if (wcslen(buf) > 0) {
        // Enumerate current adapters once
        ULONG adLen = 0;
        GetAdaptersInfo(NULL, &adLen);
        IP_ADAPTER_INFO *pAdapters = (adLen > 0) ? malloc(adLen) : NULL;
        bool adapters_ok = (pAdapters &&
                            GetAdaptersInfo(pAdapters, &adLen) == NO_ERROR);

        g_app.options.selected_nics[0] = L'\0';
        g_app.missing_nic_warning[0]   = L'\0';

        // Walk the semicolon-separated description list
        wchar_t temp[1024];
        wcscpy(temp, buf);
        wchar_t *ctx = NULL;
        wchar_t *tok = wcstok_s(temp, L";", &ctx);

        while (tok) {
            bool found = false;

            if (adapters_ok) {
                IP_ADAPTER_INFO *p = pAdapters;
                while (p) {
                    wchar_t desc[128];
                    MultiByteToWideChar(CP_ACP, 0, p->Description, -1, desc, 128);
                    if (_wcsicmp(desc, tok) == 0) {
                        // Append numeric index to selected_nics (comma-separated).
                        wchar_t entry[16];
                        swprintf(entry, 16, L"%u", p->Index);
                        if (g_app.options.selected_nics[0])
                            wcsncat(g_app.options.selected_nics, L",",
                                    255 - wcslen(g_app.options.selected_nics));
                        wcsncat(g_app.options.selected_nics, entry,
                                255 - wcslen(g_app.options.selected_nics));
                        found = true;
                        break;
                    }
                    p = p->Next;
                }
            }

            if (!found) {
                // Record the first missing NIC name for a status-bar warning.
                if (!g_app.missing_nic_warning[0]) {
                    swprintf(g_app.missing_nic_warning, 256,
                             L"Saved NIC not found: \"%s\" - check Options", tok);
                }
            }

            tok = wcstok_s(NULL, L";", &ctx);
        }

        free(pAdapters);
    }

    // Buffer / burst
    GetPrivateProfileStringW(S, L"DLBuffer", L"0", buf, 32, path);
    { unsigned v = (unsigned)_wtoi(buf); if (v) g_app.options.dl_buffer = v; }

    GetPrivateProfileStringW(S, L"ULBuffer", L"0", buf, 32, path);
    { unsigned v = (unsigned)_wtoi(buf); if (v) g_app.options.ul_buffer = v; }

    GetPrivateProfileStringW(S, L"BurstSize", L"-1", buf, 32, path);
    { int v = _wtoi(buf); if (v != -1) g_app.options.burst_size = v; }

    // Process update interval
    GetPrivateProfileStringW(S, L"UpdateInterval", L"0", buf, 32, path);
    { unsigned v = (unsigned)_wtoi(buf); if (v) g_app.options.update_interval = v; }

    GetPrivateProfileStringW(S, L"UpdateByPackets", L"0", buf, 2, path);
    g_app.options.update_by_packets = (buf[0] == L'1');

    GetPrivateProfileStringW(S, L"UpdateCooldown", L"0", buf, 32, path);
    { unsigned v = (unsigned)_wtoi(buf); if (v) g_app.options.update_cooldown = v; }

    // UI preferences
    GetPrivateProfileStringW(S, L"MinimizeToTray", L"1", buf, 2, path);
    g_app.minimize_to_tray = (buf[0] != L'0');

    GetPrivateProfileStringW(S, L"DisplayUnit", L"-1", buf, 4, path);
    {
        int v = _wtoi(buf);
        if (v >= 0 && v < UNIT_COUNT) {
            g_app.current_unit = (RateUnit)v;
        }
    }
}

// ---------------------------------------------------------------------------
// NIC list
// ---------------------------------------------------------------------------
void PopulateNicList(HWND hDlg) {
    HWND hList = GetDlgItem(hDlg, IDC_OPT_NIC_LIST);
    SendMessage(hList, LB_RESETCONTENT, 0, 0);

    // Get adapter info
    ULONG bufLen = 0;
    GetAdaptersInfo(NULL, &bufLen);  // Get required size

    if (bufLen == 0) return;

    IP_ADAPTER_INFO* pAdapters = (IP_ADAPTER_INFO*)malloc(bufLen);
    if (!pAdapters) return;

    if (GetAdaptersInfo(pAdapters, &bufLen) == NO_ERROR) {
        IP_ADAPTER_INFO* pAdapter = pAdapters;
        while (pAdapter) {
            // Format: "[Index] Description (IP)"
            wchar_t entry[256];
            wchar_t desc[128];
            wchar_t ip[32];

            // Convert description to wide
            MultiByteToWideChar(CP_ACP, 0, pAdapter->Description, -1, desc, 128);

            // Get first IP address
            if (pAdapter->IpAddressList.IpAddress.String[0] != '0') {
                MultiByteToWideChar(CP_ACP, 0, pAdapter->IpAddressList.IpAddress.String, -1, ip, 32);
            } else {
                wcscpy(ip, L"No IP");
            }

            swprintf(entry, 256, L"[%u] %s (%s)",
                    pAdapter->Index, desc, ip);

            int idx = (int)SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)entry);

            // Store index as item data
            SendMessage(hList, LB_SETITEMDATA, idx, (LPARAM)pAdapter->Index);

            // Select if it was previously selected
            // (check against g_app.options.selected_nics)

            pAdapter = pAdapter->Next;
        }
    }

    free(pAdapters);
}

// ---------------------------------------------------------------------------
// Rate formatting functions
// ---------------------------------------------------------------------------
double ParseRateInput(const wchar_t* input) {
    if (!input || input[0] == L'\0') return 0.0;

    wchar_t* endptr;
    double val = wcstod(input, &endptr);

    // Skip trailing whitespace
    while (iswspace(*endptr)) {
        endptr++;
    }

    // Check for conversion errors
    if (endptr == input || *endptr != L'\0') {
        return 0.0;
    }

    // Check for overflow/underflow
    if (val == HUGE_VAL || val == -HUGE_VAL) {
        return 0.0;
    }

    // Clamp to reasonable range (0 to 1 TB/s)
    if (val < 0) val = 0;
    if (val > 1e12) val = 1e12;

    return val * UNIT_MULTIPLIERS[g_app.current_unit];
}

// For status bar - auto-scales to best unit
void FormatRateAuto(wchar_t* buf, size_t len, double rate_bps) {
    // Find best unit automatically
    int unit = UNIT_GB;
    while (unit > UNIT_BYTES && rate_bps < UNIT_MULTIPLIERS[unit] / 10.0) {
        unit--;
    }

    double val = rate_bps / UNIT_MULTIPLIERS[unit];
    swprintf(buf, len, L"%.2f %s", val, UNIT_LABELS[unit]);
}

// For process list - uses user's selected unit strictly
void FormatRateFixed(wchar_t* buf, size_t len, double rate_bps) {
    double val = rate_bps / UNIT_MULTIPLIERS[g_app.current_unit];
    swprintf(buf, len, L"%.2f %s", val, UNIT_LABELS[g_app.current_unit]);
}

// Parse quota input (MB to bytes)
uint64_t ParseQuotaInput(const wchar_t* input) {
    if (!input || input[0] == L'\0') return 0;

    wchar_t* endptr;
    double mb = wcstod(input, &endptr);

    if (endptr == input || mb <= 0.0) return 0;

    // Convert MB to bytes: multiply by 1024*1024 = 1048576
    const uint64_t MB_TO_BYTES = 1048576ULL;

    if (mb > (double)(UINT64_MAX / MB_TO_BYTES)) {
        return UINT64_MAX;
    }

    return (uint64_t)(mb * MB_TO_BYTES);
}

// ---------------------------------------------------------------------------
// Tooltip helper functions
// ---------------------------------------------------------------------------
HWND CreateTooltips(HWND hDlg, const TooltipDef *defs, int count) {
    UINT dlgDpi = GetDpiForWindow(hDlg);

    // Create tooltip control
    HWND hTip = CreateWindowExW(
        WS_EX_TOPMOST,
        TOOLTIPS_CLASS,
        NULL,
        WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, 
        CW_USEDEFAULT, CW_USEDEFAULT,
        hDlg,  // Parent must be the dialog
        NULL, 
        g_hInst, 
        NULL);

    if (!hTip) {
        return NULL;
    }

    // Modern tooltip settings
    SendMessage(hTip, TTM_SETMAXTIPWIDTH, 0, MulDiv(350, dlgDpi, 96));
    
    // Set initial delay times
    SendMessage(hTip, TTM_SETDELAYTIME, TTDT_AUTOPOP, 10000);
    SendMessage(hTip, TTM_SETDELAYTIME, TTDT_INITIAL, 500);
    SendMessage(hTip, TTM_SETDELAYTIME, TTDT_RESHOW, 100);

    // Set the font for the tooltip
    HFONT hFont = (HFONT)SendMessage(hDlg, WM_GETFONT, 0, 0);
    if (hFont) {
        SendMessage(hTip, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    // Add each tool
    for (int i = 0; i < count; i++) {
        HWND hCtrl = GetDlgItem(hDlg, defs[i].ctrlId);
        if (!hCtrl) {
            continue;
        }

        // Initialize the entire structure to zero first
        TOOLINFOW ti = {0};
        ti.cbSize = TTTOOLINFOW_V2_SIZE;  // Use the correct size constant

        // Set up the tool info
        ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS | TTF_TRANSPARENT;
        ti.hwnd = hDlg;
        ti.uId = (UINT_PTR)hCtrl;
        ti.lpszText = (LPWSTR)defs[i].text;

        // Get the control's rectangle in client coordinates
        RECT rcCtrl;
        GetWindowRect(hCtrl, &rcCtrl);
        POINT pt = {rcCtrl.left, rcCtrl.top};
        ScreenToClient(hDlg, &pt);
        rcCtrl.left = pt.x;
        rcCtrl.top = pt.y;
        pt.x = rcCtrl.right;
        pt.y = rcCtrl.bottom;
        ScreenToClient(hDlg, &pt);
        rcCtrl.right = pt.x;
        rcCtrl.bottom = pt.y;
        ti.rect = rcCtrl;

        // Try to add the tool
        if (!SendMessageW(hTip, TTM_ADDTOOLW, 0, (LPARAM)&ti)) {
            // Try alternative approach - add tool without rectangle first
            ti.rect.left = ti.rect.top = ti.rect.right = ti.rect.bottom = 0;
            SendMessageW(hTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
        }
    }

    // Activate the tooltip
    SendMessage(hTip, TTM_ACTIVATE, TRUE, 0);

    return hTip;
}

// ---------------------------------------------------------------------------
// Various helper functions
// ---------------------------------------------------------------------------
// Update statistics
void UpdateStats(void) {
    if (!g_app.shaper) return;

    // Take atomic snapshot - this is the single source of truth
    TrafficSnapshot snapshot = {0};
    if (!shaper_snapshot_traffic(g_app.shaper, &snapshot)) {
        return;  // Snapshot failed
    }

    uint64_t now = snapshot.timestamp;
    static uint64_t lastTime = 0;
    static uint64_t lastTotalBytes = 0;  // For sparkline calculation

    // Calculate total bytes from snapshot (one pass through snapshot entries)
    uint64_t total_bytes = 0;
    for (int i = 0; i < snapshot.count; i++) {
        total_bytes += snapshot.entries[i].dl_bytes + snapshot.entries[i].ul_bytes;
    }

    shaper_free_traffic_snapshot(&snapshot);

    // Calculate rates for sparkline (unused here)
    //uint64_t elapsed = (lastTime > 0 && now > lastTime) ? (now - lastTime) : 0;

    // Read aggregate rates under lock
    EnterCriticalSection(&g_app.process_lock);

    // Update sparkline history using aggregate rates from process entries
    // (these are already calculated in UpdateProcessRatesFromStats)
    double total_dl_rate = 0, total_ul_rate = 0;
    for (int i = 0; i < g_app.process_count; i++) {
        total_dl_rate += g_app.processes[i].dl_rate;
        total_ul_rate += g_app.processes[i].ul_rate;
    }

    LeaveCriticalSection(&g_app.process_lock);

    g_app.dl_history[g_app.history_head] = total_dl_rate;
    g_app.ul_history[g_app.history_head] = total_ul_rate;
    g_app.history_head = (g_app.history_head + 1) % SPARKLINE_SAMPLES;

    // Update last values for next delta calculation
    lastTotalBytes = total_bytes;
    lastTime = now;

    // Get overall stats for other metrics (these are cheap, just reading counters)
    ShaperStats stats;
    shaper_get_stats(g_app.shaper, &stats);

    // Update status bar with current throughput
    wchar_t buf[64];
    wchar_t dl_str[32], ul_str[32];

    FormatRateAuto(dl_str, 32, total_dl_rate);
    FormatRateAuto(ul_str, 32, total_ul_rate);

    swprintf(buf, 64, L"%s %s %s %s",
             dl_str, DOWNWARDS_ARROW, ul_str, UPWARDS_ARROW);

    SendMessageW(g_app.hStatusBar, SB_SETTEXT, 2, (LPARAM)buf);
}

// Draw sparkline for statistics
void DrawSparkline(HDC hdc, RECT* rect, double* history, COLORREF color) {
    // Save DC state
    int savedDC = SaveDC(hdc);

    // Set clipping region to prevent drawing outside
    IntersectClipRect(hdc, rect->left, rect->top, rect->right, rect->bottom);

    // Fill background
    HBRUSH hbrBlack = CreateSolidBrush(RGB(0, 0, 0));
    FillRect(hdc, rect, hbrBlack);
    DeleteObject(hbrBlack);

    int W = rect->right - rect->left;
    int H = rect->bottom - rect->top;

    if (W <= 0 || H <= 0) {
        RestoreDC(hdc, savedDC);
        return;
    }

    // Find max for scaling
    double maxVal = 1.0;
    int i;
    for (i = 0; i < SPARKLINE_SAMPLES; i++) {
        if (history[i] > maxVal) maxVal = history[i];
    }

    // Draw grid lines (subtle)
    HPEN gridPen = CreatePen(PS_SOLID, 1, RGB(40, 40, 40));
    HPEN oldPen = SelectObject(hdc, gridPen);
    for (i = 1; i < 4; i++) {
        int y = rect->top + (H * i) / 4;
        MoveToEx(hdc, rect->left, y, NULL);
        LineTo(hdc, rect->right, y);
    }
    SelectObject(hdc, oldPen);
    DeleteObject(gridPen);

    // Draw data line with proper pen selection/deselection
    HPEN dataPen = CreatePen(PS_SOLID, 2, color);
    HPEN oldDataPen = SelectObject(hdc, dataPen);

    bool first = true;
    for (i = 0; i < SPARKLINE_SAMPLES; i++) {
        int idx = (g_app.history_head + i) % SPARKLINE_SAMPLES;
        double val = history[idx];

        int x = rect->left + (i * W) / (SPARKLINE_SAMPLES - 1);
        int y = rect->bottom - 5 - (int)((val / maxVal) * (H - 10));

        // Clamp to drawing area
        if (y < rect->top + 5) y = rect->top + 5;
        if (y > rect->bottom - 5) y = rect->bottom - 5;

        if (first) {
            MoveToEx(hdc, x, y, NULL);
            first = false;
        } else {
            LineTo(hdc, x, y);
        }
    }

    // Restore the original pen before deleting
    SelectObject(hdc, oldDataPen);
    DeleteObject(dataPen);

    // Draw legend text
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, color);
    wchar_t label[32];
    swprintf(label, 32, L"%.1f", maxVal / 1000.0);
    TextOutW(hdc, rect->left + 5, rect->top + 2, label, (int)wcslen(label));

    // Restore DC
    RestoreDC(hdc, savedDC);
}

// Change the update frequency
void ApplyUpdateFrequency(int idx) {
    if (idx < 0 || idx > 5) return;
    g_app.freq_idx = idx;

    // Kill the current timer unconditionally
    KillTimer(g_app.hMainWnd, TIMER_PROCESS_REFRESH);

    UINT interval = FREQ_INTERVALS[idx];
    if (interval > 0) {
        SetTimer(g_app.hMainWnd, TIMER_PROCESS_REFRESH, interval, NULL);
    }
    // interval == 0 means "Disabled" - timer stays killed, no further refresh

    // Update the View > Update Frequency submenu checkmarks
    HMENU hMenu = GetMenu(g_app.hMainWnd);
    if (!hMenu) return;
    HMENU hView = GetSubMenu(hMenu, 1);   // "View" is the second top-level item
    if (!hView) return;
    HMENU hFreq = NULL;
    for (int i = 0; i < GetMenuItemCount(hView); i++) {
        HMENU sub = GetSubMenu(hView, i);
        if (sub && GetMenuState(sub, ID_FREQ_OFTEN, MF_BYCOMMAND) != (UINT)-1) {
            hFreq = sub;
            break;
        }
    }
    if (!hFreq) return;

    for (int i = 0; i <= 5; i++) {
        CheckMenuItem(hFreq, ID_FREQ_OFTEN + i,
                      MF_BYCOMMAND | (i == idx ? MF_CHECKED : MF_UNCHECKED));
    }
}

// Check if any process has reached its quota limit
bool IsAnyQuotaExhausted(void) {
    for (int i = 0; i < g_app.process_count; i++) {
        ProcessEntry* proc = &g_app.processes[i];
        if ((proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in) ||
            (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out)) {
            return true;
        }
    }
    return false;
}

// Returns true if at least one sticky process has a non-empty schedule.
// Used to skip the TIMER_SCHEDULE_CHECK work entirely when nothing is configured.
bool AnyScheduleActive(void) {
    for (int i = 0; i < g_app.process_count; i++) {
        const ProcessEntry *p = &g_app.processes[i];
        if (p->is_sticky && !schedule_is_empty(&p->schedule))
            return true;
    }
    return false;
}

// Returns the milliseconds to wait before the next schedule boundary fires.
// Scans every sticky process with has_time == true and finds the nearest
// start_min or end_min (in today's minute-of-day), then converts to ms
// minus the seconds already elapsed in the current minute, plus 1s of slack
// so we fire just after the boundary rather than just before.
// Clamped to [5000, 30000] ms.  Falls back to 30000 when there are no
// time-constrained schedules (day-only schedules need only a midnight nudge).
UINT ScheduleNextFireMs(void) {
    const UINT MIN_MS = 5000;
    const UINT MAX_MS = 30000;

    SYSTEMTIME st;
    GetLocalTime(&st);
    int now_min = st.wHour * 60 + st.wMinute;
    int now_sec = st.wSecond;

    int nearest = INT_MAX;

    for (int i = 0; i < g_app.process_count; i++) {
        const ProcessEntry *p = &g_app.processes[i];
        if (!p->is_sticky || !p->schedule.has_time) continue;

        int bounds[2] = { p->schedule.start_min, p->schedule.end_min };
        for (int b = 0; b < 2; b++) {
            int delta = bounds[b] - now_min;
            if (delta < 0) delta += 24 * 60;
            if (delta < nearest) nearest = delta;
        }
    }

    if (nearest == INT_MAX) return MAX_MS;

    // If we're at a boundary (nearest == 0), fire at MIN_MS
    // Otherwise calculate normally
    int ms;
    if (nearest == 0) {
        ms = MIN_MS;  // At boundary - check soon
    } else {
        ms = nearest * 60 * 1000 - now_sec * 1000 + 1000;
    }
    
    if (ms < (int)MIN_MS) ms = (int)MIN_MS;
    if (ms > (int)MAX_MS) ms = (int)MAX_MS;
    return (UINT)ms;
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------
void LayoutMainWindow(HWND hWnd) {
    // Resize child controls
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);

    int toolbarHeight = S(40);
    int statusHeight = S(25);
    int comboWidth = S(80);
    int margin = S(8);

    // Toolbar area
    SetWindowPos(g_app.hToolbar, NULL, 0, 0, rcClient.right, toolbarHeight, SWP_NOZORDER);

    // Position buttons and unit selector within toolbar area
    HWND hStart = GetDlgItem(hWnd, IDC_START_BTN);
    HWND hStop = GetDlgItem(hWnd, IDC_STOP_BTN);
    HWND hReload = GetDlgItem(hWnd, IDC_RELOAD_BTN);

    SetWindowPos(hStart, NULL, margin, S(8), S(60), S(24), SWP_NOZORDER);
    SetWindowPos(hStop, NULL, margin + S(70), S(8), S(60), S(24), SWP_NOZORDER);
    SetWindowPos(hReload, NULL, margin + S(140), S(8), S(60), S(24), SWP_NOZORDER);
    SetWindowPos(g_app.hUnitCombo, NULL, margin + S(220), S(8), comboWidth, S(24), SWP_NOZORDER);

    // Process list
    SetWindowPos(g_app.hProcessList, NULL, margin, toolbarHeight + margin,
                 rcClient.right - margin * 2,
                 rcClient.bottom - toolbarHeight - statusHeight - margin * 2,
                 SWP_NOZORDER);

    // Status bar
    SetWindowPos(g_app.hStatusBar, NULL, 0, rcClient.bottom - statusHeight,
                 rcClient.right, statusHeight, SWP_NOZORDER);

    // Reflow status bar part widths to match new window width
    {
        int parts[3];
        parts[0] = S(200);
        parts[1] = rcClient.right - S(180);  // process count part grows with window
        parts[2] = -1;
        SendMessage(g_app.hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    }
}

void onTimer(HWND hWnd, WPARAM wParam) {
    if (wParam == TIMER_STATS_ID && g_app.shaper) {
        UpdateProcessRatesFromStats();
        UpdateStats();
        if (!g_app.pause_refresh) UpdateProcessList();
    } else if (wParam == TIMER_PROCESS_REFRESH) {
        RefreshProcessList();
        if (g_app.shaper && shaper_is_running(g_app.shaper)) shaper_periodic_cleanup(g_app.shaper, 30, 15); // interval_seconds, max_age_seconds
    } else if (wParam == TIMER_SCHEDULE_CHECK) {
        // Re-evaluate schedule windows for all sticky processes and push
        // updated rules to the core if anything changed
        // Skip entirely if no sticky process has a schedule configured
        if (AnyScheduleActive() && g_app.shaper && shaper_is_running(g_app.shaper)) {
            UpdateProcessLimits();
            InvalidateRect(g_app.hProcessList, NULL, FALSE);
        }
        // One-shot: re-arm aligned to the nearest upcoming boundary so the
        // timer fires close to the exact minute a window opens or closes.
        RearmScheduleTimer(hWnd);
    }
}

// Convenience: kill then immediately re-arm TIMER_SCHEDULE_CHECK as a one-shot
// aligned to the next schedule boundary.
void RearmScheduleTimer(HWND hWnd) {
    KillTimer(hWnd, TIMER_SCHEDULE_CHECK);
    SetTimer(hWnd, TIMER_SCHEDULE_CHECK, ScheduleNextFireMs(), NULL);
}

// ---------------------------------------------------------------------------
// Command handlers (delegates)
// ---------------------------------------------------------------------------
BOOL onCommand(HWND hWnd, WPARAM wParam, LPARAM lParam) {
    int id = LOWORD(wParam);

    // Menu commands
    switch (id) {
    case ID_FILE_LOCATE_PROC:
        Cmd_LocateProcess(hWnd);
        return 0;

    case ID_FILE_SPECIFY_PROC:
        Cmd_SpecifyProcess(hWnd);
        return 0;

    case ID_FILE_REMOVE_CUSTOM:
        Cmd_RemoveStickyEntry(hWnd);
        return 0;

    case ID_FILE_EXIT:
        PostMessage(hWnd, WM_CLOSE, 0, 0);
        return 0;

    case ID_VIEW_REFRESH:
        RefreshProcessList();
        return 0;

    case ID_VIEW_EXPAND_ALL:
        for (int i = 0; i < g_app.process_count; i++)
            g_app.processes[i].expanded = (g_app.processes[i].pid_count > 1);
        RebuildDisplayRows();
        InvalidateRect(g_app.hProcessList, NULL, FALSE);
        return 0;

    case ID_VIEW_COLLAPSE_ALL:
        for (int i = 0; i < g_app.process_count; i++)
            g_app.processes[i].expanded = false;
        RebuildDisplayRows();
        InvalidateRect(g_app.hProcessList, NULL, FALSE);
        return 0;

    case ID_FREQ_OFTEN:
    case ID_FREQ_NORMAL:
    case ID_FREQ_SLOWER:
    case ID_FREQ_SCARCELY:
    case ID_FREQ_RARELY:
    case ID_FREQ_DISABLED:
        ApplyUpdateFrequency(LOWORD(wParam) - ID_FREQ_OFTEN);
        return 0;

    case ID_PROC_SHOW_ALL:
        ApplyProcFilter(PROC_FILTER_ALL);
        return 0;
    case ID_PROC_SHOW_CUSTOM:
        ApplyProcFilter(PROC_FILTER_STICKY_ONLY);
        return 0;
    case ID_PROC_SHOW_RUNNING:
        ApplyProcFilter(PROC_FILTER_RUNNING_ONLY);
        return 0;

    case ID_VIEW_OPTIONS:
        if (!g_app.options_window_open) {
            g_app.options_window_open = true;
            DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_OPTIONS_DIALOG), hWnd, OptionsDlgProc);
            g_app.options_window_open = false;
        }
        return 0;

    case ID_VIEW_STATS:
        if (!g_app.hStatsWnd) {
            OpenOrFocusStats(hWnd);
        }
        return 0;

    case ID_HELP_ABOUT:
        wchar_t buff[256];
        swprintf(buff, 256, L"BandwidthShaper " APP_VERSION L"\nAdvanced Traffic Shaper");
        MSGBOX(hWnd, buff, L"About", MB_OK);
        return 0;
    }

    // Button commands
    switch (id) {
    case IDC_START_BTN:
        if (!g_app.shaper && StartShaper()) {
            EnableWindow(GetDlgItem(hWnd, IDC_START_BTN), FALSE);
            EnableWindow(GetDlgItem(hWnd, IDC_STOP_BTN), TRUE);
            EnableWindow(GetDlgItem(hWnd, IDC_RELOAD_BTN), TRUE);
            SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Shaper running");
        }
        return 0;

    case IDC_STOP_BTN:
        StopShaper();
        EnableWindow(GetDlgItem(hWnd, IDC_START_BTN), TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_STOP_BTN), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_RELOAD_BTN), FALSE);
        SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Stopped");
        return 0;

    case IDC_RELOAD_BTN:
        if (g_app.shaper && shaper_is_running(g_app.shaper)) {
            if (ReloadShaperConfig()) {
                SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Configuration reloaded");
            } else {
                char err[512];
                snprintf(err, 512, "Reload failed: %s",
                        shaper_get_last_error(g_app.shaper));
                wchar_t werr[512];
                MultiByteToWideChar(CP_UTF8, 0, err, -1, werr, 512);
                MSGBOX(hWnd, werr, L"Reload Error", MB_OK | MB_ICONERROR);

                // Fallback
                StopShaper();
                if (StartShaper()) {
                    SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Configuration reloaded (fallback)");
                }
            }
        } else {
            // Shaper not running - just start
            if (StartShaper()) {
                SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Configuration reloaded");
            }
        }
        return 0;

    case IDC_UNIT_COMBO:
        if (HIWORD(wParam) == CBN_SELCHANGE) {
            int sel = (int)SendMessage(g_app.hUnitCombo, CB_GETCURSEL, 0, 0);
            if (sel >= 0 && sel < UNIT_COUNT) {
                g_app.current_unit = (RateUnit)sel;
                RefreshProcessList();  // Update displayed rates
            }
        }
        return 0;
    }

    // Process list context menu or limit changes
    if (id >= 10000 && id < 20000) {
        // Process limit edit controls
        int procIdx = (id - 10000) / 10;
        int colIdx = (id - 10000) % 10;

        if (procIdx < g_app.process_count) {
            HWND hEdit = (HWND)lParam;
            wchar_t buf[32];
            GetWindowTextW(hEdit, buf, 32);
            double val = _wtof(buf);

            if (colIdx == IDC_PL_DL_LIMIT) {
                g_app.processes[procIdx].dl_limit = val * UNIT_MULTIPLIERS[g_app.current_unit];
            } else if (colIdx == IDC_PL_UL_LIMIT) {
                g_app.processes[procIdx].ul_limit = val * UNIT_MULTIPLIERS[g_app.current_unit];
            }

            UpdateProcessLimits();
        }
        return 0;
    }

    // Tray menu commands
    switch (id) {
    case ID_TRAY_SHOW:
        if (IsWindowVisible(hWnd)) {
            ShowWindow(hWnd, SW_HIDE);
        } else {
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
        }
        return 0;

    case ID_TRAY_START:
        if (!g_app.shaper && StartShaper()) {
            EnableWindow(GetDlgItem(hWnd, IDC_START_BTN), FALSE);
            EnableWindow(GetDlgItem(hWnd, IDC_STOP_BTN), TRUE);
            EnableWindow(GetDlgItem(hWnd, IDC_RELOAD_BTN), TRUE);
            SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Shaper running");
        }
        return 0;

    case ID_TRAY_STOP:
        StopShaper();
        EnableWindow(GetDlgItem(hWnd, IDC_START_BTN), TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_STOP_BTN), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_RELOAD_BTN), FALSE);
        SendMessage(g_app.hStatusBar, SB_SETTEXT, 0, (LPARAM)L"Stopped");
        return 0;

    case ID_TRAY_STATS:
        if (!g_app.hStatsWnd) {
            OpenOrFocusStats(hWnd);
        }
        return 0;

    case ID_TRAY_EXIT:
        PostMessage(hWnd, WM_CLOSE, 0, 0);
        return 0;
    }
    
    return FALSE;
}

// ---------------------------------------------------------------------------
// Window lifecycle
// ---------------------------------------------------------------------------
LRESULT onCreate(HWND hWnd) {
    g_app.processes = g_processes;
    g_app.process_count = 0;
    memset(g_processes, 0, sizeof(g_processes));  // Clear all including histories
    g_app.dpi = GetDpiForWindow(hWnd);  // Requires Win10 1607+
    RecreateUiFont();
    g_app.hMainWnd = hWnd;

    // Set default options
    g_app.options.dl_buffer = DEFAULT_DL_BUFFER;
    g_app.options.ul_buffer = DEFAULT_UL_BUFFER;
    g_app.options.burst_size = 0;
    g_app.options.update_interval = 1500;
    g_app.options.update_by_packets = false;
    g_app.options.update_cooldown = 5000;
    g_app.options.data_cap = 0;
    g_app.options.tcp_limit = 0;
    g_app.options.udp_limit = 0;
    g_app.options.latency = 0;
    g_app.options.packet_loss = 0.0f;
    g_app.options.priority = 0;
    g_app.options.global_dl_limit = 0;
    g_app.options.global_ul_limit = 0;
    g_app.current_unit = UNIT_KB;
    g_app.minimize_to_tray = false;
    g_app.options.save_settings = false;
    g_app.options.save_sticky_settings = false;

    g_app.sort_column = 0;      // Default sort by Process name
    g_app.sort_ascending = true;

    // Load dark mode
    InitializeDarkMode();

    // Load persisted sticky entries before the first process refresh
    Sticky_Load();

    // Load stored settings
    Settings_Load();
    if (g_app.missing_nic_warning[0]) {
        PostMessage(hWnd, WM_APP_NIC_WARNING, 0, 0);  // handled later
    }

    // Initialize process lock
    if (!InitializeCriticalSectionAndSpinCount(&g_app.process_lock, 4000)) {
        DestroyWindow(hWnd);
        return -1;
    }
    g_app.process_lock_initialized = true;

    // Initialize after Settings got loaded
    InitializeMainWindow(hWnd);
    g_app.proc_filter = PROC_FILTER_ALL;
    ApplyProcFilter(g_app.proc_filter);  // Only after ListView

    // Try/catch-style protection for remaining initialization
    bool init_success = true;

    // Sync combo after creation
    if (g_app.hUnitCombo) {
        SendMessage(g_app.hUnitCombo, CB_SETCURSEL, (WPARAM)g_app.current_unit, 0);
    } else {
        init_success = false;
    }

    // Apply dark mode if enabled (after all controls created)
    DarkMode_InitUxtheme();
    g_app.dark_mode = DarkMode_SystemIsDark();
    if (g_app.dark_mode) {
        ApplyDarkModeToAllControls(hWnd, true);
    }

    // Start timers
    g_app.freq_idx = FREQ_DEFAULT_IDX;
    ApplyUpdateFrequency(g_app.freq_idx);
    if (!SetTimer(hWnd, TIMER_SCHEDULE_CHECK, ScheduleNextFireMs(), NULL)) {
        init_success = false;
    }

    if (g_app.minimize_to_tray) TrayAdd(hWnd);
    RefreshProcessList();

    if (!init_success) {
        // Clean up on partial initialization failure
        if (g_app.process_lock_initialized) {
            DeleteCriticalSection(&g_app.process_lock);
            g_app.process_lock_initialized = false;
        }
        DestroyWindow(hWnd);
        return -1;
    }
    return 0;
}

LRESULT onClose(HWND hWnd) {
    KillTimer(g_app.hMainWnd, TIMER_STATS_ID);
    KillTimer(g_app.hMainWnd, TIMER_PROCESS_REFRESH);
    KillTimer(g_app.hMainWnd, TIMER_SCHEDULE_CHECK);
    StopShaper();
    CleanupDarkMode();
    TrayRemove();
    Sticky_Save();
    Settings_Save();
    if (g_app.hStatsWnd) {
        DestroyWindow(g_app.hStatsWnd);
        g_app.hStatsWnd = NULL;
    }
    DestroyWindow(hWnd);
    return 0;
}

LRESULT onDestroy(HWND hWnd) {
    if (g_app.process_lock_initialized) {
        DeleteCriticalSection(&g_app.process_lock);
    }
    PostQuitMessage(0);
    return 0;
}

LRESULT onDrawItem(HWND hWnd, LPARAM lParam) {
    if (!g_app.dark_mode) return FALSE;
    LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
    if (dis->CtlType == ODT_BUTTON) {
        DrawDarkButton(dis);
        return TRUE;
    }
    return FALSE;
}

LRESULT onEraseBkgnd(HWND hWnd, WPARAM wParam) {
    if (!g_app.dark_mode) return FALSE;
    HDC hdc = (HDC)wParam;
    RECT rc;
    GetClientRect(hWnd, &rc);
    FillRect(hdc, &rc, g_app.hDarkBrush);
    return 1;
}

LRESULT onUahDrawMenu(HWND hWnd, WPARAM wParam, LPARAM lParam) {
    if (!g_app.dark_mode) return FALSE;
    UAHMENU *um = (UAHMENU *)lParam;
    MENUBARINFO mbi = { sizeof(mbi) };
    GetMenuBarInfo(hWnd, OBJID_MENU, 0, &mbi);
    RECT rcWindow;
    GetWindowRect(hWnd, &rcWindow);
    // Fill the menu bar background
    RECT rc = mbi.rcBar;
    OffsetRect(&rc, -rcWindow.left, -rcWindow.top);
    FillRect(um->hdc, &rc, g_app.hDarkBrush);
    return TRUE;
}

LRESULT onUahDrawMenuItem(HWND hWnd, WPARAM wParam, LPARAM lParam) {
    if (!g_app.dark_mode) return FALSE;
    UAHDRAWMENUITEM *umi = (UAHDRAWMENUITEM *)lParam;
    // Hot/selected state
    BOOL hot = (umi->dis.itemState & (ODS_HOTLIGHT | ODS_SELECTED)) != 0;
    COLORREF bg = hot ? DARK_HIGHLIGHT_COLOR : DARK_BG_COLOR;
    COLORREF fg = hot ? DARK_TEXT_COLOR     : DARK_TEXT_COLOR;
    HBRUSH hbr = CreateSolidBrush(bg);
    FillRect(umi->um.hdc, &umi->dis.rcItem, hbr);
    DeleteObject(hbr);
    // Get and draw item text
    wchar_t buf[256] = {0};
    MENUITEMINFOW mii = { sizeof(mii) };
    mii.fMask    = MIIM_STRING;
    mii.dwTypeData = buf;
    mii.cch      = 256;
    GetMenuItemInfoW(umi->um.hmenu, umi->umi.iPosition, TRUE, &mii);
    SetBkMode(umi->um.hdc, TRANSPARENT);
    SetTextColor(umi->um.hdc, fg);
    DrawTextW(umi->um.hdc, buf, -1, &umi->dis.rcItem,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    return TRUE;
}

LRESULT areaNC(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!g_app.dark_mode) return FALSE;
    LRESULT lr = DefWindowProc(hWnd, msg, wParam, lParam);
    // Repaint the bottom line of the NC area that separates menubar from client
    // (UAHMenuBar calls this UAHDrawMenuNCBottomLine)
    RECT rcClient;
    GetClientRect(hWnd, &rcClient);
    HDC hdc = GetWindowDC(hWnd);
    if (hdc) {
        RECT rcWindow;
        GetWindowRect(hWnd, &rcWindow);
        MapWindowPoints(HWND_DESKTOP, hWnd, (LPPOINT)&rcClient, 2);
        // Draw over the light separator line
        RECT rcSep = { rcClient.left, rcClient.top - 1,
                       rcClient.right, rcClient.top };
        FillRect(hdc, &rcSep, g_app.hDarkBrush);
        ReleaseDC(hWnd, hdc);
    }
    return lr ? lr : TRUE;  // ensure non-zero so caller skips second DefWindowProc
}

LRESULT settingChanged(HWND hWnd, WPARAM wParam, LPARAM lParam) {
    if (lParam && wcscmp((wchar_t*)lParam, L"ImmersiveColorSet") == 0) {
        BOOL nowDark = DarkMode_SystemIsDark();
        if (nowDark != g_app.dark_mode) {
            g_app.dark_mode = nowDark;
            ApplyDarkModeToAllControls(hWnd, g_app.dark_mode);
            // Recolour the ListView explicitly since it needs extra calls
            if (g_app.dark_mode) {
                ApplyDarkModeToListViewHeader(g_app.hProcessList);
            }
            /*if (g_app.hStatsWnd) {
                SendMessage(g_app.hStatsWnd, WM_SETTINGCHANGE, wParam, lParam);
                ApplyDarkModeToAllControls(g_app.hStatsWnd, g_app.dark_mode);
                UpdateStatistics_RichBox();
            }*/

            InvalidateRect(hWnd, NULL, TRUE);
            // Force full redraw of main window
            RedrawWindow(hWnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
        }
    }
    return FALSE;
}

LRESULT onDpiChanged(HWND hWnd, WPARAM wParam, LPARAM lParam) {
    g_app.dpi = HIWORD(wParam);  // new DPI
    RecreateUiFont();

    // Store current selection before font change
    int curSel = (int)SendMessage(g_app.hUnitCombo, CB_GETCURSEL, 0, 0);
    if (curSel != CB_ERR) g_app.current_unit = (RateUnit)curSel;

    // Windows tells us exactly where to put the window at the new DPI
    RECT *rc = (RECT*)lParam;
    SetWindowPos(hWnd, NULL,
                 rc->left, rc->top,
                 rc->right  - rc->left,
                 rc->bottom - rc->top,
                 SWP_NOZORDER | SWP_NOACTIVATE);

    // Reflow everything
    ApplyFontToChildren(hWnd);
    // Rebuild column widths in the ListView
    struct { int width; } cols[] = {
        {S(170)},{S(55)},{S(75)},{S(75)},
        {S(75)},{S(75)},{S(80)},{S(80)},{S(100)},{S(70)}
    };
    for (int i = 0; i < 10; i++)
        ListView_SetColumnWidth(g_app.hProcessList, i, cols[i].width);

    // Reapply current selection so the combo face shows the right text after font change
    SendMessage(g_app.hUnitCombo, CB_SETCURSEL, (WPARAM)g_app.current_unit, 0);

    // Recalculate combo box height for new DPI
    GetWindowRect(g_app.hUnitCombo, rc);
    MapWindowPoints(NULL, hWnd, (LPPOINT)rc, 2);
    SetWindowPos(g_app.hUnitCombo, NULL, 
        rc->left, rc->top, 
        rc->right - rc->left, S(100),
        SWP_NOZORDER);

    // Reflow row height via the font-change message
    SendMessage(g_app.hProcessList, WM_SETFONT,
                (WPARAM)g_app.hUiFont, MAKELPARAM(TRUE, 0));

    InvalidateRect(g_app.hUnitCombo, NULL, TRUE);
    InvalidateRect(hWnd, NULL, TRUE);
    return 0;
}
