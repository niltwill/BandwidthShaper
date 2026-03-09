// Options, Stats, Specify Process, Schedule dialogs

#include "gui_constants.h"
#include "gui_state.h"
#include "gui_dialogs.h"
#include "gui_utils.h"
#include "gui_proc_list.h"
#include "resource.h"
#include "shaper_core.h"
#include "schedule.h"
#include <richedit.h>
#include <commdlg.h>
#include <shlobj.h>

// Stats dialog context
typedef struct {
    uint64_t lastDlBytes;
    uint64_t lastUlBytes;
    uint64_t lastTime;
    BOOL initialized;
    TrafficSnapshot last_snapshot;
    bool has_snapshot;
} StatsDialogContext;

// Control IDs for ScheduleDlgProc (avoids conflict with main window)
enum {
    SDLG_CHK_TIME   = 100,
    SDLG_EDIT_SH    = 101,  // start hour
    SDLG_EDIT_SM    = 102,  // start minute
    SDLG_EDIT_EH    = 103,  // end hour
    SDLG_EDIT_EM    = 104,  // end minute
    SDLG_LBL_COLON1 = 105,
    SDLG_LBL_DASH   = 106,
    SDLG_LBL_COLON2 = 107,
    SDLG_LBL_24H    = 108,
    SDLG_CHK_DAYS   = 110,
    SDLG_DAY_MON    = 111,  // days 111..117 = Mon..Sun
    SDLG_DAY_TUE    = 112,
    SDLG_DAY_WED    = 113,
    SDLG_DAY_THU    = 114,
    SDLG_DAY_FRI    = 115,
    SDLG_DAY_SAT    = 116,
    SDLG_DAY_SUN    = 117,
    SDLG_DESC_LABEL = 140,
    SDLG_BTN_RESET  = 120,
    SDLG_BTN_OK     = 121,
    SDLG_BTN_CANCEL = 122,
};

// ---------------------------------------------------------------------------
// Options dialog
// ---------------------------------------------------------------------------
INT_PTR CALLBACK OptionsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;

    switch (msg) {
    case WM_INITDIALOG: {
        // Initialize controls with current values
        SetDlgItemInt(hDlg, IDC_OPT_DL_BUFFER, g_app.options.dl_buffer, FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_UL_BUFFER, g_app.options.ul_buffer, FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_BURST_SIZE, g_app.options.burst_size, TRUE);
        SetDlgItemInt(hDlg, IDC_OPT_UPDATE_INTERVAL, g_app.options.update_interval, FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_UPDATE_COOLDOWN, g_app.options.update_cooldown, FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_DATA_CAP, (UINT)(g_app.options.data_cap / 1000000), FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_TCP_LIMIT, g_app.options.tcp_limit, FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_UDP_LIMIT, g_app.options.udp_limit, FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_LATENCY, g_app.options.latency, FALSE);

        wchar_t buf[32];
        swprintf(buf, 32, L"%.2f", g_app.options.packet_loss);
        SetDlgItemTextW(hDlg, IDC_OPT_PACKET_LOSS, buf);

        if (g_app.options.priority > 30000) g_app.options.priority = 30000;
        if (g_app.options.priority < -30000) g_app.options.priority = -30000;
        SetDlgItemInt(hDlg, IDC_OPT_PRIORITY, g_app.options.priority, TRUE);

        // Global limits
        SetDlgItemInt(hDlg, IDC_OPT_DL_GLOBAL, (UINT)(g_app.options.global_dl_limit / 1000), FALSE);
        SetDlgItemInt(hDlg, IDC_OPT_UL_GLOBAL, (UINT)(g_app.options.global_ul_limit / 1000), FALSE);

        // Update type radio buttons
        if (g_app.options.update_by_packets) {
            CheckDlgButton(hDlg, IDC_OPT_UPDATE_TYPE, BST_CHECKED);       // Packets
            CheckDlgButton(hDlg, IDC_OPT_UPDATE_TYPE + 1, BST_UNCHECKED); // Milliseconds
        } else {
            CheckDlgButton(hDlg, IDC_OPT_UPDATE_TYPE, BST_UNCHECKED);     // Packets
            CheckDlgButton(hDlg, IDC_OPT_UPDATE_TYPE + 1, BST_CHECKED);   // Milliseconds
        }

        // Minimize to tray checkbox
        CheckDlgButton(hDlg, IDC_OPT_MINIMIZE_TRAY,
                      g_app.minimize_to_tray ? BST_CHECKED : BST_UNCHECKED);

        // Save settings to config file
        CheckDlgButton(hDlg, IDC_OPT_SAVE_SETTINGS,
                      g_app.options.save_settings ? BST_CHECKED : BST_UNCHECKED);

        // Save sticky settings to config file
        CheckDlgButton(hDlg, IDC_OPT_SAVE_STICKY_SETTINGS,
                      g_app.options.save_sticky_settings ? BST_CHECKED : BST_UNCHECKED);

        // File path fields
        SetDlgItemTextW(hDlg, IDC_OPT_CONFIG_DIR,   g_app.options.config_dir);
        SetDlgItemTextW(hDlg, IDC_OPT_SNAPSHOT_DIR, g_app.options.snapshot_dir);

        // Apply dark mode to this dialog if enabled
        if (g_app.dark_mode) {
            ApplyDarkModeToDialog(hDlg);
        }

        // Populate NIC list
        PopulateNicList(hDlg);

        // Restore previous selections
        HWND hList = GetDlgItem(hDlg, IDC_OPT_NIC_LIST);

        // Parse g_app.options.selected_nics and select matching items
        if (wcslen(g_app.options.selected_nics) > 0) {
            wchar_t temp[256];
            wcscpy(temp, g_app.options.selected_nics);
            wchar_t* context = NULL;
            wchar_t* token = wcstok_s(temp, L",", &context);

            while (token != NULL) {
                DWORD targetIndex = (DWORD)_wtoi(token);

                // Find and select the item with this index
                int count = (int)SendMessage(hList, LB_GETCOUNT, 0, 0);
                for (int i = 0; i < count; i++) {
                    DWORD itemIndex = (DWORD)SendMessage(hList, LB_GETITEMDATA, i, 0);
                    if (itemIndex == targetIndex) {
                        SendMessage(hList, LB_SETSEL, TRUE, i);
                        break;
                    }
                }

                token = wcstok_s(NULL, L",", &context);
            }
        }

        // Lock the list if shaper is running
        if (g_app.shaper != NULL && shaper_is_running(g_app.shaper)) {
            EnableWindow(hList, FALSE);
        } else {
            EnableWindow(hList, TRUE);
        }

        CenterWindow(hDlg, GetParent(hDlg));
        ClampWindowToWorkArea(hDlg);

        // Tooltips
        {
            static const TooltipDef tips[] = {
                // Global Bandwidth Limits
                { IDC_OPT_DL_GLOBAL,
                  L"Maximum total inbound bandwidth across all processes combined.\n"
                  L"0 = no global limit (per-process limits still apply)." },
                { IDC_OPT_UL_GLOBAL,
                  L"Maximum total outbound bandwidth across all processes combined.\n"
                  L"0 = no global limit (per-process limits still apply)." },

                // Buffer Settings
                { IDC_OPT_DL_BUFFER,
                  L"Size of the internal packet buffer for inbound traffic, in bytes.\n"
                  L"Larger values smooth out bursty traffic but increase memory use.\n"
                  L"Typical range: 65536 - 524288." },
                { IDC_OPT_UL_BUFFER,
                  L"Size of the internal packet buffer for outbound traffic, in bytes.\n"
                  L"Larger values smooth out bursty traffic but increase memory use.\n"
                  L"Typical range: 65536 - 524288." },
                { IDC_OPT_BURST_SIZE,
                  L"Maximum number of bytes a process may send in a single burst before throttling kicks in.\n"
				  L"0 = chosen automatically based on the active limit.\n"
                  L"Increase this if limited connections feel laggy;\n"
				  L"decrease to enforce stricter pacing." },

                // Process Update Interval
                { IDC_OPT_UPDATE_INTERVAL,
                  L"How often the shaper re-evaluates traffic and applies limits.\n"
                  L"In Packets mode: trigger after this many packets.\n"
                  L"In Milliseconds mode: trigger every this many ms.\n"
                  L"Lower = more responsive, but higher CPU use." },
                { IDC_OPT_UPDATE_TYPE,        // Packets radio
                  L"Trigger a traffic update after a fixed number of packets.\n"
                  L"Good for high-packet-rate connections (gaming, VoIP)." },
                { IDC_OPT_UPDATE_TYPE + 1,    // Milliseconds radio
                  L"Trigger a traffic update on a fixed time interval.\n"
                  L"Good for bulk transfers (downloads, streaming)." },
                { IDC_OPT_UPDATE_COOLDOWN,
                  L"Minimum time in milliseconds that must elapse between two consecutive "
                  L"traffic updates, regardless of the interval setting above. "
                  L"Prevents thrashing when many small packets arrive at once." },

                // Advanced
                { IDC_OPT_DATA_CAP,
                  L"Session-wide data cap in megabytes. Once total traffic (in + out)\n"
                  L"exceeds this value the shaper blocks all further traffic.\n"
                  L"0 = no cap. Resets when the shaper is stopped and restarted." },
                { IDC_OPT_TCP_LIMIT,
                  L"Maximum number of simultaneous TCP connections allowed per process. "
                  L"New connections beyond this limit are dropped.\n"
                  L"0 = no connection limit." },
                { IDC_OPT_UDP_LIMIT,
                  L"Maximum number of simultaneous UDP flows allowed per process. "
                  L"New flows beyond this limit are dropped.\n"
                  L"0 = no flow limit." },
                { IDC_OPT_LATENCY,
                  L"Artificial delay added to every packet, in milliseconds.\n"
                  L"Useful for testing application behaviour under high-latency conditions.\n"
                  L"0 = no added latency." },
                { IDC_OPT_PACKET_LOSS,
                  L"Percentage of packets to drop randomly (0.00 - 100.00).\n"
                  L"Simulates an unreliable network link.\n"
                  L"0 = no packet loss." },
                { IDC_OPT_PRIORITY,
                  L"The priority set for WinDivert itself (-30000 lowest to 30000 highest). "
                  L"Negative values deprioritise traffic; positive values prioritise it.\n"
                  L"-30000 = lowest, -15000 = low, 0 = normal,\n"
				  L"15000 = high, 30000 = highest." },

                // Network Interfaces
                { IDC_OPT_NIC_LIST,
                  L"Select one or more network adapters to monitor and shape.\n"
                  L"The list is disabled while the shaper is running." },

                // Behavior
                { IDC_OPT_MINIMIZE_TRAY,
                  L"When minimized, hide the window and show only a system tray icon. "
                  L"Double-click the tray icon to restore." },
                { IDC_OPT_SAVE_SETTINGS,
                  L"Save all current Options values to BandwidthShaper.cfg\n"
                  L"when the program exits, and reload them on next launch." },
                { IDC_OPT_SAVE_STICKY_SETTINGS,
                  L"Save the sticky process list (pinned processes and their limits)\n"
                  L"to BandwidthShaper.cfg on exit, and restore them on next launch.\n"
                  L"Does require 'Remember settings on exit' to also be checked." },
                { IDC_OPT_CONFIG_DIR,
                  L"Save the config file to this location when the program exits,\n"
                  L"and reload them using that path next launch." },
                { IDC_OPT_SNAPSHOT_DIR,
                  L"Save the snapshots from statistics to this location,\n"
                  L"instead of the same directory as the EXE file itself." },
            };

            // Store tooltip handle in dialog user data
            HWND hTip = CreateTooltips(hDlg, tips, sizeof(tips)/sizeof(tips[0]));           
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)hTip);

            // After creating the tooltip, if in dark mode
            if (g_app.dark_mode) {
                SetWindowTheme(hTip, L"DarkMode_Explorer", NULL);
                SendMessage(hTip, TTM_SETTIPBKCOLOR, (WPARAM)g_app.dark_list_bg, 0);
                SendMessage(hTip, TTM_SETTIPTEXTCOLOR, (WPARAM)g_app.dark_text, 0);
            }
        }

        return TRUE;
    }

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;

        // Handle tooltip notifications
        if (pnmh->code == TTN_GETDISPINFO) {
            LPNMTTDISPINFOW lpdi = (LPNMTTDISPINFOW)lParam;

            // Get the control that triggered the tooltip
            HWND hCtrl = (HWND)lpdi->hdr.idFrom;
            int ctrlId = GetDlgCtrlID(hCtrl);

            // Return the static text from the definition
            return TRUE;
        }
        else if (pnmh->code == TTN_SHOW) {
            // Tooltip is about to show
            return FALSE;  // Let the tooltip handle positioning
        }
        else if (pnmh->code == TTN_POP) {
            // Tooltip is closing
            return FALSE;
        }
        break;
    }

    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
    case WM_MOUSELEAVE:
    case WM_MOUSEMOVE: {
        // Forward mouse messages to tooltip
        HWND hTip = (HWND)GetWindowLongPtr(hDlg, GWLP_USERDATA);
        if (hTip && IsWindow(hTip)) {
            MSG msg = {0};
            msg.hwnd = hDlg;
            msg.message = WM_MOUSEMOVE;
            msg.wParam = wParam;
            msg.lParam = lParam;
            msg.time = GetMessageTime();
            msg.pt.x = GET_X_LPARAM(lParam);
            msg.pt.y = GET_Y_LPARAM(lParam);
            ClientToScreen(hDlg, &msg.pt);
            
            SendMessage(hTip, TTM_RELAYEVENT, 0, (LPARAM)&msg);
        }
        break;
    }

    case WM_DESTROY: {
        // Clean up tooltip when dialog closes
        HWND hTip = (HWND)GetWindowLongPtr(hDlg, GWLP_USERDATA);
        if (hTip && IsWindow(hTip)) {
            DestroyWindow(hTip);
        }
        SetWindowLongPtr(hDlg, GWLP_USERDATA, 0);
        break;
    }

    case WM_ERASEBKGND: {
        if (!g_app.dark_mode) break;
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hDlg, &rc);
        FillRect(hdc, &rc, g_app.hDarkBrush);
        return TRUE;
    }

    case WM_DRAWITEM: {
        if (!g_app.dark_mode) break;
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            DrawDarkButton(dis);
            return TRUE;
        }
        break;
    }

    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
        if (!g_app.dark_mode) break;
        return DarkMode_HandleCtlColor((HDC)wParam, (HWND)lParam, msg);
    }

    case WM_SETTINGCHANGE: {
        if (lParam && wcscmp((wchar_t*)lParam, L"ImmersiveColorSet") == 0) {
            DarkMode_ApplyToDialog(hDlg);
        }
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            // Read file path fields first so every subsequent Settings_GetPath
            // call (including inside save_sticky_settings and Settings_Save)
            // already uses the paths the user just typed/selected.
            GetDlgItemTextW(hDlg, IDC_OPT_CONFIG_DIR,
                            g_app.options.config_dir, MAX_PATH);
            GetDlgItemTextW(hDlg, IDC_OPT_SNAPSHOT_DIR,
                            g_app.options.snapshot_dir, MAX_PATH);
            // Trim trailing whitespace from both paths
            for (int _i = (int)wcslen(g_app.options.config_dir) - 1;
                 _i >= 0 && (g_app.options.config_dir[_i] == L' ' ||
                             g_app.options.config_dir[_i] == L'\t'); _i--)
                g_app.options.config_dir[_i] = L'\0';
            for (int _i = (int)wcslen(g_app.options.snapshot_dir) - 1;
                 _i >= 0 && (g_app.options.snapshot_dir[_i] == L' ' ||
                             g_app.options.snapshot_dir[_i] == L'\t'); _i--)
                g_app.options.snapshot_dir[_i] = L'\0';

            // Read values from controls
            g_app.options.dl_buffer = GetDlgItemInt(hDlg, IDC_OPT_DL_BUFFER, NULL, FALSE);
            g_app.options.ul_buffer = GetDlgItemInt(hDlg, IDC_OPT_UL_BUFFER, NULL, FALSE);
            g_app.options.burst_size = GetDlgItemInt(hDlg, IDC_OPT_BURST_SIZE, NULL, TRUE);
            g_app.options.update_interval = GetDlgItemInt(hDlg, IDC_OPT_UPDATE_INTERVAL, NULL, FALSE);
            g_app.options.update_cooldown = GetDlgItemInt(hDlg, IDC_OPT_UPDATE_COOLDOWN, NULL, FALSE);
            g_app.options.data_cap = (uint64_t)GetDlgItemInt(hDlg, IDC_OPT_DATA_CAP, NULL, FALSE) * 1000000;
            g_app.options.tcp_limit = GetDlgItemInt(hDlg, IDC_OPT_TCP_LIMIT, NULL, FALSE);
            g_app.options.udp_limit = GetDlgItemInt(hDlg, IDC_OPT_UDP_LIMIT, NULL, FALSE);
            g_app.options.latency = GetDlgItemInt(hDlg, IDC_OPT_LATENCY, NULL, FALSE);

            wchar_t buf[32];
            GetDlgItemTextW(hDlg, IDC_OPT_PACKET_LOSS, buf, 32);
            g_app.options.packet_loss = (float)_wtof(buf);

            g_app.options.priority = GetDlgItemInt(hDlg, IDC_OPT_PRIORITY, NULL, TRUE);

            g_app.options.global_dl_limit = (double)GetDlgItemInt(hDlg, IDC_OPT_DL_GLOBAL, NULL, FALSE) * 1000;
            g_app.options.global_ul_limit = (double)GetDlgItemInt(hDlg, IDC_OPT_UL_GLOBAL, NULL, FALSE) * 1000;

            g_app.options.update_by_packets = IsDlgButtonChecked(hDlg, IDC_OPT_UPDATE_TYPE) == BST_CHECKED;

            // Add or remove tray icon based on the setting
            bool old_minimize = g_app.minimize_to_tray;
            g_app.minimize_to_tray = IsDlgButtonChecked(hDlg, IDC_OPT_MINIMIZE_TRAY) == BST_CHECKED;
            if (g_app.minimize_to_tray && !old_minimize) {
                TrayAdd(GetParent(hDlg));  // Add if newly enabled
            } else if (!g_app.minimize_to_tray && old_minimize) {
                TrayRemove();  // Remove if newly disabled
            }

            // Remove StickyProcesses part from config if unset
            g_app.options.save_sticky_settings =
                IsDlgButtonChecked(hDlg, IDC_OPT_SAVE_STICKY_SETTINGS) == BST_CHECKED;
            Sticky_Save();

            g_app.options.save_settings =
                IsDlgButtonChecked(hDlg, IDC_OPT_SAVE_SETTINGS) == BST_CHECKED;

            // Settings_Save handles all cases: full save when save_settings
            // is on, redirect-only when a custom dir is set but save_settings
            // is off, and cleanup (DeleteFile) when neither applies.
            Settings_Save();

            // Get selected NICs
            HWND hList = GetDlgItem(hDlg, IDC_OPT_NIC_LIST);
            int selCount = (int)SendMessage(hList, LB_GETSELCOUNT, 0, 0);
            if (selCount > 0) {
                int* selItems = (int*)malloc(selCount * sizeof(int));
                SendMessage(hList, LB_GETSELITEMS, selCount, (LPARAM)selItems);

                g_app.options.selected_nics[0] = L'\0';
                for (int i = 0; i < selCount; i++) {
                    DWORD nicIndex = (DWORD)SendMessage(hList, LB_GETITEMDATA, selItems[i], 0);
                    wchar_t buf[16];
                    swprintf(buf, 16, L"%u,", nicIndex);
                    wcscat(g_app.options.selected_nics, buf);
                }
                // Remove trailing comma
                size_t len = wcslen(g_app.options.selected_nics);
                if (len > 0) g_app.options.selected_nics[len-1] = L'\0';

                free(selItems);
            }

            // Apply changes to running shaper if it's running
            if (g_app.shaper && shaper_is_running(g_app.shaper)) {
                if (!ReloadShaperConfig()) {
                    char err[512];
                    snprintf(err, 512, "Failed to reload config: %s",
                            shaper_get_last_error(g_app.shaper));
                    wchar_t werr[512];
                    MultiByteToWideChar(CP_UTF8, 0, err, -1, werr, 512);
                    MSGBOX(hDlg, werr, L"Error", MB_OK | MB_ICONERROR);
                }
            }

            EndDialog(hDlg, IDOK);
            return TRUE;
        }

        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;

        case IDC_OPT_CONFIG_DIR_BROWSE:
        case IDC_OPT_SNAPSHOT_DIR_BROWSE: {
            // Pop up a folder-picker dialog
            bool is_config = (LOWORD(wParam) == IDC_OPT_CONFIG_DIR_BROWSE);
            int edit_id = is_config ? IDC_OPT_CONFIG_DIR : IDC_OPT_SNAPSHOT_DIR;

            // Read current text as starting folder
            wchar_t start[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, edit_id, start, MAX_PATH);

            // Use SHBrowseForFolderW (available on all supported Windows versions)
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hDlg;
            bi.lpszTitle = is_config
                           ? L"Select folder for the config file (BandwidthShaper.cfg):"
                           : L"Select folder for CSV snapshot exports:";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            // Pre-select the folder currently shown in the edit box
            if (start[0] != L'\0') {
                bi.lParam = (LPARAM)start;
                bi.lpfn = NULL;  // no callback needed for pre-selection via pidl below
            }

            // Convert the starting path to a PIDL so SHBrowseForFolder can
            // pre-select it (only if the path actually exists right now)
            LPITEMIDLIST pidl_start = NULL;
            if (start[0] != L'\0') {
                SFGAOF sfgao = 0;
                SHParseDisplayName(start, NULL, &pidl_start, 0, &sfgao);
                if (pidl_start) bi.pidlRoot = NULL;  // use absolute pidl via pszDisplayName trick
                // Actually pass via lParam + callback for pre-selection
                // Simpler: just set pszDisplayName; Windows will try to expand it
                if (pidl_start) { CoTaskMemFree(pidl_start); pidl_start = NULL; }
            }

            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                wchar_t chosen[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, chosen)) {
                    SetDlgItemTextW(hDlg, edit_id, chosen);
                }
                CoTaskMemFree(pidl);
            }
            return TRUE;
        }
        }
        break;
    }

    return FALSE;
}

// ---------------------------------------------------------------------------
// Stats dialog
// ---------------------------------------------------------------------------
INT_PTR CALLBACK StatsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    StatsDialogContext *ctx = (StatsDialogContext*)GetWindowLongPtr(hDlg, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG:
        // Allocate and initialize context
        ctx = calloc(1, sizeof(StatsDialogContext));
        if (ctx) {
            ctx->initialized = FALSE;
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)ctx);
        }

        SetTimer(hDlg, 1, 500, NULL);

        // Subclass the chart controls
        HWND hDlChart = GetDlgItem(hDlg, IDC_STATS_DL_CHART);
        HWND hUlChart = GetDlgItem(hDlg, IDC_STATS_UL_CHART);
        SetWindowSubclass(hDlChart, ChartWndProc, 0, 0); // 0 = download
        SetWindowSubclass(hUlChart, ChartWndProc, 1, 0); // 1 = upload

        // Configure the per-process traffic ListView (already created in resource)
        HWND hProcList = GetDlgItem(hDlg, IDC_STATS_PROC_LIST);
        if (hProcList) {
            // Virtual listview (for many entries)
            // SetWindowLong(hProcList, GWL_STYLE, 
            //               GetWindowLong(hProcList, GWL_STYLE) | LVS_OWNERDATA);
            // Set extended styles
            ListView_SetExtendedListViewStyle(hProcList,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

            // Set columns (in case they're not defined in resource)
            LVCOLUMNW lvc = {0};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

            // Clear existing columns first
            while (ListView_DeleteColumn(hProcList, 0)) {}

            struct { const wchar_t *text; int width; } pcols[] = {
                {L"Process", S(220)},
                {L"Data In",  S(110)},
                {L"Data Out", S(110)},
            };
            for (int i = 0; i < 3; i++) {
                lvc.iSubItem = i;
                lvc.pszText  = (LPWSTR)pcols[i].text;
                lvc.cx       = pcols[i].width;
                ListView_InsertColumn(hProcList, i, &lvc);
            }

            // Apply dark mode to header
            if (g_app.dark_mode) {
                ApplyDarkModeToListViewHeader(hProcList);
            }
        }

        // Create "Save Statistics" button (positioned in WM_SIZE; initially disabled)
        HWND hSave = CreateWindowW(L"BUTTON", L"Save Statistics",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            0, 0, 0, 0, hDlg, (HMENU)IDC_STATS_SAVE, g_hInst, NULL);

        // Use same font as dialog
        HFONT hDlgFont = (HFONT)SendMessage(hDlg, WM_GETFONT, 0, 0);
        if (hDlgFont) {
            if (hSave) SendMessage(hSave, WM_SETFONT, (WPARAM)hDlgFont, FALSE);
        }

        // Initial layout
        PostMessage(hDlg, WM_SIZE, 0, 0);

		HWND hOldEdit = GetDlgItem(hDlg, IDC_STATS_TEXT);
		RECT rcEdit = {0};
		GetWindowRect(hOldEdit, &rcEdit);
		MapWindowPoints(HWND_DESKTOP, hDlg, (LPPOINT)&rcEdit, 2);
		DestroyWindow(hOldEdit);

		// Create RichEdit
		HWND hRichEdit = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, NULL,
			WS_CHILD | WS_VISIBLE | WS_VSCROLL |
			ES_MULTILINE | ES_AUTOVSCROLL,
			rcEdit.left, rcEdit.top,
			rcEdit.right - rcEdit.left, rcEdit.bottom - rcEdit.top,
			hDlg, (HMENU)IDC_STATS_TEXT, g_hInst, NULL);

        // Match the font of the old edit control
        HFONT hFont = (HFONT)SendMessage(hDlg, WM_GETFONT, 0, 0);
        if (hFont) SendMessage(hRichEdit, WM_SETFONT, (WPARAM)hFont, FALSE);

        // Apply dark mode if enabled
        if (g_app.dark_mode) {
            ApplyDarkModeToDialog(hDlg);

            // Edit box (stats text) needs CFD theme for the caret colour
            //HWND hStatsText = GetDlgItem(hDlg, IDC_STATS_TEXT);
            //if (hStatsText) SetWindowTheme(hStatsText, L"DarkMode_CFD", NULL);

            SetWindowTheme(hRichEdit, L"DarkMode_Explorer", NULL);
            SendMessage(hRichEdit, EM_SETBKGNDCOLOR, 0, (LPARAM)g_app.dark_list_bg);

            CHARFORMAT2W cf = { sizeof(cf) };
            cf.dwMask = CFM_COLOR | CFM_BACKCOLOR;
            cf.crTextColor = g_app.dark_text;
            cf.crBackColor = g_app.dark_list_bg;
            cf.dwEffects = 0;
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
            InvalidateRect(hRichEdit, NULL, TRUE);
            UpdateWindow(hRichEdit);

            // Per-process ListView - colours set by ApplyDarkModeToDialog,
            // but set explicitly as well to be safe
            if (hProcList) {
                ListView_SetTextColor(hProcList, g_app.dark_text);
                ListView_SetTextBkColor(hProcList, g_app.dark_list_bg);
                ListView_SetBkColor(hProcList, g_app.dark_list_bg);
                HWND hHdr = ListView_GetHeader(hProcList);
                if (hHdr) SetWindowTheme(hHdr, L"DarkMode_ItemsView", NULL);
            }
        } else {
            // Restore light mode colors
            SetWindowTheme(hRichEdit, L"Explorer", NULL);
            SendMessage(hRichEdit, EM_SETBKGNDCOLOR, 0, (LPARAM)GetSysColor(COLOR_WINDOW));

            CHARFORMAT2W cf = { sizeof(cf) };
            cf.dwMask = CFM_COLOR | CFM_BACKCOLOR;
            cf.crTextColor = GetSysColor(COLOR_WINDOWTEXT);  // Default black
            cf.crBackColor = GetSysColor(COLOR_WINDOW);      // Default white
            cf.dwEffects = 0;
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
            SendMessage(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
            InvalidateRect(hRichEdit, NULL, TRUE);
            UpdateWindow(hRichEdit);
        }

        return TRUE;

	case WM_SIZE: {
		RECT rc;
		GetClientRect(hDlg, &rc);
		int w = rc.right - rc.left;
		int h = rc.bottom - rc.top;
		int margin = S(8);

		// Fixed heights for components
		int chartHeight = S(80);            // Height for each chart
		int labelHeight = S(18);            // Height for "Download History" labels
		int listHeaderHeight = S(20);       // Height for "Per-Process Traffic" label
		int statsLabelHeight = S(18);       // Height for "Statistics:" label
		int buttonHeight = S(23);           // Height for buttons
		int bottomMargin = S(10);           // Margin at bottom

		// Calculate positions
		int currentY = margin;

		// Download chart section
		HWND hDlLabel = GetDlgItem(hDlg, IDC_STATIC_DL_LABEL);
		HWND hDlChart = GetDlgItem(hDlg, IDC_STATS_DL_CHART);

		if (hDlLabel) {
			SetWindowPos(hDlLabel, NULL,
				margin, currentY,
				100, labelHeight,
				SWP_NOZORDER);
		}
		currentY += labelHeight;

		if (hDlChart) {
			SetWindowPos(hDlChart, NULL,
				margin, currentY,
				w - margin * 2, chartHeight,
				SWP_NOZORDER);
		}
		currentY += chartHeight + margin;

		// Upload chart section
		HWND hUlLabel = GetDlgItem(hDlg, IDC_STATIC_UL_LABEL);
		HWND hUlChart = GetDlgItem(hDlg, IDC_STATS_UL_CHART);

		if (hUlLabel) {
			SetWindowPos(hUlLabel, NULL,
				margin, currentY,
				100, labelHeight,
				SWP_NOZORDER);
		}
		currentY += labelHeight;

		if (hUlChart) {
			SetWindowPos(hUlChart, NULL,
				margin, currentY,
				w - margin * 2, chartHeight,
				SWP_NOZORDER);
		}
		currentY += chartHeight + margin;

		// Process list section (with header)
		HWND hProcListLabel = GetDlgItem(hDlg, IDC_STATIC_PROC_LIST_LABEL);
		HWND hProcList = GetDlgItem(hDlg, IDC_STATS_PROC_LIST);

		if (hProcListLabel) {
			SetWindowPos(hProcListLabel, NULL,
				margin, currentY,
				120, listHeaderHeight,
				SWP_NOZORDER);
		}
		currentY += listHeaderHeight;

		if (hProcList) {
			// Calculate remaining height for process list
			int remainingHeight = h - currentY - statsLabelHeight - 80 - buttonHeight - bottomMargin;
			int listHeight = max(80, remainingHeight - 240);  // Minimum 80 pixels

			SetWindowPos(hProcList, NULL,
				margin, currentY,
				w - margin * 2, listHeight,
				SWP_NOZORDER);

			currentY += listHeight + margin;
		}

		// Statistics text section
		HWND hStatsLabel = GetDlgItem(hDlg, IDC_STATIC_STATS_LABEL);
		HWND hStatsText = GetDlgItem(hDlg, IDC_STATS_TEXT);

		if (hStatsLabel) {
			SetWindowPos(hStatsLabel, NULL,
				margin, currentY,
				80, statsLabelHeight,
				SWP_NOZORDER);
		}
		currentY += statsLabelHeight;

		if (hStatsText) {
			int statsHeight = 300;  // Fixed height for stats text
			SetWindowPos(hStatsText, NULL,
				margin, currentY,
				w - margin * 2, statsHeight,
				SWP_NOZORDER);

			currentY += statsHeight + margin;
		}

		// Buttons at the bottom
		HWND hSave = GetDlgItem(hDlg, IDC_STATS_SAVE);
		HWND hReset = GetDlgItem(hDlg, IDC_STATS_RESET);
		HWND hClose = GetDlgItem(hDlg, IDCLOSE);

		int btn_width = S(110);
		int btn_spacing = S(10);
		int btn_y = h - buttonHeight - bottomMargin;

		if (hSave) {
			SetWindowPos(hSave, NULL,
				margin, btn_y,
				btn_width, buttonHeight,
				SWP_NOZORDER);
		}

		if (hReset) {
			SetWindowPos(hReset, NULL,
				margin + btn_width + btn_spacing, btn_y,
				btn_width, buttonHeight,
				SWP_NOZORDER);
		}

		if (hClose) {
			SetWindowPos(hClose, NULL,
				w - btn_width - margin, btn_y,
				btn_width, buttonHeight,
				SWP_NOZORDER);
		}

		return 0;
	}

    case WM_TIMER: {
        if (!ctx) return TRUE;

        if (g_app.shaper) {
			// Take atomic snapshot
			TrafficSnapshot current = {0};
			uint64_t total_dl_bytes = 0, total_ul_bytes = 0;

			if (shaper_snapshot_traffic(g_app.shaper, &current)) {
				uint64_t now = current.timestamp;

                // Update proc_stats under lock
                EnterCriticalSection(&g_app.process_lock);

				// Update proc_stats with current snapshot data
				// Clear existing proc_stats
				memset(g_app.proc_stats, 0, sizeof(g_app.proc_stats));
				g_app.proc_stats_count = 0;

				// Build a temporary map of PID -> entry for quick lookup
				typedef struct {
					DWORD pid;
					uint64_t dl_bytes;
					uint64_t ul_bytes;
				} TempEntry;

                TempEntry *temp_entries = malloc(sizeof(TempEntry) * MAX_PROCESSES * MAX_PID_FOR_PROCESS);
                if (!temp_entries) return TRUE;
				int temp_count = current.count;

				// Copy snapshot entries to temp array
				for (int i = 0; i < current.count && i < MAX_PROCESSES * MAX_PID_FOR_PROCESS; i++) {
					temp_entries[i].pid = current.entries[i].pid;
					temp_entries[i].dl_bytes = current.entries[i].dl_bytes;
					temp_entries[i].ul_bytes = current.entries[i].ul_bytes;
				}

				// Now aggregate by process name
				for (int i = 0; i < g_app.process_count; i++) {
					ProcessEntry* proc = &g_app.processes[i];
					uint64_t proc_dl = 0, proc_ul = 0;

					// Sum traffic for all PIDs of this process
					for (int p = 0; p < proc->pid_count; p++) {
						DWORD pid = proc->pids[p];
						
						// Find this PID in the temp entries
						for (int t = 0; t < temp_count; t++) {
							if (temp_entries[t].pid == pid) {
								proc_dl += temp_entries[t].dl_bytes;
								proc_ul += temp_entries[t].ul_bytes;
								break;
							}
						}
					}

					// If process has any traffic, add to proc_stats
					if (proc_dl > 0 || proc_ul > 0) {
						int idx = g_app.proc_stats_count++;
						wcsncpy(g_app.proc_stats[idx].name, proc->name, MAX_PATH);

						// Try to get friendly description from version info
						g_app.proc_stats[idx].description[0] = L'\0';
						if (proc->path[0]) {
							DWORD handle = 0;
							DWORD size = GetFileVersionInfoSizeW(proc->path, &handle);
							if (size > 0) {
								void* ver = malloc(size);
								if (ver) {
									if (GetFileVersionInfoW(proc->path, 0, size, ver)) {
										wchar_t* desc = NULL;
										UINT descLen = 0;
										if (VerQueryValueW(ver, L"\\StringFileInfo\\040904B0\\FileDescription",
														  (void**)&desc, &descLen) && desc && descLen > 0) {
											wcsncpy(g_app.proc_stats[idx].description, desc, 255);
										}
									}
									free(ver);
								}
							}
						}

						g_app.proc_stats[idx].dl_bytes = proc_dl;
						g_app.proc_stats[idx].ul_bytes = proc_ul;

						// Store PIDs for potential future use
						g_app.proc_stats[idx].pid_count = proc->pid_count;
						for (int p = 0; p < proc->pid_count && p < MAX_PID_FOR_PROCESS; p++) {
							g_app.proc_stats[idx].pids[p] = proc->pids[p];
							g_app.proc_stats[idx].dl_bytes_snap[p] = 0;  // Not needed for display
							g_app.proc_stats[idx].ul_bytes_snap[p] = 0;
						}
					}
				}

                LeaveCriticalSection(&g_app.process_lock);

                if (ctx->initialized && ctx->has_snapshot) {
                    uint64_t elapsed = now - ctx->lastTime;
                    if (elapsed > 0) {
                        // Sum all traffic for rate calculation
                        uint64_t current_dl = 0, current_ul = 0;
                        uint64_t last_dl = 0, last_ul = 0;

                        for (int i = 0; i < current.count; i++) {
                            current_dl += current.entries[i].dl_bytes;
                            current_ul += current.entries[i].ul_bytes;
                        }

                        for (int i = 0; i < ctx->last_snapshot.count; i++) {
                            last_dl += ctx->last_snapshot.entries[i].dl_bytes;
                            last_ul += ctx->last_snapshot.entries[i].ul_bytes;
                        }

                        double dlBps = (current_dl >= last_dl) 
                                     ? (double)(current_dl - last_dl) * 1000.0 / elapsed : 0;
                        double ulBps = (current_ul >= last_ul) 
                                     ? (double)(current_ul - last_ul) * 1000.0 / elapsed : 0;

                        g_app.dl_history[g_app.history_head] = dlBps;
                        g_app.ul_history[g_app.history_head] = ulBps;
                        g_app.history_head = (g_app.history_head + 1) % SPARKLINE_SAMPLES;

                        total_dl_bytes = current_dl;  // Store for later use
                        total_ul_bytes = current_ul;
                    }
                } else {
                    ctx->initialized = TRUE;
                    // For first snapshot, just store the totals
                    for (int i = 0; i < current.count; i++) {
                        total_dl_bytes += current.entries[i].dl_bytes;
                        total_ul_bytes += current.entries[i].ul_bytes;
                    }
                }

                // Save snapshot for next comparison
                shaper_free_traffic_snapshot(&ctx->last_snapshot);  // Free the previous snapshot before overwriting
                ctx->last_snapshot = current;  // Take ownership of current
                ctx->lastTime = now;
                ctx->has_snapshot = true;

                // Free heap allocation
                free(temp_entries);
            }

            // Also get overall stats for other counters
            ShaperStats stats;
            shaper_get_stats(g_app.shaper, &stats);

            // Build quota exhaustion message
            wchar_t quota_msg[128] = L"";
            bool quota_exhausted = IsAnyQuotaExhausted();

            if (quota_exhausted) {
                // Build list of processes with exhausted quotas
                wchar_t exhausted_list[512] = L"\r\n*** QUOTA EXHAUSTED PROCESSES ***\r\n";
                for (int i = 0; i < g_app.process_count; i++) {
                    ProcessEntry* proc = &g_app.processes[i];
                    if ((proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in) ||
                        (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out)) {
                        wchar_t line[128];
                        swprintf(line, 128, L"  %s", proc->name);
                        if (proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in)
                            wcscat(line, L" (IN)");
                        if (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out)
                            wcscat(line, L" (OUT)");
                        wcscat(line, L"\r\n");
                        wcsncat(exhausted_list, line, 511 - wcslen(exhausted_list));
                    }
                }
                wcsncpy(quota_msg, exhausted_list, 127);
            }

            wchar_t buf[2048];
            swprintf(buf, 2048,
                L"Packets processed:  %I64u\r\n"
                L"Dropped (rate):     %I64u\r\n"
                L"Dropped (loss):     %I64u\r\n"
                L"Delayed:            %I64u\r\n"
                L"Invalid:            %I64u\r\n"
                L"\r\n"
                L"Total Bytes:        %I64u (%.2f MB)\r\n"
                L"Download Bytes:     %I64u (%.2f MB)\r\n"
                L"Upload Bytes:       %I64u (%.2f MB)\r\n"
                L"\r\n"
                L"Current Rate:       %.2f / %.2f KB/s\r\n"
                L"%s%s%s",
                (unsigned long long)stats.packets_processed,
                (unsigned long long)stats.packets_dropped_rate_limit,
                (unsigned long long)stats.packets_dropped_loss,
                (unsigned long long)stats.packets_delayed,
                (unsigned long long)stats.invalid_packets,
                (unsigned long long)stats.bytes_processed,
                stats.bytes_processed / (1024.0 * 1024.0),
                (unsigned long long)total_dl_bytes,
                total_dl_bytes / (1024.0 * 1024.0),
                (unsigned long long)total_ul_bytes,
                total_ul_bytes / (1024.0 * 1024.0),
                g_app.dl_history[(g_app.history_head ? g_app.history_head-1 : SPARKLINE_SAMPLES-1)] / 1024.0,
                g_app.ul_history[(g_app.history_head ? g_app.history_head-1 : SPARKLINE_SAMPLES-1)] / 1024.0,
                stats.cap_reached ? L"\r\n*** DATA CAP REACHED ***" : L"",
                (stats.cap_reached && quota_exhausted) ? L"\r\n" : L"",
                quota_exhausted ? quota_msg : L"");

            // Instead of calling SetDlgItemText every time,
            // only update if the text actually changed
            static wchar_t currentText[2048] = {0};
            GetWindowTextW(GetDlgItem(hDlg, IDC_STATS_TEXT), currentText, 2048);

            if (wcscmp(buf, currentText) != 0) {
                SetWindowTextW(GetDlgItem(hDlg, IDC_STATS_TEXT), buf);
            }

			// For charts, only invalidate if data changed
			static int lastHistoryHead = -1;
			if (lastHistoryHead != g_app.history_head) {
				lastHistoryHead = g_app.history_head;
				InvalidateRect(GetDlgItem(hDlg, IDC_STATS_DL_CHART), NULL, FALSE);
				InvalidateRect(GetDlgItem(hDlg, IDC_STATS_UL_CHART), NULL, FALSE);
			}

        } else if (g_app.has_last_stats) {
            //SetDlgItemTextW(hDlg, IDC_STATS_TEXT, g_app.last_stats_text);
            SetWindowTextW(GetDlgItem(hDlg, IDC_STATS_TEXT), g_app.last_stats_text);
        }

        // Enable Save button only when shaper is stopped (data is final)
        {
            HWND hSave = GetDlgItem(hDlg, IDC_STATS_SAVE);
            if (hSave) {
                bool can_save = (!g_app.shaper || !shaper_is_running(g_app.shaper))
                                && g_app.proc_stats_count > 0;
                EnableWindow(hSave, can_save ? TRUE : FALSE);
            }
        }

        // Refresh per-process traffic list (only processes with non-zero traffic)
        HWND hProcList = GetDlgItem(hDlg, IDC_STATS_PROC_LIST);
        if (hProcList) {            
            SortEntry sorted[MAX_PROCESSES];
            int scount = 0;
            for (int i = 0; i < g_app.proc_stats_count; i++) {
                uint64_t t = g_app.proc_stats[i].dl_bytes + g_app.proc_stats[i].ul_bytes;
                if (t == 0) continue;
                sorted[scount].idx   = i;
                sorted[scount].total = t;
                scount++;
            }
            // Bubble sort descending
            for (int a = 0; a < scount - 1; a++)
                for (int b = a + 1; b < scount; b++)
                    if (sorted[b].total > sorted[a].total) {
                        SortEntry tmp = sorted[a]; sorted[a] = sorted[b]; sorted[b] = tmp;
                    }

            // Check if virtual or not
            LONG_PTR style = GetWindowLongPtr(hProcList, GWL_STYLE);
            bool isVirtual = (style & LVS_OWNERDATA) != 0;

            if (isVirtual) {
                ListView_SetItemCountEx(hProcList, scount, LVSICF_NOSCROLL);
            } else {
                // Delete all and re-add items
                ListView_DeleteAllItems(hProcList);
                for (int r = 0; r < scount; r++) {
                    LVITEMW lvi = {0};
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = r;
                    lvi.iSubItem = 0;
                    lvi.pszText = L"";
                    ListView_InsertItem(hProcList, &lvi);

                    // Update content
                    int si = sorted[r].idx;
                    wchar_t name_col[256];
                    if (g_app.proc_stats[si].description[0]) {
                        swprintf(name_col, 256, L"%s (%s)",
                                 g_app.proc_stats[si].name,
                                 g_app.proc_stats[si].description);
                    } else {
                        wcsncpy(name_col, g_app.proc_stats[si].name, 255);
                    }
                    ListView_SetItemText(hProcList, r, 0, name_col);

                    wchar_t mb_buf[32];
                    double dl_mb = g_app.proc_stats[si].dl_bytes / (1024.0 * 1024.0);
                    double ul_mb = g_app.proc_stats[si].ul_bytes / (1024.0 * 1024.0);

                    // Format with locale-style thousands grouping by using manual formatting
                    if (dl_mb >= 1000.0)
                        swprintf(mb_buf, 32, L"%.1f MB", dl_mb);
                    else
                        swprintf(mb_buf, 32, L"%.1f MB", dl_mb);
                    ListView_SetItemText(hProcList, r, 1, mb_buf);

                    if (ul_mb >= 1000.0)
                        swprintf(mb_buf, 32, L"%.1f MB", ul_mb);
                    else
                        swprintf(mb_buf, 32, L"%.1f MB", ul_mb);
                    ListView_SetItemText(hProcList, r, 2, mb_buf);
                }
            }
        }

        return true;
    }

    // Eliminate grey flash: fill background before any child paints
    case WM_ERASEBKGND: {
        if (!g_app.dark_mode) break;
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hDlg, &rc);
        FillRect(hdc, &rc, g_app.hDarkBrush);
        return 1;  // claim erased
    }

    // Colour hooks for child controls
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
        if (!g_app.dark_mode) break;
        return DarkMode_HandleCtlColor((HDC)wParam, (HWND)lParam, msg);
    }

    case WM_SETTINGCHANGE: {
        if (lParam && wcscmp((wchar_t*)lParam, L"ImmersiveColorSet") == 0) {
            BOOL nowDark = DarkMode_SystemIsDark();
            if (nowDark != g_app.dark_mode) {
                g_app.dark_mode = nowDark;

                ApplyDarkModeToAllControls(hDlg, g_app.dark_mode);

                // Re-apply theme to RichEdit
                HWND hRichEdit = GetDlgItem(hDlg, IDC_STATS_TEXT);
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

                // Also update ListView
                HWND hProcList = GetDlgItem(hDlg, IDC_STATS_PROC_LIST);
                if (hProcList) {
                    ApplyDarkModeToListViewHeader(hProcList);
                    InvalidateRect(hProcList, NULL, TRUE);
                    RedrawWindow(hProcList, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);
                }

                // Other elements
                DarkMode_ApplyToDialog(hDlg);
            }
        }
        break;
    }

    // Owner-draw buttons (Save Statistics, Reset Statistics, Close)
    case WM_DRAWITEM: {
        if (!g_app.dark_mode) break;
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            DrawDarkButton(dis);
            return TRUE;
        }
        break;
    }

    // Background fill for the dialog client area
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hDlg, &ps);
        if (g_app.dark_mode) {
            RECT rc;
            GetClientRect(hDlg, &rc);
            FillRect(hdc, &rc, g_app.hDarkBrush);
        }
        EndPaint(hDlg, &ps);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_STATS_SAVE:
            SaveStatisticsToCSV(hDlg);
            return true;

        case IDC_STATS_RESET:
            memset(g_app.dl_history, 0, sizeof(g_app.dl_history));
            memset(g_app.ul_history, 0, sizeof(g_app.ul_history));
            g_app.history_head = 0;

            // Reset per-process stats table
            memset(g_app.proc_stats, 0, sizeof(g_app.proc_stats));
            g_app.proc_stats_count = 0;

            if (ctx) ctx->initialized = FALSE;

            // Clear the proc list display
            {
                HWND hProcList = GetDlgItem(hDlg, IDC_STATS_PROC_LIST);
                if (hProcList) ListView_DeleteAllItems(hProcList);
            }

            InvalidateRect(hDlg, NULL, FALSE);
            return true;

        case IDCLOSE:
        case IDCANCEL:
            DestroyWindow(hDlg);
            return true;
        }
        break;

    case WM_NCDESTROY:
        KillTimer(hDlg, 1);
        hDlChart = GetDlgItem(hDlg, IDC_STATS_DL_CHART);
        hUlChart = GetDlgItem(hDlg, IDC_STATS_UL_CHART);
        if (hDlChart) RemoveWindowSubclass(hDlChart, ChartWndProc, 0);
        if (hUlChart) RemoveWindowSubclass(hUlChart, ChartWndProc, 1);

        if (ctx) {
            shaper_free_traffic_snapshot(&ctx->last_snapshot);
            free(ctx);
            SetWindowLongPtr(hDlg, GWLP_USERDATA, 0);
        }
        g_app.hStatsWnd = NULL;
        break;

    case WM_CLOSE:
        // Ensure cleanup even if closed via X button
        HWND hTip = (HWND)GetWindowLongPtr(hDlg, GWLP_USERDATA);
        if (hTip && IsWindow(hTip)) {
            DestroyWindow(hTip);
        }
        SetWindowLongPtr(hDlg, GWLP_USERDATA, 0);
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }

    return false;
}

// ---------------------------------------------------------------------------
// "Specify process" input dialog proc
// ---------------------------------------------------------------------------
INT_PTR CALLBACK SpecifyProcDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        SetWindowLongPtr(hDlg, GWLP_USERDATA, lParam);  // caller's wchar_t buffer
        SetFocus(GetDlgItem(hDlg, IDC_SPECIFY_NAME));
        CenterWindow(hDlg, GetParent(hDlg));

        // Apply dark mode to this dialog if enabled
        if (g_app.dark_mode) {
            // Set dialog background color
            SetClassLongPtr(hDlg, GCLP_HBRBACKGROUND, (LONG_PTR)g_app.hDarkBrush);
            
            // Force buttons to be owner-draw
            HWND hBtnOK = GetDlgItem(hDlg, IDOK);
            HWND hBtnCancel = GetDlgItem(hDlg, IDCANCEL);
            
            if (hBtnOK) {
                DWORD style = GetWindowLong(hBtnOK, GWL_STYLE);
                SetWindowLong(hBtnOK, GWL_STYLE, (style & ~BS_TYPEMASK) | BS_OWNERDRAW);
                SetWindowTheme(hBtnOK, L"", L"");
            }
            
            if (hBtnCancel) {
                DWORD style = GetWindowLong(hBtnCancel, GWL_STYLE);
                SetWindowLong(hBtnCancel, GWL_STYLE, (style & ~BS_TYPEMASK) | BS_OWNERDRAW);
                SetWindowTheme(hBtnCancel, L"", L"");
            }
            
            // Apply to all controls
            ApplyDarkModeToDialog(hDlg);
        }
        return FALSE; // focus set manually

    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
        if (!g_app.dark_mode) break;
        return DarkMode_HandleCtlColor((HDC)wParam, (HWND)lParam, msg);
    }

    case WM_ERASEBKGND:
        if (g_app.dark_mode) {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hDlg, &rc);
            FillRect(hdc, &rc, g_app.hDarkBrush);
            return TRUE;
        }
        break;

    case WM_DRAWITEM: {
        if (!g_app.dark_mode) break;
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;

        if (dis->CtlID == IDC_TOOLBAR) {
            // Fill with dark toolbar color
            FillRect(dis->hDC, &dis->rcItem, g_app.hDarkToolbarBrush);

            // Draw bottom border line
            HPEN hPen = CreatePen(PS_SOLID, 1, DARK_BTN_BORDER);
            HPEN hOld = SelectObject(dis->hDC, hPen);
            MoveToEx(dis->hDC, dis->rcItem.left, dis->rcItem.bottom - 1, NULL);
            LineTo(dis->hDC, dis->rcItem.right, dis->rcItem.bottom - 1);
            SelectObject(dis->hDC, hOld);
            DeleteObject(hPen);
            return TRUE;
        }

        if (dis->CtlType == ODT_BUTTON) {
            // Use your existing DrawDarkButton function
            DrawDarkButton(dis);
            return TRUE;
        }
        break;
    }

    case WM_SETTINGCHANGE: {
        if (lParam && wcscmp((wchar_t*)lParam, L"ImmersiveColorSet") == 0) {
            DarkMode_ApplyToDialog(hDlg);
        }
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            wchar_t *buf = (wchar_t *)GetWindowLongPtr(hDlg, GWLP_USERDATA);
            GetDlgItemTextW(hDlg, IDC_SPECIFY_NAME, buf, MAX_PATH);
            // Trim whitespace
            wchar_t *p = buf;
            while (*p == L' ' || *p == L'\t') p++;
            if (p != buf) memmove(buf, p, (wcslen(p) + 1) * sizeof(wchar_t));
            p = buf + wcslen(buf) - 1;
            while (p >= buf && (*p == L' ' || *p == L'\t')) *p-- = L'\0';
            if (buf[0] == L'\0') {
                MSGBOX(hDlg, L"Please enter a process name.", L"Specify Process",
                            MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Schedule helpers
// ---------------------------------------------------------------------------
// Enable/disable the time edit fields based on checkbox state.
static void SchedDlg_EnableTimeFields(HWND hDlg, bool enable) {
    const int ids[] = { SDLG_EDIT_SH, SDLG_EDIT_SM, SDLG_EDIT_EH, SDLG_EDIT_EM,
                        SDLG_LBL_COLON1, SDLG_LBL_DASH, SDLG_LBL_COLON2, SDLG_LBL_24H };
    for (int i = 0; i < 8; i++)
        EnableWindow(GetDlgItem(hDlg, ids[i]), enable ? TRUE : FALSE);
}

// Enable/disable the day-of-week buttons based on checkbox state.
static void SchedDlg_EnableDayButtons(HWND hDlg, bool enable) {
    for (int id = SDLG_DAY_MON; id <= SDLG_DAY_SUN; id++)
        EnableWindow(GetDlgItem(hDlg, id), enable ? TRUE : FALSE);
}

// Update the description label based on current Schedule state
static void SchedDlg_UpdateDesc(HWND hDlg, const Schedule *s) {
    HWND hDesc = GetDlgItem(hDlg, SDLG_DESC_LABEL);
    if (!hDesc) return;
    if (schedule_is_empty(s)) {
        SetWindowTextW(hDesc, L"(no schedule - rules always active)");
    } else {
        wchar_t buf[128];
        schedule_describe(s, buf, 128);
        SetWindowTextW(hDesc, buf);
    }
}

// Pull HH/MM from edit boxes into s->start/end_min
static void SchedDlg_ReadTime(HWND hDlg, Schedule *s) {
    wchar_t buf[8];
    GetDlgItemTextW(hDlg, SDLG_EDIT_SH, buf, 4); int sh = _wtoi(buf);
    GetDlgItemTextW(hDlg, SDLG_EDIT_SM, buf, 4); int sm = _wtoi(buf);
    GetDlgItemTextW(hDlg, SDLG_EDIT_EH, buf, 4); int eh = _wtoi(buf);
    GetDlgItemTextW(hDlg, SDLG_EDIT_EM, buf, 4); int em = _wtoi(buf);
    if (sh > 23) sh = 23;  if (sm > 59) sm = 59;
    if (eh > 23) eh = 23;  if (em > 59) em = 59;
    s->start_min = sh * 60 + sm;
    s->end_min   = eh * 60 + em;
}

// ---------------------------------------------------------------------------
// Schedule dialog
// ---------------------------------------------------------------------------
INT_PTR CALLBACK ScheduleDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    ScheduleDlgCtx *ctx =
        (ScheduleDlgCtx *)GetWindowLongPtr(hDlg, GWLP_USERDATA);

    switch (msg) {

    case WM_INITDIALOG: {
        ctx = (ScheduleDlgCtx *)lParam;
        SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)ctx);
        ctx->initializing = true;  // suppress EN_CHANGE until controls are fully populated

        // Title: process name
        ProcessEntry *proc = &g_app.processes[ctx->proc_idx];
        wchar_t title[MAX_PATH + 20];
        swprintf(title, MAX_PATH + 20, L"Schedule - %s", proc->name);
        SetWindowTextW(hDlg, title);

        // Resize the dialog to the correct pixel size
        // Base dimensions at 96 DPI (logical pixels).
        // Using S() scales them for the current monitor DPI automatically.
        const int DLG_W = S(360);
        const int DLG_H = S(220);

        // Compute centred position on the parent window
        RECT rcParent;
        // Note: 'hParent' in ShowScheduleDialog is unavailable here, so we
        // use the dialog's own owner (GetWindow(hDlg, GW_OWNER))
        GetWindowRect((GetWindow(hDlg, GW_OWNER)) ? (GetWindow(hDlg, GW_OWNER)) : GetDesktopWindow(), &rcParent);
        HWND hOwner = GetWindow(hDlg, GW_OWNER);
        if (hOwner && IsWindow(hOwner))
            GetWindowRect(hOwner, &rcParent);
        else
            SystemParametersInfo(SPI_GETWORKAREA, 0, &rcParent, 0);

        int cx = rcParent.left + (rcParent.right  - rcParent.left - DLG_W) / 2;
        int cy = rcParent.top  + (rcParent.bottom - rcParent.top  - DLG_H) / 2;
        // Clamp to work area
        RECT wa;
        SystemParametersInfo(SPI_GETWORKAREA, 0, &wa, 0);
        if (cx < wa.left) cx = wa.left;
        if (cy < wa.top)  cy = wa.top;

        SetWindowPos(hDlg, NULL, cx, cy, DLG_W, DLG_H,
                     SWP_NOZORDER | SWP_NOACTIVATE);

        // Font
        HFONT hFont = g_app.hUiFont
                      ? g_app.hUiFont
                      : (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        // Helper macro for creating & font-setting controls
        // x, y, w, h are base-96-DPI pixels; S() scales them.
#define CTRL(cls, text, exstyle, style, x, y, w, h, id) \
    do { \
        HWND _hw = CreateWindowExW((exstyle), cls, text, \
            WS_CHILD | WS_VISIBLE | (style), \
            S(x), S(y), S(w), S(h), \
            hDlg, (HMENU)(INT_PTR)(id), g_hInst, NULL); \
        SendMessage(_hw, WM_SETFONT, (WPARAM)hFont, FALSE); \
    } while (0)

        // ----------------------------------------------------------
        // Row 1 – Time  (y=12..28)
        // ----------------------------------------------------------
        // Time
        CTRL(L"BUTTON", L"Time",
             0, BS_AUTOCHECKBOX,
             10, 12, 52, 16, SDLG_CHK_TIME);

        // [HH] : [MM] – [HH] : [MM]  (24h)
        // Each edit box is 28 px wide; colons and dash are narrow statics.
        CTRL(L"EDIT",   L"00", WS_EX_CLIENTEDGE,
             ES_CENTER | ES_NUMBER | WS_TABSTOP,
             66, 11, 28, 18, SDLG_EDIT_SH);
        CTRL(L"STATIC", L":", 0, SS_CENTER | SS_CENTERIMAGE,
             96, 11, 8, 18, SDLG_LBL_COLON1);
        CTRL(L"EDIT",   L"00", WS_EX_CLIENTEDGE,
             ES_CENTER | ES_NUMBER | WS_TABSTOP,
             106, 11, 28, 18, SDLG_EDIT_SM);
        CTRL(L"STATIC", L"-", 0, SS_CENTER | SS_CENTERIMAGE,
             136, 11, 10, 18, SDLG_LBL_DASH);
        CTRL(L"EDIT",   L"00", WS_EX_CLIENTEDGE,
             ES_CENTER | ES_NUMBER | WS_TABSTOP,
             148, 11, 28, 18, SDLG_EDIT_EH);
        CTRL(L"STATIC", L":", 0, SS_CENTER | SS_CENTERIMAGE,
             178, 11, 8, 18, SDLG_LBL_COLON2);
        CTRL(L"EDIT",   L"00", WS_EX_CLIENTEDGE,
             ES_CENTER | ES_NUMBER | WS_TABSTOP,
             188, 11, 28, 18, SDLG_EDIT_EM);
        CTRL(L"STATIC", L"(24h)", 0, SS_LEFTNOWORDWRAP | SS_CENTERIMAGE,
             220, 11, 36, 18, SDLG_LBL_24H);

        // Limit each hour/minute box to 2 characters
        SendDlgItemMessage(hDlg, SDLG_EDIT_SH, EM_SETLIMITTEXT, 2, 0);
        SendDlgItemMessage(hDlg, SDLG_EDIT_SM, EM_SETLIMITTEXT, 2, 0);
        SendDlgItemMessage(hDlg, SDLG_EDIT_EH, EM_SETLIMITTEXT, 2, 0);
        SendDlgItemMessage(hDlg, SDLG_EDIT_EM, EM_SETLIMITTEXT, 2, 0);

        // ----------------------------------------------------------
        // Row 2 – Day of week  (y=38..54)
        // ----------------------------------------------------------
        CTRL(L"BUTTON", L"Day of week",
             0, BS_AUTOCHECKBOX,
             10, 38, 96, 16, SDLG_CHK_DAYS);

        // Seven push-like checkboxes: Mo Tu We Th Fr Sa Su
        static const wchar_t *DAY_LABELS[7] =
            { L"Mo", L"Tu", L"We", L"Th", L"Fr", L"Sa", L"Su" };
        for (int d = 0; d < 7; d++) {
            CTRL(L"BUTTON", DAY_LABELS[d],
                 0, BS_AUTOCHECKBOX | BS_PUSHLIKE | WS_TABSTOP,
                 110 + d * 32, 37, 30, 18,
                 SDLG_DAY_MON + d);
        }

        // ----------------------------------------------------------
        // Description label (sunken static)  (y=64..80)
        // ----------------------------------------------------------
        CTRL(L"STATIC", L"",
             WS_EX_STATICEDGE, SS_LEFTNOWORDWRAP | SS_CENTERIMAGE,
             10, 64, 318, 18, SDLG_DESC_LABEL);

        // ----------------------------------------------------------
        // Horizontal separator  (y=92)
        // ----------------------------------------------------------
        CTRL(L"STATIC", L"",
             0, SS_ETCHEDHORZ,
             10, 92, 318, 2, -1);

        // ----------------------------------------------------------
        // Note text  (y=100..120)
        // ----------------------------------------------------------
        CTRL(L"STATIC",
             L"When outside the schedule, all rules for this process are suspended.",
             0, SS_LEFT,
             10, 100, 318, 36, -1);

        // ----------------------------------------------------------
        // Buttons  (y=148..152)
        // ----------------------------------------------------------
        CTRL(L"BUTTON", L"Reset",  0, BS_PUSHBUTTON | WS_TABSTOP,
             10, 148, 60, 20, SDLG_BTN_RESET);
        CTRL(L"BUTTON", L"OK",     0, BS_DEFPUSHBUTTON | WS_TABSTOP,
             204, 148, 60, 20, SDLG_BTN_OK);
        CTRL(L"BUTTON", L"Cancel", 0, BS_PUSHBUTTON | WS_TABSTOP,
             268, 148, 60, 20, SDLG_BTN_CANCEL);

#undef CTRL

        // Populate controls from ctx->current
        const Schedule *s = &ctx->current;

        CheckDlgButton(hDlg, SDLG_CHK_TIME,
                       s->has_time ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, SDLG_CHK_DAYS,
                       s->has_days ? BST_CHECKED : BST_UNCHECKED);

        if (s->has_time) {
            SetDlgItemInt(hDlg, SDLG_EDIT_SH, s->start_min / 60, FALSE);
            SetDlgItemInt(hDlg, SDLG_EDIT_SM, s->start_min % 60, FALSE);
            SetDlgItemInt(hDlg, SDLG_EDIT_EH, s->end_min   / 60, FALSE);
            SetDlgItemInt(hDlg, SDLG_EDIT_EM, s->end_min   % 60, FALSE);
        }

        if (s->has_days) {
            for (int d = 1; d <= 7; d++) {
                CheckDlgButton(hDlg, SDLG_DAY_MON + d - 1,
                    (s->days_mask & (1u << d)) ? BST_CHECKED : BST_UNCHECKED);
            }
        }

        SchedDlg_EnableTimeFields(hDlg, s->has_time);
        SchedDlg_EnableDayButtons(hDlg, s->has_days);
        SchedDlg_UpdateDesc(hDlg, s);

        // Apply dark mode to all freshly-created child controls
        if (g_app.dark_mode)
            ApplyDarkModeToAllControls(hDlg, true);

        ctx->initializing = false;  // controls fully set up; EN_CHANGE is now live
        return TRUE;
    }

    case WM_COMMAND: {
        int id    = LOWORD(wParam);
        int notif = HIWORD(wParam);

        if (!ctx) break;

        switch (id) {

        // Checkbox: Time
        case SDLG_CHK_TIME: {
            bool checked = (IsDlgButtonChecked(hDlg, SDLG_CHK_TIME) == BST_CHECKED);
            ctx->current.has_time = checked;
            SchedDlg_EnableTimeFields(hDlg, checked);
            if (checked) SchedDlg_ReadTime(hDlg, &ctx->current);
            SchedDlg_UpdateDesc(hDlg, &ctx->current);
            break;
        }

        // Checkbox: Days
        case SDLG_CHK_DAYS: {
            bool checked = (IsDlgButtonChecked(hDlg, SDLG_CHK_DAYS) == BST_CHECKED);
            ctx->current.has_days = checked;
            SchedDlg_EnableDayButtons(hDlg, checked);
            if (checked) {
                // Rebuild day mask from the toggle buttons
                ctx->current.days_mask = 0;
                for (int d = 0; d < 7; d++) {
                    if (IsDlgButtonChecked(hDlg, SDLG_DAY_MON + d) == BST_CHECKED)
                        ctx->current.days_mask |= (1u << (d + 1));
                }
                // Default to Mon–Fri if nothing is already selected
                if (ctx->current.days_mask == 0) {
                    for (int d = 1; d <= 5; d++) {
                        ctx->current.days_mask |= (1u << d);
                        CheckDlgButton(hDlg, SDLG_DAY_MON + d - 1, BST_CHECKED);
                    }
                }
            }
            SchedDlg_UpdateDesc(hDlg, &ctx->current);
            break;
        }

        // Day toggle buttons (Mon=SDLG_DAY_MON .. Sun=SDLG_DAY_SUN)
        case SDLG_DAY_MON: case SDLG_DAY_TUE: case SDLG_DAY_WED: case SDLG_DAY_THU:
        case SDLG_DAY_FRI: case SDLG_DAY_SAT: case SDLG_DAY_SUN: {
            if (notif == BN_CLICKED && ctx->current.has_days) {
                ctx->current.days_mask = 0;
                for (int d = 0; d < 7; d++) {
                    if (IsDlgButtonChecked(hDlg, SDLG_DAY_MON + d) == BST_CHECKED)
                        ctx->current.days_mask |= (1u << (d + 1));
                }
                SchedDlg_UpdateDesc(hDlg, &ctx->current);
            }
            break;
        }

        // Time edit fields: update description live as user types
        case SDLG_EDIT_SH: case SDLG_EDIT_SM:
        case SDLG_EDIT_EH: case SDLG_EDIT_EM: {
            if (notif == EN_CHANGE && ctx->current.has_time && !ctx->initializing) {
                SchedDlg_ReadTime(hDlg, &ctx->current);
                SchedDlg_UpdateDesc(hDlg, &ctx->current);
            }
            break;
        }

        // Clear the entire schedule
        case SDLG_BTN_RESET: {
            schedule_init(&ctx->current);

            CheckDlgButton(hDlg, SDLG_CHK_TIME, BST_UNCHECKED);
            CheckDlgButton(hDlg, SDLG_CHK_DAYS, BST_UNCHECKED);

            for (int d = 0; d < 7; d++)
                CheckDlgButton(hDlg, SDLG_DAY_MON + d, BST_UNCHECKED);

            SetDlgItemTextW(hDlg, SDLG_EDIT_SH, L"00");
            SetDlgItemTextW(hDlg, SDLG_EDIT_SM, L"00");
            SetDlgItemTextW(hDlg, SDLG_EDIT_EH, L"00");
            SetDlgItemTextW(hDlg, SDLG_EDIT_EM, L"00");

            SchedDlg_EnableTimeFields(hDlg, false);
            SchedDlg_EnableDayButtons(hDlg, false);
            SchedDlg_UpdateDesc(hDlg, &ctx->current);
            break;
        }

        case SDLG_BTN_OK:
        case IDOK: {
            // Final read in case the user never left the last edit box
            if (ctx->current.has_time)
                SchedDlg_ReadTime(hDlg, &ctx->current);

            if (ctx->current.has_time &&
                ctx->current.start_min == ctx->current.end_min) {
                MSGBOX(hDlg,
                    L"Start and end times are identical.\n"
                    L"Please enter a valid time range, or uncheck the Time option.",
                    L"Invalid Schedule", MB_OK | MB_ICONWARNING);
                break;
            }
            if (ctx->current.has_days && ctx->current.days_mask == 0) {
                MSGBOX(hDlg,
                    L"No days of the week are selected.\n"
                    L"Please select at least one day, or uncheck the Day of week option.",
                    L"Invalid Schedule", MB_OK | MB_ICONWARNING);
                break;
            }

            // Commit to the ProcessEntry
            ProcessEntry *proc = &g_app.processes[ctx->proc_idx];
            proc->schedule = ctx->current;

            // Sync back to the sticky registry and save to disk
            SyncStickyLimits(proc);
            Sticky_Save();

            // Re-apply throttle rules now (schedule may have changed
            // whether the current time is inside the window)
            UpdateProcessLimits();
            InvalidateRect(g_app.hProcessList, NULL, FALSE);

            // Re-arm the timer so it fires at the nearest boundary of the
            // newly configured schedule rather than up to 30s from now.
            RearmScheduleTimer(g_app.hMainWnd);

            EndDialog(hDlg, IDOK);
            break;
        }

        case SDLG_BTN_CANCEL:
        case IDCANCEL: {
            EndDialog(hDlg, IDCANCEL);
            break;
        }

        } // switch (id)
        break;
    }

    // Dark-mode colour hooks
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
        if (!g_app.dark_mode) break;
        return DarkMode_HandleCtlColor((HDC)wParam, (HWND)lParam, msg);
    }

    case WM_ERASEBKGND: {
        if (!g_app.dark_mode) break;
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hDlg, &rc);
        FillRect(hdc, &rc, g_app.hDarkBrush);
        return 1;
    }

    case WM_DRAWITEM: {
        if (!g_app.dark_mode) break;
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            DrawDarkButton(dis);
            return TRUE;
        }
        break;
    }

    case WM_NCDESTROY:
        free(ctx);
        SetWindowLongPtr(hDlg, GWLP_USERDATA, 0);
        break;

    case WM_CLOSE:
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }

    return FALSE;
}

// ---------------------------------------------------------------------------
// Stats window management
// ---------------------------------------------------------------------------
// Modeless pattern for windows
void OpenOrFocusStats(HWND hParent) {
    if (g_app.hStatsWnd) {
        // Already open - bring to front and restore if minimized
        if (IsIconic(g_app.hStatsWnd))
            ShowWindow(g_app.hStatsWnd, SW_RESTORE);
        SetForegroundWindow(g_app.hStatsWnd);
        return;
    }

    // CreateDialog (modeless) instead of DialogBox (modal)
    g_app.hStatsWnd = CreateDialogW(g_hInst,
                                    MAKEINTRESOURCE(IDD_STATS_DIALOG),
                                    hParent,   // owner - keeps it above main
                                    StatsDlgProc);
    if (!g_app.hStatsWnd) return;

    // Add the APPWINDOW style to make it appear on the taskbar
    SetWindowLong(g_app.hStatsWnd, GWL_EXSTYLE,
                  GetWindowLong(g_app.hStatsWnd, GWL_EXSTYLE) | WS_EX_APPWINDOW);

    // Remove the owner relationship
    SetWindowLongPtr(g_app.hStatsWnd, GWLP_HWNDPARENT, 0);

    // Set the icon
    HICON hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(1));
    if (!hIcon) hIcon = LoadIcon(NULL, IDI_APPLICATION);
    SendMessage(g_app.hStatsWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    SendMessage(g_app.hStatsWnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);

    // Center relative to main window on first open.
    CenterWindow(g_app.hStatsWnd, hParent);

    // Clamp to monitor work area so it never spawns off-screen
    ClampWindowToWorkArea(g_app.hStatsWnd);

    // Force initial WM_SIZE layout pass
    RECT rc;
    GetClientRect(g_app.hStatsWnd, &rc);
    SendMessage(g_app.hStatsWnd, WM_SIZE, SIZE_RESTORED,
                MAKELPARAM(rc.right, rc.bottom));

    ShowWindow(g_app.hStatsWnd, SW_SHOW);
}

// ---------------------------------------------------------------------------
// Chart window subclass
// ---------------------------------------------------------------------------
LRESULT CALLBACK ChartWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                      UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc;
        GetClientRect(hWnd, &rc);

        // Determine which chart this is
        bool isUpload = (uIdSubclass == 1);
        double* history = isUpload ? g_app.ul_history : g_app.dl_history;
        COLORREF color = isUpload ? RGB(255, 140, 64) : RGB(64, 190, 255);

        DrawSparkline(hdc, &rc, history, color);

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, ChartWndProc, uIdSubclass);
        break;
    }

    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------
// Save Statistics to CSV
// Writes per-process traffic table + summary to a timestamped CSV file
// next to the executable.  Returns true on success.
bool SaveStatisticsToCSV(HWND hParent) {
    // Build output path: <snapshot_dir>\BandwidthShaper_YYYYMMDD_HHMM.csv
    // snapshot_dir is resolved (with fallback to exe dir) by ResolveOrFallbackDir
    // inside Settings_GetSnapshotDir, called here directly.
    extern bool ResolveOrFallbackDir(const wchar_t*, wchar_t*, DWORD);
    wchar_t snap_dir[MAX_PATH];
    if (!ResolveOrFallbackDir(g_app.options.snapshot_dir, snap_dir, MAX_PATH)
            || snap_dir[0] == L'\0') {
        // Fallback: exe directory (ResolveOrFallbackDir already filled snap_dir)
        if (snap_dir[0] == L'\0') {
            if (!GetModuleFileNameW(NULL, snap_dir, MAX_PATH)) return false;
            wchar_t *sep = wcsrchr(snap_dir, L'\\');
            if (!sep) sep = wcsrchr(snap_dir, L'/');
            if (sep) *(sep + 1) = L'\0'; else snap_dir[0] = L'\0';
        }
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t filename[MAX_PATH];
    swprintf(filename, MAX_PATH,
             L"%sBandwidthShaper_%04u%02u%02u_%02u%02u.csv",
             snap_dir,
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute);

    // Open file for writing (UTF-8 with BOM so Excel auto-detects encoding)
    FILE *f = NULL;
    if (_wfopen_s(&f, filename, L"w,ccs=UTF-8") != 0 || !f) {
        MSGBOX(hParent,
            L"Failed to create the CSV file.\n"
            L"Make sure the application has write access to its directory.",
            L"Save Statistics", MB_OK | MB_ICONERROR);
        return false;
    }

    // Timestamp header
    fwprintf(f, L"BandwidthShaper Statistics Export\n");
    fwprintf(f, L"Generated,%04u-%02u-%02u %02u:%02u:%02u\n\n",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);

    // Read process stats under lock
    EnterCriticalSection(&g_app.process_lock);

    // Per-process traffic table
    // Sort by total descending (same logic as display)
    typedef struct { int idx; uint64_t total; } SE;
    SE sorted[MAX_PROCESSES];
    int scount = 0;
    for (int i = 0; i < g_app.proc_stats_count; i++) {
        uint64_t t = g_app.proc_stats[i].dl_bytes + g_app.proc_stats[i].ul_bytes;
        if (t == 0) continue;
        sorted[scount].idx   = i;
        sorted[scount].total = t;
        scount++;
    }
    for (int a = 0; a < scount - 1; a++)
        for (int b = a + 1; b < scount; b++)
            if (sorted[b].total > sorted[a].total) {
                SE tmp = sorted[a]; sorted[a] = sorted[b]; sorted[b] = tmp;
            }

    fwprintf(f, L"Per-Process Traffic\n");
    fwprintf(f, L"Process,Description,Data In (MB),Data Out (MB),Total (MB),Quota In (MB),Quota Out (MB),Quota Exhausted\n");
    for (int r = 0; r < scount; r++) {
        int si = sorted[r].idx;
        double dl_mb = g_app.proc_stats[si].dl_bytes / (1024.0 * 1024.0);
        double ul_mb = g_app.proc_stats[si].ul_bytes / (1024.0 * 1024.0);
        double tot = dl_mb + ul_mb;

        // Find matching process entry to get quota information
        double quota_in_mb = 0.0;
        double quota_out_mb = 0.0;
        bool quota_exhausted = false;

        for (int i = 0; i < g_app.process_count; i++) {
            if (_wcsicmp(g_app.processes[i].name, g_app.proc_stats[si].name) == 0) {
                quota_in_mb = g_app.processes[i].quota_in / (1024.0 * 1024.0);
                quota_out_mb = g_app.processes[i].quota_out / (1024.0 * 1024.0);
                quota_exhausted = (g_app.processes[i].quota_in > 0 && g_app.processes[i].quota_in_used >= g_app.processes[i].quota_in) ||
                                 (g_app.processes[i].quota_out > 0 && g_app.processes[i].quota_out_used >= g_app.processes[i].quota_out);
                break;
            }
        }

        // Quote fields that might contain commas
        fwprintf(f, L"\"%s\",\"%s\",%.3f,%.3f,%.3f,%.3f,%.3f,\"%s\"\n",
                 g_app.proc_stats[si].name,
                 g_app.proc_stats[si].description,
                 dl_mb, ul_mb, tot,
                 quota_in_mb, quota_out_mb,
                 quota_exhausted ? L"YES" : L"NO");
    }

    LeaveCriticalSection(&g_app.process_lock);

    if (scount == 0) {
        fwprintf(f, L"(no traffic recorded)\n");
    }

    fwprintf(f, L"\n");

    // Summary / packet counters
    fwprintf(f, L"Session Summary\n");
    if (g_app.has_last_stats) {
        // Use the frozen last_stats snapshot
        fwprintf(f, L"Packets processed,%llu\n",     g_app.last_stats.packets_processed);
        fwprintf(f, L"Dropped (rate limit),%llu\n",  g_app.last_stats.packets_dropped_rate_limit);
        fwprintf(f, L"Dropped (loss sim),%llu\n",    g_app.last_stats.packets_dropped_loss);
        fwprintf(f, L"Delayed,%llu\n",               g_app.last_stats.packets_delayed);
        fwprintf(f, L"Invalid packets,%llu\n",       g_app.last_stats.invalid_packets);
        fwprintf(f, L"Total bytes processed,%llu\n", g_app.last_stats.bytes_processed);
        fwprintf(f, L"Total bytes processed (MB),%.3f\n",
                 g_app.last_stats.bytes_processed / (1024.0 * 1024.0));

        // Compute overall DL/UL from the proc_stats table (most accurate)
        uint64_t sum_dl = 0, sum_ul = 0;
        for (int i = 0; i < g_app.proc_stats_count; i++) {
            sum_dl += g_app.proc_stats[i].dl_bytes;
            sum_ul += g_app.proc_stats[i].ul_bytes;
        }
        fwprintf(f, L"Download bytes (MB),%.3f\n", sum_dl / (1024.0 * 1024.0));
        fwprintf(f, L"Upload bytes (MB),%.3f\n",   sum_ul / (1024.0 * 1024.0));

        if (g_app.last_stats.cap_reached)
            fwprintf(f, L"Data cap reached,YES\n");

        // Add quota exhaustion summary
        bool any_quota_exhausted = false;
        for (int i = 0; i < g_app.process_count; i++) {
            ProcessEntry* proc = &g_app.processes[i];
            if ((proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in) ||
                (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out)) {
                if (!any_quota_exhausted) {
                    fwprintf(f, L"\nQuota Exhausted Processes\n");
                    fwprintf(f, L"Process,Quota Type,Quota (MB),Used (MB)\n");
                    any_quota_exhausted = true;
                }

                if (proc->quota_in > 0 && proc->quota_in_used >= proc->quota_in) {
                    double quota_mb = proc->quota_in / (1024.0 * 1024.0);
                    double used_mb = proc->quota_in_used / (1024.0 * 1024.0);
                    fwprintf(f, L"\"%s\",IN,%.3f,%.3f\n", proc->name, quota_mb, used_mb);
                }

                if (proc->quota_out > 0 && proc->quota_out_used >= proc->quota_out) {
                    double quota_mb = proc->quota_out / (1024.0 * 1024.0);
                    double used_mb = proc->quota_out_used / (1024.0 * 1024.0);
                    fwprintf(f, L"\"%s\",OUT,%.3f,%.3f\n", proc->name, quota_mb, used_mb);
                }
            }
        }
    } else {
        fwprintf(f, L"(shaper not yet stopped - no final summary available)\n");
    }

    fclose(f);

    // Notify user with the full path
    wchar_t msg[MAX_PATH + 64];
    swprintf(msg, MAX_PATH + 64, L"Statistics saved to:\n%s", filename);
    MSGBOX(hParent, msg, L"Save Statistics", MB_OK | MB_ICONINFORMATION);
    return true;
}
