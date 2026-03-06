#ifndef GUI_CONSTANTS_H
#define GUI_CONSTANTS_H

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <uxtheme.h>
#include <windowsx.h>

// Timer IDs
#define TIMER_STATS_ID          1
#define TIMER_PROCESS_REFRESH   2
#define TIMER_SCHEDULE_CHECK    3
#define TIMER_STATS_INTERVAL_MS 500   // Update statistics (ms)
#define TIMER_PROCESS_INTERVAL  2000  // Update processes (ms)
#define TIMER_PAUSE_UNTIL_TICK  5000  // Pause periodic refresh (ms) - while editing a cell

// Sparkline
#define SPARKLINE_SAMPLES 60

// Process limit for PIDs
// Note: shaper_snapshot_traffic is only used in the GUI,
// but for the future as a reminder...
// For CLI use, this should be put into common.h instead and then remove it from here
#define MAX_PID_FOR_PROCESS 128

// Application messages
#define WM_APP_NIC_WARNING      (WM_APP + 1)
#define WM_APP_UPDATE_LIMITS    (WM_APP + 2)

// Window messages
#define WM_UPDATE_PROCESS_LIST  (WM_USER + 10)
#define WM_TRAY_ICON            (WM_USER + 11)

// Display constants
#define process_iconSize S(16)
#define MAX_DISPLAY_ROWS (MAX_PROCESSES * 17)

// Symbols
#define DOWNWARDS_ARROW   L"\x2193"   // ↓ (DL indicator in status)
#define UPWARDS_ARROW     L"\x2191"   // ↑ (UL indicator in status)
#define UP_ARROW          L"\x25B2"   // ▲ (up arrow for sorting)
#define DOWN_ARROW        L"\x25BC"   // ▼ (down arrow for sorting)
#define SUB_PID           L"\x2514"   // └ (grouped PID process)
#define RIGHT_ARROW       L"\x25BA"   // ► (expandable process with multiple PIDs)
#define MARKER_RUNNING    L"\x25CF "  // ● (live sticky process)
#define MARKER_GHOST      L"\x25CC "  // ◌ (sticky but not currently running)
#define MARKER_NOTRUNNING L"\x2014"   // — (process is currently not running)

// MessageBox helper
#define MSGBOX(hWnd, text, caption, type) MessageBoxW(hWnd, text, caption, type)

#endif
