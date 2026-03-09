// resource.h
#pragma once

#ifndef IDC_STATIC
#define IDC_STATIC  -1
#endif

// Main window
#define IDR_MAIN_MENU       101
#define IDD_MAIN_WINDOW     102
#define IDD_OPTIONS_DIALOG  103
#define IDD_STATS_DIALOG    104

// Menu items - File
#define ID_FILE_EXIT            1001
#define ID_FILE_LOCATE_PROC     1002
#define ID_FILE_SPECIFY_PROC    1003
#define ID_FILE_REMOVE_CUSTOM   1004

// Menu items - View
#define ID_VIEW_REFRESH         1101
#define ID_VIEW_OPTIONS         1102
#define ID_VIEW_STATS           1103
#define ID_VIEW_EXPAND_ALL      1104
#define ID_VIEW_COLLAPSE_ALL    1105

// View > Update Frequency submenu (contiguous so LOWORD(wParam) - ID_FREQ_OFTEN = index)
#define ID_FREQ_OFTEN           1110   // 1 s
#define ID_FREQ_NORMAL          1111   // 2 s  (default)
#define ID_FREQ_SLOWER          1112   // 15 s
#define ID_FREQ_SCARCELY        1113   // 45 s
#define ID_FREQ_RARELY          1114   // 2 min
#define ID_FREQ_DISABLED        1115   // timer off

// View > Processes submenu
#define ID_PROC_SHOW_ALL        1120
#define ID_PROC_SHOW_CUSTOM     1121
#define ID_PROC_SHOW_RUNNING    1122

// Menu items - Help
#define ID_HELP_ABOUT           1201

// Main window controls
#define IDC_TOOLBAR         2000
#define IDC_START_BTN       2001
#define IDC_STOP_BTN        2002
#define IDC_RELOAD_BTN      2003
#define IDC_UNIT_COMBO      2004
#define IDC_PROCESS_LIST    2005
#define IDC_STATUS_BAR      2006

// Process list columns
#define IDC_PL_NAME         0
#define IDC_PL_PID          1
#define IDC_PL_DL_RATE      2
#define IDC_PL_UL_RATE      3
#define IDC_PL_DL_LIMIT     4
#define IDC_PL_UL_LIMIT     5
#define IDC_PL_QUOTA_IN     6
#define IDC_PL_QUOTA_OUT    7
#define IDC_PL_SCHEDULE     8
#define IDC_PL_ACTIONS      9

// Options dialog controls
#define IDC_OPT_NIC_LIST             3001
#define IDC_OPT_DL_BUFFER            3002
#define IDC_OPT_UL_BUFFER            3003
#define IDC_OPT_BURST_SIZE           3004
#define IDC_OPT_UPDATE_INTERVAL      3005
#define IDC_OPT_UPDATE_TYPE          3006  // packets radio (Milliseconds = 3007)
#define IDC_OPT_UPDATE_COOLDOWN      3018
#define IDC_OPT_DATA_CAP             3008
#define IDC_OPT_TCP_LIMIT            3009
#define IDC_OPT_UDP_LIMIT            3010
#define IDC_OPT_MINIMIZE_TRAY        3011
#define IDC_OPT_LATENCY              3012
#define IDC_OPT_PACKET_LOSS          3013
#define IDC_OPT_PRIORITY             3014
#define IDC_OPT_DL_GLOBAL            3015
#define IDC_OPT_UL_GLOBAL            3016
#define IDC_OPT_APPLY                3017
#define IDC_OPT_SAVE_SETTINGS        3019
#define IDC_OPT_SAVE_STICKY_SETTINGS 3020
#define IDC_OPT_CONFIG_DIR           3021
#define IDC_OPT_CONFIG_DIR_BROWSE    3022
#define IDC_OPT_SNAPSHOT_DIR         3023
#define IDC_OPT_SNAPSHOT_DIR_BROWSE  3024

// "Specify process" input dialog
#define IDD_SPECIFY_PROC        105
#define IDC_SPECIFY_NAME        6001

// Stats dialog controls
#define IDC_STATIC_DL_LABEL         4001
#define IDC_STATIC_UL_LABEL         4002
#define IDC_STATIC_PROC_LIST_LABEL  4003
#define IDC_STATIC_STATS_LABEL      4004
#define IDC_STATS_DL_CHART          4005
#define IDC_STATS_UL_CHART          4006
#define IDC_STATS_PROC_LIST         4007
#define IDC_STATS_TEXT              4008
#define IDC_STATS_SAVE              4009
#define IDC_STATS_RESET             4010

// Tray
#define IDI_TRAY_ICON       5000
#define ID_TRAY_SHOW        5001
#define ID_TRAY_START       5002
#define ID_TRAY_STOP        5003
#define ID_TRAY_STATS       5004
#define ID_TRAY_EXIT        5005
