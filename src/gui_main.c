// Core: WinMain, main WndProc, application lifecycle
#include "gui_main.h"
#include "gui_state.h"
#include "gui_utils.h"
#include "gui_proc_list.h"
#include "gui_dialogs.h"
#include "resource.h"
#include "external/UAHMenuBar.h"
#include <objbase.h>

AppState g_app = {0};
HINSTANCE g_hInst = NULL;
HTHEME g_menuTheme = NULL;

// MainWndProc - only essential window handling, delegate to other modules
static LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        return onCreate(hWnd);

    case WM_SIZE:
        // Delegate to utility function for layout
        LayoutMainWindow(hWnd);
        return 0;

    case WM_TIMER:
        // Delegate to appropriate handlers
        onTimer(hWnd, wParam);
        return 0;

    case WM_COMMAND:
        // Delegate command handling
        return onCommand(hWnd, wParam, lParam);

    case WM_NOTIFY:
        // Delegate to process list handler first
        if (onProcessListNotify(hWnd, lParam))
            return 0;
        // Then check other notifications
        break;  // to fall through to DefWindowProc

    case WM_DRAWITEM: {
        // Owner-draw buttons (dark mode)
        LRESULT result = onDrawItem(hWnd, lParam);
        if (result)
            return result;
        break;
    }

    case WM_ERASEBKGND: {
        // Suppress grey erase flash on the main window
        LRESULT result = onEraseBkgnd(hWnd, wParam);
        if (result)
            return result;
        break;
    }

    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLORBTN: {
        // Dark mode colour hooks for child controls
        if (!g_app.dark_mode) break;
        return DarkMode_HandleCtlColor((HDC)wParam, (HWND)lParam, msg);
    }

    case WM_UAHDRAWMENU: {
        LRESULT result = onUahDrawMenu(hWnd, wParam, lParam);
        if (result)
            return result;
        break;
    }

    case WM_UAHDRAWMENUITEM: {
        LRESULT result = onUahDrawMenuItem(hWnd, wParam, lParam);
        if (result)
            return result;
        break;
    }

    case WM_NCPAINT:
    case WM_NCACTIVATE: {
        LRESULT result = areaNC(hWnd, msg, wParam, lParam);
        if (result)
            return result;
        break;
    }
    
    case WM_SETTINGCHANGE: {
        LRESULT result = settingChanged(hWnd, wParam, lParam);
        if (result)
            return result;
        break;
    }

    case WM_THEMECHANGED: {
        if (g_menuTheme) { CloseThemeData(g_menuTheme); g_menuTheme = NULL; }
        break;
    }

    case WM_DPICHANGED:
        return onDpiChanged(hWnd, wParam, lParam);

    case WM_APP_NIC_WARNING:
        SendMessageW(g_app.hStatusBar, SB_SETTEXT, 0,
                     (LPARAM)g_app.missing_nic_warning);
        return 0;

    case WM_APP_UPDATE_LIMITS:
        UpdateProcessLimits();
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_MINIMIZE && g_app.minimize_to_tray) {
            MinimizeToTray();
            return 0;
        }
        break;

    case WM_TRAY_ICON:
        if (lParam == WM_RBUTTONUP) {
            TrayShowMenu(hWnd);
        } else if (lParam == WM_LBUTTONDBLCLK) {
            RestoreFromTray();
        }
        return 0;

    case WM_CLOSE:
        return onClose(hWnd);

    case WM_DESTROY:
        return onDestroy(hWnd);
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// WinMain
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nCmdShow) {

    (void)hPrev; (void)lpCmdLine;
    g_hInst = hInst;

    // Initialize COM for shell operations
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        MSGBOX(NULL, L"Failed to initialize COM", L"Error", MB_OK);
        return 1;
    }

    // Check for existing instance
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"BandwidthShaper_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Another instance is running - bring it to front and exit
        HWND hExisting = FindWindowW(L"BandwidthShaperMain", NULL);
        if (hExisting) {
            ShowWindow(hExisting, SW_RESTORE);
            SetForegroundWindow(hExisting);
        }
        CloseHandle(hMutex);
        return 0;
    }

    // Check for admin privileges
    if (!IsUserAdmin()) {
        int result = MSGBOX(NULL,
            L"This program requires administrator privileges to work.\n\n"
            L"Would you like to try to elevate it?",
            L"Administrator Rights Required",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON1);

        if (result == IDYES) {
            if (!RelaunchAsAdmin()) {
                MSGBOX(NULL,
                    L"Failed to obtain administrator privileges.\n"
                    L"The program will now exit.",
                    L"Error",
                    MB_OK | MB_ICONERROR);
                CloseHandle(hMutex);
                return 1;
            }
            // Relaunch succeeded - exit this non-elevated instance
            CloseHandle(hMutex);
            return 0;
        } else {
            CloseHandle(hMutex);
            return 0;
        }
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icex = {sizeof(icex), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&icex);

    // Initialize Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // Register window class
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(1));
    if (!wc.hIcon)
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = MAKEINTRESOURCE(IDR_MAIN_MENU);
    wc.lpszClassName = L"BandwidthShaperMain";
    wc.hIconSm = LoadIcon(g_hInst, MAKEINTRESOURCE(1));
    if (!wc.hIconSm)
        wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MSGBOX(NULL, L"Failed to register window class", L"Error", MB_OK);
        return 1;
    }

    // Create main window
    UINT startDpi = GetDpiForSystem();  // safe before the window exists
    HWND hWnd = CreateWindowExW(
        0, L"BandwidthShaperMain", L"BandwidthShaper",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, MulDiv(1000, startDpi, 96), MulDiv(700, startDpi, 96),
        NULL, NULL, hInst, NULL
    );

    if (!hWnd) {
        MSGBOX(NULL, L"Failed to create window", L"Error", MB_OK);
        return 1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

	// Local Accelerator Table for hotkeys
    ACCEL accel[] = {
        { FVIRTKEY | FALT,        'L',   ID_FILE_LOCATE_PROC },         // Alt+L (Locate)
        { FVIRTKEY | FALT,        'P',   ID_FILE_SPECIFY_PROC },        // Alt+P (Process)
        { FVIRTKEY | FALT,        'R',   ID_FILE_REMOVE_CUSTOM },       // Alt+R (Remove)
        { FVIRTKEY,               VK_F5, ID_VIEW_REFRESH },             // F5
        { FVIRTKEY | FALT,        VK_ADD, ID_VIEW_EXPAND_ALL },         // Alt++ (+)
        { FVIRTKEY | FALT,        VK_SUBTRACT, ID_VIEW_COLLAPSE_ALL },  // Alt+- (-)
        { FVIRTKEY | FALT,        'A',   ID_PROC_SHOW_ALL },            // Alt+A (All)
        { FVIRTKEY | FALT,        'S',   ID_PROC_SHOW_CUSTOM },         // Alt+S (Sticky)
        { FVIRTKEY | FALT,        'C',   ID_PROC_SHOW_RUNNING },        // Alt+C (Current)
        { FVIRTKEY | FCONTROL,    'O',   ID_VIEW_OPTIONS },             // Ctrl+O (Options)
        { FVIRTKEY | FCONTROL,    'S',   ID_VIEW_STATS },               // Ctrl+S (Stats)
    };
    HACCEL hAccel = CreateAcceleratorTable(accel, 11);

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (g_app.hStatsWnd && IsDialogMessage(g_app.hStatsWnd, &msg))
            continue;
        if (!TranslateAccelerator(hWnd, hAccel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    DestroyAcceleratorTable(hAccel);
    WSACleanup();
    CloseHandle(hMutex);
    UnregisterClassW(L"BandwidthShaperMain", hInst);
    if (SUCCEEDED(hr) || hr == S_FALSE) {
        CoUninitialize();
    }
    return (int)msg.wParam;
}
