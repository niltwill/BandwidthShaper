#ifndef GUI_UTILS_H
#define GUI_UTILS_H

#include "gui_main.h"
#include "gui_constants.h"
#include "gui_types.h"

// Accessors for AppState members needed by utils
HINSTANCE GetHInst(void);
UINT GetDPI(void);
HFONT GetUIFont(void);
bool IsDarkMode(void);
HBRUSH GetDarkBrush(int type);

// Update frequencies
#define FREQ_DEFAULT_IDX 1

// Dark mode colors
#define DARK_BG_COLOR        RGB(32, 32, 32)
#define DARK_LIST_COLOR      RGB(45, 45, 45)
#define DARK_HIGHLIGHT_COLOR RGB(60, 80, 120)
#define DEF_HIGHLIGHT_COLOR  RGB(169, 212, 255)
#define DARK_TEXT_COLOR      RGB(240, 240, 240)
#define DEF_TEXT_COLOR       RGB(0, 0, 0)
#define DARK_GRID_COLOR      RGB(80, 80, 80)
#define DARK_BTN_FACE        RGB(58, 58, 58)
#define DARK_BTN_HOT         RGB(75, 75, 75)
#define DARK_BTN_PRESSED     RGB(40, 40, 40)
#define DARK_BTN_BORDER      RGB(110, 110, 110)
#define DARK_DISABLED_TEXT   RGB(120, 120, 120)
#define DARK_TOOLBAR_COLOR   RGB(38, 38, 38)

// Admin privilege check and elevation helpers
bool IsUserAdmin(void);
bool RelaunchAsAdmin(void);

// Initialize main window
void InitializeMainWindow(HWND hWnd);
void CreateStatusBar(HWND hWnd);

// Stop and reload functions
bool StartShaper(void);
bool ReloadShaperConfig(void);
void StopShaper(void);

// DPI scaling
int S(int px);
void RecreateUiFont(void);
void ApplyFontToChildren(HWND hParent);
void CenterWindow(HWND hWnd, HWND hParent);
void ClampWindowToWorkArea(HWND hWnd);

// Dark mode
void InitializeDarkMode(void);
void CleanupDarkMode(void);
bool DarkMode_SystemIsDark(void);
void DarkMode_InitUxtheme(void);
void ApplyDarkModeToAllControls(HWND hParent, bool enable);
void ApplyDarkModeToListViewHeader(HWND hListView);
void ApplyDarkModeToDialog(HWND hDlg);
void DarkMode_ApplyToDialog(HWND hDlg);
void UpdateStatistics_RichBox(void);
BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam);
LRESULT DarkMode_HandleCtlColor(HDC hdc, HWND hwndCtl, UINT msg);
void DrawDarkButton(LPDRAWITEMSTRUCT dis);

// Dark mode - subclasses (custom dark theme overrides)
LRESULT CALLBACK ToolbarPanelSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
LRESULT CALLBACK StatusBarSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
LRESULT CALLBACK HeaderSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

// Tray icon
void TrayAdd(HWND hWnd);
void TrayRemove(void);
void TrayShowMenu(HWND hWnd);
void MinimizeToTray(void);
void RestoreFromTray(void);

// Settings
bool Settings_GetPath(wchar_t *path, DWORD cchPath);
void Settings_Save(void);
void Settings_Load(void);

// NIC list
void PopulateNicList(HWND hDlg);

// Rate formatting
double ParseRateInput(const wchar_t* input);
void FormatRateAuto(wchar_t* buf, size_t len, double rate_bps);
void FormatRateFixed(wchar_t* buf, size_t len, double rate_bps);
uint64_t ParseQuotaInput(const wchar_t* input);

// Tooltip helper
typedef struct { int ctrlId; const wchar_t *text; } TooltipDef;
HWND CreateTooltips(HWND hDlg, const TooltipDef *defs, int count);

// Various helper functions
void UpdateStats(void);
void DrawSparkline(HDC hdc, RECT* rect, double* history, COLORREF color);
void ApplyUpdateFrequency(int idx);
bool IsAnyQuotaExhausted(void);
bool AnyScheduleActive(void);
UINT ScheduleNextFireMs(void);

// Layout
void LayoutMainWindow(HWND hWnd);

// Timer handlers
void onTimer(HWND hWnd, WPARAM timerId);
void RearmScheduleTimer(HWND hWnd);

// Command handlers (delegates)
BOOL onCommand(HWND hWnd, WPARAM wParam, LPARAM lParam);

// Window lifecycle
LRESULT onCreate(HWND hWnd);
LRESULT onClose(HWND hWnd);
LRESULT onDestroy(HWND hWnd);
LRESULT onDrawItem(HWND hWnd, LPARAM lParam);
LRESULT onEraseBkgnd(HWND hWnd, WPARAM wParam);
LRESULT onUahDrawMenu(HWND hWnd, WPARAM wParam, LPARAM lParam);
LRESULT onUahDrawMenuItem(HWND hWnd, WPARAM wParam, LPARAM lParam);
LRESULT areaNC(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT settingChanged(HWND hWnd, WPARAM wParam, LPARAM lParam);
LRESULT onDpiChanged(HWND hWnd, WPARAM wParam, LPARAM lParam);

#endif
