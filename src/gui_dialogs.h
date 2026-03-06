#ifndef GUI_DIALOGS_H
#define GUI_DIALOGS_H

#include "gui_main.h"
#include "gui_types.h"
#include "schedule.h"

// Context passed to the dialog (related to sticky processes)
typedef struct {
    int proc_idx;      // index into g_app.processes
    Schedule initial;  // schedule when dialog opened (for Cancel)
    Schedule current;  // working copy being edited
    bool     initializing; // true while WM_INITDIALOG is populating controls
} ScheduleDlgCtx;

// Dialog procedures
INT_PTR CALLBACK OptionsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK StatsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK SpecifyProcDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK ScheduleDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);

// Stats window management
void OpenOrFocusStats(HWND hParent);

// Chart window subclass
LRESULT CALLBACK ChartWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
                              UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

// CSV export
bool SaveStatisticsToCSV(HWND hParent);

#endif
