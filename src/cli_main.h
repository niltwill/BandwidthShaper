#ifndef MAIN_CLI_H
#define MAIN_CLI_H

// cli_main.h
// Public interface for the BandwidthShaper CLI front-end.
//
// This header exists primarily so the translation unit is self-contained
// and so a future test harness can call cli_run() directly without
// linking a second main().  In normal builds only cli_main.c includes it.

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdbool.h>
#include <windows.h>

// -----------------------------------------------------------------------
// Entry point (called by main())
// -----------------------------------------------------------------------

// Run the full CLI lifecycle:
//   parse -> validate -> start core -> loop -> hot-reload -> stop -> cleanup
// Returns EXIT_SUCCESS or EXIT_FAILURE.
int cli_run(int argc, char **argv);

// -----------------------------------------------------------------------
// Ctrl+C / console-event handler
//
// Registered with SetConsoleCtrlHandler().  Sets the shared quit flag
// that both the packet loop and the main thread check.
// Must be async-signal-safe: no printf, malloc, Sleep, etc.
// -----------------------------------------------------------------------
BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType);

#endif // MAIN_CLI_H
