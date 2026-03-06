// common.h
// Central header for BandwidthShaper - includes all common system headers and defines
#ifndef COMMON_H
#define COMMON_H

// -----------------------------------------------------------------------
// Platform and compiler defines
// -----------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

// -----------------------------------------------------------------------
// App version number
// -----------------------------------------------------------------------
#define APP_VERSION L"V2.0"

// -----------------------------------------------------------------------
// Windows headers
// -----------------------------------------------------------------------
#include <winsock2.h>      // Must come before windows.h
#include <windows.h>
#include <ws2tcpip.h>      // For INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <iphlpapi.h>      // For network adapter functions
#include <psapi.h>         // For process enumeration

// -----------------------------------------------------------------------
// Standard C headers
// -----------------------------------------------------------------------
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include <assert.h>

// -----------------------------------------------------------------------
// Third-party headers
// -----------------------------------------------------------------------
#include "external/windivert.h"
#include "external/uthash.h"

// -----------------------------------------------------------------------
// Project-wide constants
// -----------------------------------------------------------------------
#define MAX_PACKET_SIZE WINDIVERT_MTU_MAX  // (40 + 0xFFFF) = 40 + 65535
#define DEFAULT_DL_BUFFER 150000
#define DEFAULT_UL_BUFFER 150000
#define DELAY_BUFFER_SIZE 8192
#define STATS_UPDATE_INTERVAL 5000  // ms
#define MAX_PROCESS_NAME_LEN 260

// Maximum number of sticky processes
#define MAX_STICKY_PROCS 64

// Maximum number of processes
#define MAX_PROCESSES 256

// Config file constants
#define MAX_CONFIG_LINE_LEN 1024
#define MAX_CONFIG_KEY_LEN 64
#define MAX_CONFIG_VALUE_LEN 512
#define MAX_INTERVAL_STR_LEN 32

// -----------------------------------------------------------------------
// Common inline utilities
// -----------------------------------------------------------------------
static inline LONGLONG get_time_ticks(void) {
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return c.QuadPart;
}

static inline double get_perf_frequency(void) {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return (double)freq.QuadPart;
}

#endif // COMMON_H
