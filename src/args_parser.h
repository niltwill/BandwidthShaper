#ifndef ARGS_PARSER_H
#define ARGS_PARSER_H

// args_parser.h
// CLI argument and INI config-file parsing for BandwidthShaper.
//
// Callers fill a ParsedArgs struct by calling:
//   1.  parse_args()       – process argc/argv
//   2.  load_config_file() – apply an INI file on top (config overrides CLI)
//
// Both functions write into the same ParsedArgs so the final merged state
// is always in one place. cli_main.c then hands the result to the core.

#include "common.h"
#include "shaper_utils.h"
#include "shaper_core.h"
#include "schedule.h"

// -----------------------------------------------------------------------
// Aggregated, caller-owned result of parse_args + load_config_file
// -----------------------------------------------------------------------

typedef struct ParsedArgs {
    // rate limits
    double download_rate;
    double upload_rate;

    // buffers
    unsigned int download_buffer_size;
    unsigned int upload_buffer_size;

    // connection limits
    unsigned int max_tcp_connections;
    unsigned int max_udp_packets_per_second;

    // simulation
    unsigned int latency_ms;
    float        packet_loss;

    // WinDivert priority
    int priority;

    // burst size
    int burst_size;

    // data cap
    uint64_t data_cap_bytes;

    // NIC / per-NIC limits
    ThrottlingParams throttling;

    // process / PID filtering
    ProcessParams process;

    // behaviour flags
    bool quiet_mode;
    bool enable_statistics;

    // Per-process rules
    // Each entry covers rate limits, optional per-process data quotas, and an
    // optional schedule window.  All three may be set on the same identifier.
    struct RuleEntry {
        char identifier[MAX_PROCESS_NAME_LEN];
        double dl_rate;           // bytes/sec; 0 = no rate limit
        double ul_rate;           // bytes/sec; 0 = no rate limit
        uint64_t quota_in;        // bytes; 0 = no inbound cap  (-S / --stop-at)
        uint64_t quota_out;       // bytes; 0 = no outbound cap (-S / --stop-at)
        Schedule schedule;        // active window; empty = always active (-T / --schedule)
        struct RuleEntry *next;
    } *rules_head;

    // Global schedule (-T before any per-process target)
    // Applied when --schedule appears without a preceding per-process target.
    Schedule global_schedule;

    // quota/schedule check interval
    unsigned int quota_check_interval_ms;

    // config file path
    char *config_path;

    // early-exit flag
    bool early_exit;
} ParsedArgs;

// -----------------------------------------------------------------------
// Initialise / release
// -----------------------------------------------------------------------

// Zero-initialise a ParsedArgs and fill in defaults.
void parsed_args_init(ParsedArgs *args);

// Free all heap memory owned by ParsedArgs (process_list, rule list, etc.).
// Does NOT free config_path (it points into argv).
void parsed_args_free(ParsedArgs *args);

// -----------------------------------------------------------------------
// Primary parsing entry points
// -----------------------------------------------------------------------

// Parse argc/argv into *args.
// Returns false on a fatal error (unknown flag, invalid value, etc.).
// Sets args->early_exit = true for --help / --version / --list-nics.
bool parse_args(int argc, char **argv, ParsedArgs *args);

// Load an INI-style config file and apply its values on top of *args.
// Config values override whatever parse_args() already set.
// Returns false if the file cannot be opened or contains a bad value.
bool load_config_file(const char *path, ParsedArgs *args);

// -----------------------------------------------------------------------
// Help / version
// -----------------------------------------------------------------------

// Print usage to stdout.
void print_help(const char *program_path);

// Print version string to stdout.
void print_version(void);

#endif // ARGS_PARSER_H
