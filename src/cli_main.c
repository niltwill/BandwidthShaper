// cli_main.c
// BandwidthShaper CLI entry point.
//
// Responsibilities:
//   - Register the Ctrl+C handler
//   - Call parse_args() + load_config_file()
//   - Validate parsed values before handing them to the core
//   - Print the startup summary for the user
//   - Start the shaper core and run the packet loop
//   - Handle 'Q' (quit) and 'R' (hot-reload) keyboard shortcuts
//   - Clean up and exit
//
// This file deliberately contains no packet processing, no WinDivert
// calls, and no token-bucket logic.  All of that lives in shaper_core.c.

#include "cli_main.h"
#include "args_parser.h"
#include "shaper_core.h"
#include "shaper_utils.h"
#include "schedule.h"

// -----------------------------------------------------------------------
// Shared quit flag
// Set atomically by console_ctrl_handler() and checked by the loop.
// -----------------------------------------------------------------------
static volatile LONG g_quit_flag = 0;

// -----------------------------------------------------------------------
// Ctrl+C / console-event handler
// Must be async-signal-safe: no printf, malloc, Sleep, or locks.
// -----------------------------------------------------------------------
BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            InterlockedExchange(&g_quit_flag, 1);
            return TRUE;
        default:
            return FALSE;
    }
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

// Print the "now active" summary that the user sees at startup.
static void print_startup_summary(const ParsedArgs *args) {
    if (args->quiet_mode) return;

    // Priority label
    int p = args->priority;
    const char *plabel =
        (p == 30000)               ? " (highest)" :
        (p > 15000)                ? " (high)"    :
        (p >= 0 && p <= 14999)     ? " (normal)"  :
        (p >= -15000)              ? " (low)"      :
                                     " (lowest)";
    printf("Priority: %d%s\n", p, plabel);

    // NIC list
    printf("Bandwidth throttled on NIC index: ");
    for (unsigned int i = 0; i < args->throttling.nic_count; i++) {
        if (i > 0) printf(", ");
        printf("%u", args->throttling.nic_indices[i]);
    }
    printf("\n");

    if (args->data_cap_bytes > 0)
        printf("Data cap: %.2f GB (internet disabled when reached)\n",
               args->data_cap_bytes / 1e9);

    if (args->download_rate > 0) {
        print_rate_with_units("Download limit", args->download_rate);
        printf("Max download buffer size: %u bytes\n", args->download_buffer_size);
    }
    if (args->upload_rate > 0) {
        print_rate_with_units("Upload limit", args->upload_rate);
        printf("Max upload buffer size: %u bytes\n", args->upload_buffer_size);
    }
    if (args->burst_size > 0)
        printf("Burst size: %d bytes (overrides buffer size)\n", args->burst_size);
    if (args->max_tcp_connections > 0)
        printf("Max TCP connections: %u\n", args->max_tcp_connections);
    if (args->max_udp_packets_per_second > 0)
        printf("Max UDP packets/sec: %u\n", args->max_udp_packets_per_second);
    if (args->latency_ms > 0)
        printf("Simulated latency: %u ms\n", args->latency_ms);
    if (args->packet_loss > 0.0f)
        printf("Simulated packet loss: %.2f%%\n", args->packet_loss);

    // Per-process rules (rates + quotas + schedules)
    if (args->rules_head) {
        printf("\nPer-process rules:\n");
        for (struct RuleEntry *e = args->rules_head; e; e = e->next) {
            printf("  [%s]", e->identifier);
            if (e->dl_rate > 0) {
                double r = e->dl_rate;
                if      (r >= 1e9) printf("  DL: %.2f GB/s", r / 1e9);
                else if (r >= 1e6) printf("  DL: %.2f MB/s", r / 1e6);
                else if (r >= 1e3) printf("  DL: %.2f KB/s", r / 1e3);
                else               printf("  DL: %.0f B/s",  r);
            }
            if (e->ul_rate > 0) {
                double r = e->ul_rate;
                if      (r >= 1e9) printf("  UL: %.2f GB/s", r / 1e9);
                else if (r >= 1e6) printf("  UL: %.2f MB/s", r / 1e6);
                else if (r >= 1e3) printf("  UL: %.2f KB/s", r / 1e3);
                else               printf("  UL: %.0f B/s",  r);
            }
            if (e->quota_in  > 0) printf("  Quota-in: %.2f MB",  e->quota_in  / 1e6);
            if (e->quota_out > 0) printf("  Quota-out: %.2f MB", e->quota_out / 1e6);
            if (!schedule_is_empty(&e->schedule)) {
                wchar_t sched_buf[64];
                schedule_describe(&e->schedule, sched_buf, _countof(sched_buf));
                printf("  Schedule: %ls", sched_buf);
            }
            printf("\n");
        }
    }

    // Global schedule (applies to -p / -z targets and global rate limits)
    if (!schedule_is_empty(&args->global_schedule)) {
        wchar_t sched_buf[64];
        schedule_describe(&args->global_schedule, sched_buf, _countof(sched_buf));
        printf("\nGlobal schedule: %ls\n", sched_buf);
        printf("  (all rules suspended outside this window)\n");
    }

    printf("\nPress 'Q' or Ctrl+C to quit.  Press 'R' to reload configuration.\n");
}

// Validate ParsedArgs before WinDivert
// Returns true if everything looks sane
static bool validate_args(const ParsedArgs *args) {
    if (args->download_rate < 0 || args->upload_rate < 0) {
        fprintf(stderr, "Error: Download/Upload rate must not be negative.\n");
        return false;
    }
    if (args->packet_loss < 0.0f || args->packet_loss > 100.0f) {
        fprintf(stderr, "Error: Packet loss must be between 0 and 100.\n");
        return false;
    }
    if (args->throttling.nic_count == 0) {
        fprintf(stderr, "Error: You must specify at least one NIC with --nic.\n");
        return false;
    }
    if (!is_admin()) {
        fprintf(stderr,
            "Error: Administrator privileges required.\n"
            "       Please relaunch from an elevated command prompt.\n");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------
// sync_rules_to_shaper
// Schedule + quota enforcement sync
// - Checks traffic against quotas using shaper_get_process_traffic_by_name()
// - Automatically removes rules when quotas are exceeded
// - Logs quota breaches: "[quota] Process 'X' reached limit: IN 500.00/500.00 MB"
// -----------------------------------------------------------------------
static void sync_rules_to_shaper(ShaperInstance         *shaper,
                                    struct RuleEntry *const rules_list,
                                    bool                    quiet_mode) {
    if (!shaper || !rules_list) return;

    int added = 0, removed = 0, quota_stopped = 0;

    for (struct RuleEntry *e = rules_list; e; e = e->next) {
        bool should_be_active = schedule_is_empty(&e->schedule) || 
                                schedule_is_active_now(&e->schedule);
        bool exists = shaper_has_process_rule(shaper, e->identifier);

        // Check quota status if rule exists and has quotas
        bool quota_breached = false;
        if (exists && (e->quota_in > 0 || e->quota_out > 0)) {
            uint64_t total_dl = 0, total_ul = 0;
            if (shaper_get_process_traffic_by_name(shaper, e->identifier, &total_dl, &total_ul)) {
                if ((e->quota_in > 0 && total_dl >= e->quota_in) ||
                    (e->quota_out > 0 && total_ul >= e->quota_out)) {
                    quota_breached = true;

                    // Get current quota state to avoid duplicate logging
                    uint64_t qi, qo;
                    bool in_reached, out_reached;
                    if (shaper_get_process_quota(shaper, e->identifier, &qi, &qo, &in_reached, &out_reached)) {
                        if (!in_reached && !out_reached) {
                            // First time detecting breach
                            if (!quiet_mode) {
                                printf("[quota] Process '%s' reached limit: ", e->identifier);
                                if (e->quota_in > 0 && total_dl >= e->quota_in)
                                    printf("IN %.2f/%.2f MB ", total_dl/1e6, e->quota_in/1e6);
                                if (e->quota_out > 0 && total_ul >= e->quota_out)
                                    printf("OUT %.2f/%.2f MB", total_ul/1e6, e->quota_out/1e6);
                                printf(" - removing rule\n");
                            }
                        }
                    }
                }
            }
        }

        if (should_be_active && !quota_breached) {
            if (!exists) {
                bool blocked = (e->dl_rate == 0.0 && e->ul_rate == 0.0);
                if (shaper_add_process_rule(shaper, e->identifier, e->dl_rate, e->ul_rate,
                                            blocked, blocked, e->quota_in, e->quota_out, &e->schedule)) {
                    shaper_set_process_quota(shaper, e->identifier, e->quota_in, e->quota_out);
                    added++;
                }
            }
        } else {
            if (exists) {
                if (shaper_remove_process_rule(shaper, e->identifier)) {
                    removed++;
                    if (quota_breached) quota_stopped++;
                }
            }
        }
    }

    if (added > 0 || removed > 0) {
        shaper_reload_rules(shaper);
        if (!quiet_mode && (added > 0 || removed > 0 || quota_stopped > 0)) {
            printf("[schedule] Synced: %d added, %d removed", added, removed);
            if (quota_stopped > 0) printf(" (%d quota-exceeded)", quota_stopped);
            printf("\n");
        }
    }
}

// Apply all --rule / --stop-at entries from ParsedArgs to the shaper at startup.
// Mirrors the add-path in sync_rules_to_shaper so initial state is consistent.
static bool register_rules(ShaperInstance *shaper, const ParsedArgs *args) {
    for (struct RuleEntry *e = args->rules_head; e; e = e->next) {
        // Skip entries whose schedule window isn't open yet; the 30 s check will add them.
        if (!schedule_is_empty(&e->schedule) && !schedule_is_active_now(&e->schedule))
            continue;

        // A quota-only entry (no rate limits) is registered as blocked so traffic
        // is intercepted and counted; shaper_set_process_quota then sets the cap.
        bool blocked = (e->dl_rate == 0.0 && e->ul_rate == 0.0 &&
                        (e->quota_in > 0 || e->quota_out > 0));

        if (!shaper_add_process_rule(shaper, e->identifier,
                                     e->dl_rate, e->ul_rate,
                                     blocked, blocked, e->quota_in, e->quota_out, &e->schedule)) {
            fprintf(stderr, "Error: failed to register rule for '%s'\n", e->identifier);
            return false;
        }
        // Set per-process quotas if specified via -S / --stop-at
        if (e->quota_in > 0 || e->quota_out > 0) {
            shaper_set_process_quota(shaper, e->identifier, e->quota_in, e->quota_out);
        }
    }
    return true;
}

// Perform a hot-reload: re-parse, re-validate, hand new config to the core.
// Returns false on any error (caller should stop the shaper and exit).
static bool do_hot_reload(ShaperInstance *shaper,
                          int argc, char **argv,
                          const char *config_path,  // may be NULL
                          bool quiet_mode) {
    if (!quiet_mode) printf("\nHot-reloading configuration...\n");

    ParsedArgs new_args;
    parsed_args_init(&new_args);

    if (!parse_args(argc, argv, &new_args)) {
        fprintf(stderr, "Reload failed: argument parsing error.\n");
        parsed_args_free(&new_args);
        return false;
    }

    // Re-apply config file on top (same path as original invocation)
    if (config_path) {
        if (!load_config_file(config_path, &new_args)) {
            fprintf(stderr, "Warning: config file reload failed; using CLI values.\n");
        }
    }

    if (!validate_args(&new_args)) {
        parsed_args_free(&new_args);
        return false;
    }

    // Re-register rules on the core before calling reload
    shaper_clear_process_rules(shaper);
    if (!register_rules(shaper, &new_args)) {
        parsed_args_free(&new_args);
        return false;
    }

    bool ok = shaper_reload(shaper,
                            &new_args.throttling,
                            &new_args.process,
                            new_args.download_rate,
                            new_args.upload_rate,
                            new_args.download_buffer_size,
                            new_args.upload_buffer_size,
                            new_args.max_tcp_connections,
                            new_args.max_udp_packets_per_second,
                            new_args.latency_ms,
                            new_args.packet_loss,
                            new_args.priority,
                            new_args.burst_size,
                            new_args.data_cap_bytes,
                            new_args.quota_check_interval_ms,
                            &new_args.global_schedule,
                            new_args.quiet_mode,
                            new_args.enable_statistics);

    if (!ok) {
        fprintf(stderr, "Reload failed: %s\n", shaper_get_last_error(shaper));
    } else if (!quiet_mode) {
        print_startup_summary(&new_args);
    }

    parsed_args_free(&new_args);
    return ok;
}

// -----------------------------------------------------------------------
// cli_run - the full CLI lifecycle
// -----------------------------------------------------------------------

int cli_run(int argc, char **argv) {
    // Rules list transferred from args before free; always NULL-initialised
    // so the cleanup path can unconditionally walk-and-free it.
    struct RuleEntry *rules_list = NULL;
    // ------------------------------------------------------------------
    // 1. Ctrl+C handler
    // ------------------------------------------------------------------
    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        fprintf(stderr, "Failed to register console control handler.\n");
        return EXIT_FAILURE;
    }

    // ------------------------------------------------------------------
    // 2. Winsock
    // ------------------------------------------------------------------
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return EXIT_FAILURE;
    }

    int exit_code = EXIT_SUCCESS;

    // ------------------------------------------------------------------
    // 3. Parse CLI arguments
    // ------------------------------------------------------------------
    // Show help when invoked with no arguments.
    if (argc == 1) {
        print_help(argv[0]);
        WSACleanup();
        return EXIT_SUCCESS;
    }

    ParsedArgs args;
    parsed_args_init(&args);

    if (!parse_args(argc, argv, &args)) {
        parsed_args_free(&args);
        WSACleanup();
        return EXIT_FAILURE;
    }

    // Terminal options (--help, --version, --list-nics) were already
    // handled inside parse_args(); args.early_exit tells us to stop here.
    if (args.early_exit) {
        parsed_args_free(&args);
        WSACleanup();
        return EXIT_SUCCESS;
    }

    // ------------------------------------------------------------------
    // 4. Load config file (overrides CLI values)
    // ------------------------------------------------------------------
    if (args.config_path) {
        if (!args.quiet_mode)
            printf("Loading configuration from: %s\n", args.config_path);

        if (!load_config_file(args.config_path, &args)) {
            fprintf(stderr, "Warning: config file failed to load; using CLI values.\n");
        } else if (!args.quiet_mode) {
            printf("Configuration loaded successfully.\n");
        }
    }

    // Save original argv for hot-reload (original code had this wired up
    // to g_original_argc / g_original_argv but never actually assigned them).
    // We keep them as locals; do_hot_reload() receives them by parameter.
    int original_argc = argc;
    char **original_argv = argv;
    const char *config_path = args.config_path; // points into argv, safe lifetime

    // ------------------------------------------------------------------
    // 5. Validate merged configuration
    // ------------------------------------------------------------------
    if (!validate_args(&args)) {
        exit_code = EXIT_FAILURE;
        goto cleanup_args;
    }

    // ------------------------------------------------------------------
    // 6. Create and configure the shaper instance
    // ------------------------------------------------------------------
    ShaperInstance *shaper = shaper_create();
    if (!shaper) {
        fprintf(stderr, "Failed to allocate shaper instance.\n");
        exit_code = EXIT_FAILURE;
        goto cleanup_args;
    }

    // Register per-process rules collected during parsing
    if (!register_rules(shaper, &args)) {
        exit_code = EXIT_FAILURE;
        goto cleanup_shaper;
    }

    // ------------------------------------------------------------------
    // 7. Start the core (worker thread spawned internally)
    // ------------------------------------------------------------------
    if (!shaper_start(shaper,
                      &args.throttling,
                      &args.process,
                      args.download_rate,
                      args.upload_rate,
                      args.download_buffer_size,
                      args.upload_buffer_size,
                      args.max_tcp_connections,
                      args.max_udp_packets_per_second,
                      args.latency_ms,
                      args.packet_loss,
                      args.priority,
                      args.burst_size,
                      args.data_cap_bytes,
                      args.quota_check_interval_ms,
                      &args.global_schedule,
                      args.quiet_mode,
                      args.enable_statistics)) {
        fprintf(stderr, "Failed to start: %s\n", shaper_get_last_error(shaper));
        exit_code = EXIT_FAILURE;
        goto cleanup_shaper;
    }

    // Capture fields needed by the main loop before potentially freeing args.
    bool quiet_mode = args.quiet_mode;
    Schedule global_schedule = args.global_schedule;   // value copy

    // Print summary before transferring rules_list
    print_startup_summary(&args);

    // Transfer ownership of the rules list from args to rules_list.
    // After this point, args.rules_head is NULL and rules_list owns the list.
    // If we never reach this point (e.g., shaper_start fails), args still owns
    // the list and parsed_args_free will clean it up in the error path.
    rules_list = args.rules_head;
    args.rules_head = NULL;
    bool args_needs_cleanup = false;  // args no longer need cleanup

    parsed_args_free(&args);  // Free what's left (non-rule fields)

    // ------------------------------------------------------------------
    // 8. Main thread: wait for quit signal, keyboard, or thread death.
    // ------------------------------------------------------------------
    bool reload_pending = false;
    bool quit_pending = false;
    DWORD last_schedule_tick = GetTickCount();
    DWORD quota_check_interval = args.quota_check_interval_ms;
    static bool was_inside_global = true;      // Track global schedule state
    static bool first_global_check = true;     // First-run flag

    while (shaper_get_thread_state(shaper) == SHAPER_THREAD_RUNNING) {
        // Check Ctrl+C
        if (InterlockedCompareExchange(&g_quit_flag, 0, 1) == 1) {
            if (!quiet_mode) printf("Stopping...\n");
            shaper_stop(shaper);
            break;
        }

        // Check keyboard
        HWND hwnd = GetConsoleWindow();
        if (hwnd && GetForegroundWindow() == hwnd) {
            // Q - quit (debounced)
            if ((GetAsyncKeyState('Q') & 0x8000) && !quit_pending) {
                quit_pending = true;
                if (!quiet_mode) printf("Exiting...\n");
                shaper_stop(shaper);
                break;
            }
            if (!(GetAsyncKeyState('Q') & 0x8000)) {
                quit_pending = false;
            }

            // R - reload (debounced)
            if ((GetAsyncKeyState('R') & 0x8000) && !reload_pending) {
                reload_pending = true;
                if (!do_hot_reload(shaper, original_argc, original_argv,
                                   config_path, quiet_mode)) {
                    fprintf(stderr, "Reload failed - stopping.\n");
                    shaper_stop(shaper);
                    exit_code = EXIT_FAILURE;
                    break;
                }
            }
            if (!(GetAsyncKeyState('R') & 0x8000)) {
                reload_pending = false;
            }
        }

        // Schedule + quota check
        DWORD now_tick = GetTickCount();
        if ((DWORD)(now_tick - last_schedule_tick) >= quota_check_interval) {
            last_schedule_tick = now_tick;
            bool need_sync = false;

            if (rules_list) {
                // Check for quotas or schedules
                for (struct RuleEntry *e = rules_list; e; e = e->next) {
                    if (e->quota_in > 0 || e->quota_out > 0 ||
                        !schedule_is_empty(&e->schedule)) {
                        need_sync = true;
                        break;
                    }
                }

                // Global schedule transitions
                if (!schedule_is_empty(&global_schedule)) {
                    // Initialize on first run
                    if (first_global_check) {
                        was_inside_global = schedule_is_active_now(&global_schedule);
                        first_global_check = false;
                    }

                    bool inside = schedule_is_active_now(&global_schedule);
                    if (inside != was_inside_global) {
                        was_inside_global = inside;
                        need_sync = true;
                        if (!quiet_mode) {
                            wchar_t buf[64];
                            schedule_describe(&global_schedule, buf, _countof(buf));
                            printf("[schedule] Global window (%ls) %s.\n", buf,
                                   inside ? "entered - rules active"
                                          : "exited - all rules suspended");
                        }
                    }
                }
            }

            if (need_sync)
                sync_rules_to_shaper(shaper, rules_list, quiet_mode);
        }

        Sleep(100);
    }

    // ------------------------------------------------------------------
    // 9. Teardown
    // ------------------------------------------------------------------
    if (shaper_is_running(shaper)) {
        shaper_stop(shaper);
    }
    stop_windivert();

    cleanup_shaper:
        shaper_destroy(shaper);

    cleanup_args:
        // Free the transferred rules list
        {
            struct RuleEntry *e = rules_list;
            while (e) { 
                struct RuleEntry *nx = e->next; 
                free(e); 
                e = nx; 
            }
        }

    // Only free args if it still needs cleanup (error path)
    if (args_needs_cleanup) {
        parsed_args_free(&args);
    }

    WSACleanup();
    return exit_code;

}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------

int main(int argc, char **argv) {
    return cli_run(argc, argv);
}
