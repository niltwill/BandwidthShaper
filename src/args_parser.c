// args_parser.c
// CLI argument and INI config-file parsing for BandwidthShaper.
// See args_parser.h for the public API.

#include "args_parser.h"
#include "shaper_utils.h"
#include "schedule.h"
#include "localization_api.h"

// -----------------------------------------------------------------------
// ParsedArgs lifecycle
// -----------------------------------------------------------------------

void parsed_args_init(ParsedArgs *args) {
    memset(args, 0, sizeof(*args));
    args->download_buffer_size = DEFAULT_DL_BUFFER;
    args->upload_buffer_size = DEFAULT_UL_BUFFER;
    args->process.min_update_interval_ms = STATS_UPDATE_INTERVAL;
    args->process.last_update_time = clock();
    args->quota_check_interval_ms = QUOTA_CHECK_INTERVAL;
    args->stats_interval_ms = STATS_UPDATE_INTERVAL;
}

void parsed_args_free(ParsedArgs *args) {
    if (!args) return;

    // Free NIC arrays
    free(args->throttling.nic_indices);
    free(args->throttling.download_limits);
    free(args->throttling.upload_limits);
    args->throttling.nic_indices = NULL;
    args->throttling.download_limits = NULL;
    args->throttling.upload_limits = NULL;

    // Free process filter state
    free(args->process.process_list);
    free_pid_map_pool(args->process.pid_map, &g_pid_pool);
    args->process.process_list = NULL;
    args->process.pid_map = NULL;

    // Free rule entries
    struct RuleEntry *entry = args->rules_head;
    while (entry) {
        struct RuleEntry *next = entry->next;
        free(entry);
        entry = next;
    }
    args->rules_head = NULL;
}

// -----------------------------------------------------------------------
// Internal: append a rule to the linked list
// -----------------------------------------------------------------------

static bool append_rule(ParsedArgs *args, const char *identifier,
                        double dl_rate, double ul_rate,
                        uint64_t quota_in, uint64_t quota_out,
                        const Schedule *schedule) {
    struct RuleEntry *e = malloc(sizeof(struct RuleEntry));
    if (!e) { fprintf(stderr, C(CLI_OOM_RULE)); return false; }

    strncpy(e->identifier, identifier, sizeof(e->identifier) - 1);
    e->identifier[sizeof(e->identifier) - 1] = '\0';
    e->dl_rate = dl_rate;
    e->ul_rate = ul_rate;
    e->quota_in = quota_in;
    e->quota_out = quota_out;
    e->quota_breach_logged = false;
    if (schedule) e->schedule = *schedule;
    else          schedule_init(&e->schedule);
    e->next = NULL;

    // Append to tail (walk the list)
    if (!args->rules_head) {
        args->rules_head = e;
    } else {
        struct RuleEntry *cur = args->rules_head;
        while (cur->next) cur = cur->next;
        cur->next = e;
    }
    return true;
}

// -----------------------------------------------------------------------
// Internal: parse a --rule / --pid-rule token string
// Format: "identifier DL_RATE UL_RATE" (space-separated parts per token)
// Multiple rules can be comma-separated in one --rule argument.
// -----------------------------------------------------------------------

static bool parse_rule_string(const char *rules_str, ParsedArgs *args) {
    char *copy = strdup(rules_str);
    if (!copy) { fprintf(stderr, C(CLI_OOM_RULE_STRING)); return false; }

    bool ok = true;
    char *outer_ctx = NULL;
    char *tok = strtok_s(copy, ",", &outer_ctx);
    while (tok) {
        while (isspace((unsigned char)*tok)) tok++;
        char *end = tok + strlen(tok) - 1;
        while (end >= tok && isspace((unsigned char)*end)) *end-- = '\0';

        char *inner_ctx = NULL;
        char *identifier = strtok_s(tok, " \t", &inner_ctx);
        char *dl_str = strtok_s(NULL, " \t", &inner_ctx);
        char *ul_str = strtok_s(NULL, " \t", &inner_ctx);
        char *extra = strtok_s(NULL, " \t", &inner_ctx);

        if (!identifier || !dl_str || !ul_str || extra) {
            fprintf(stderr, C(CLI_ERR_RULE_FORMAT), tok);
            ok = false;
        } else {
            double dl = parse_rate_with_units(dl_str);
            double ul = parse_rate_with_units(ul_str);
            if (!append_rule(args, identifier, dl, ul, 0, 0, NULL)) ok = false;
        }

        tok = strtok_s(NULL, ",", &outer_ctx);
    }

    free(copy);
    return ok;
}

// -----------------------------------------------------------------------
// parse_args
// -----------------------------------------------------------------------

bool parse_args(int argc, char **argv, ParsedArgs *args) {
    for (int i = 1; i < argc; i++) {

#define NEXT_ARG(flag) \
        do { \
            if (i + 1 >= argc) { \
                fprintf(stderr, C(CLI_ERR_ARG_REQUIRES), flag); \
                return false; \
            } \
            i++; \
        } while (0)

        if ((strcmp(argv[i], "--download") == 0 || strcmp(argv[i], "-d") == 0)) {
            NEXT_ARG("--download");
            args->download_rate = parse_rate_with_units(argv[i]);

        } else if ((strcmp(argv[i], "--upload") == 0 || strcmp(argv[i], "-u") == 0)) {
            NEXT_ARG("--upload");
            args->upload_rate = parse_rate_with_units(argv[i]);

        } else if ((strcmp(argv[i], "--download-buffer") == 0 || strcmp(argv[i], "-D") == 0)) {
            NEXT_ARG("--download-buffer");
            args->download_buffer_size = (unsigned int)atoi(argv[i]);

        } else if ((strcmp(argv[i], "--upload-buffer") == 0 || strcmp(argv[i], "-U") == 0)) {
            NEXT_ARG("--upload-buffer");
            args->upload_buffer_size = (unsigned int)atoi(argv[i]);

        } else if ((strcmp(argv[i], "--tcp-limit") == 0 || strcmp(argv[i], "-t") == 0)) {
            NEXT_ARG("--tcp-limit");
            args->max_tcp_connections = (unsigned int)atoi(argv[i]);

        } else if ((strcmp(argv[i], "--udp-limit") == 0 || strcmp(argv[i], "-r") == 0)) {
            NEXT_ARG("--udp-limit");
            args->max_udp_packets_per_second = (unsigned int)atoi(argv[i]);

        } else if ((strcmp(argv[i], "--process") == 0 || strcmp(argv[i], "-p") == 0)) {
            NEXT_ARG("--process");
            free(args->process.process_list);
            args->process.process_list = strdup(argv[i]);
            if (!args->process.process_list) {
                fprintf(stderr, C(CLI_OOM_PROCESS_LIST)); return false;
            }

        } else if ((strcmp(argv[i], "--pid") == 0 || strcmp(argv[i], "-z") == 0)) {
            NEXT_ARG("--pid");
            char *tok = strtok(argv[i], ",");
            while (tok) {
                int pid = atoi(tok);
                if (pid > 0) add_pid_to_map_pool(&args->process.pid_map, pid, &g_pid_pool);
                tok = strtok(NULL, ",");
            }

        } else if ((strcmp(argv[i], "--rule") == 0 || strcmp(argv[i], "-c") == 0)) {
            NEXT_ARG("--rule");
            if (!parse_rule_string(argv[i], args)) return false;

        } else if ((strcmp(argv[i], "--burst") == 0 || strcmp(argv[i], "-b") == 0)) {
            NEXT_ARG("--burst");
            args->burst_size = (int)parse_rate_with_units(argv[i]);
            if (args->burst_size <= 0) {
                fprintf(stderr, C(CLI_ERR_BURST_POSITIVE));
                args->burst_size = 0;
            }

        } else if ((strcmp(argv[i], "--disable-after") == 0 || strcmp(argv[i], "-a") == 0)) {
            NEXT_ARG("--disable-after");
            char   *endptr;
            double  value = strtod(argv[i], &endptr);
            if (value <= 0) {
                fprintf(stderr, C(CLI_ERR_DISABLE_AFTER_POS));
            } else if (*endptr != '\0') {
                if      (_stricmp(endptr, "GB") == 0) args->data_cap_bytes = (uint64_t)(value * 1e9);
                else if (_stricmp(endptr, "MB") == 0) args->data_cap_bytes = (uint64_t)(value * 1e6);
                else if (_stricmp(endptr, "KB") == 0) args->data_cap_bytes = (uint64_t)(value * 1e3);
                else    fprintf(stderr, C(CLI_ERR_DISABLE_AFTER_UNIT));
            } else {
                args->data_cap_bytes = (uint64_t)(value * 1e9); // default: GB
            }

        } else if ((strcmp(argv[i], "--process-update-interval") == 0 || strcmp(argv[i], "-i") == 0)) {
            NEXT_ARG("--process-update-interval");
            if (parse_process_update_interval(argv[i], &args->process) != 0) {
                print_help(argv[0]);
                return false;
            }

        } else if ((strcmp(argv[i], "--priority") == 0 || strcmp(argv[i], "-P") == 0)) {
            NEXT_ARG("--priority");
            args->priority = atoi(argv[i]);
            if (args->priority < WINDIVERT_PRIORITY_LOWEST ||
                args->priority > WINDIVERT_PRIORITY_HIGHEST) {
                fprintf(stderr, C(CLI_ERR_PRIORITY_RANGE),
                        WINDIVERT_PRIORITY_LOWEST, WINDIVERT_PRIORITY_HIGHEST);
                return false;
            }

        } else if ((strcmp(argv[i], "--latency") == 0 || strcmp(argv[i], "-L") == 0)) {
            NEXT_ARG("--latency");
            args->latency_ms = (unsigned int)atoi(argv[i]);

        } else if ((strcmp(argv[i], "--packet-loss") == 0 || strcmp(argv[i], "-m") == 0)) {
            NEXT_ARG("--packet-loss");
            args->packet_loss = (float)atof(argv[i]);

        } else if ((strcmp(argv[i], "--nic") == 0 || strcmp(argv[i], "-n") == 0)) {
            NEXT_ARG("--nic");
            args->throttling.nic_indices = parse_nic_indices(argv[i], &args->throttling);
            if (!args->throttling.nic_indices) {
                fprintf(stderr, C(CLI_ERR_NIC_PARSE));
                return false;
            }

        } else if ((strcmp(argv[i], "--list-nics") == 0 || strcmp(argv[i], "-A") == 0)) {
            list_network_interfaces();
            args->early_exit = true;
            return true;

        } else if ((strcmp(argv[i], "--lang") == 0 || strcmp(argv[i], "-l") == 0)) {
            NEXT_ARG("--lang");
            if (_stricmp(argv[i], "en") == 0 || _stricmp(argv[i], "english") == 0) {
                loc_set_language(LOC_LANG_EN);
            } else if (_stricmp(argv[i], "hu") == 0 || _stricmp(argv[i], "hungarian") == 0) {
                loc_set_language(LOC_LANG_HU);
            } else {
                fprintf(stderr, C(CLI_ERR_UNKNOWN_ARG), argv[i]);
                print_help(argv[0]);
                return false;
            }

        } else if ((strcmp(argv[i], "--statistics") == 0 || strcmp(argv[i], "-s") == 0)) {
            args->enable_statistics = true;

        } else if ((strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0)) {
            args->quiet_mode = true;

        } else if ((strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0)) {
            print_version();
            args->early_exit = true;
            return true;

        } else if ((strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)) {
            print_help(argv[0]);
            args->early_exit = true;
            return true;

        } else if ((strcmp(argv[i], "--stop-at") == 0 || strcmp(argv[i], "-S") == 0)) {
            // -S <process|PID> <QUOTA_IN> <QUOTA_OUT>
            // Registers a per-process data cap.  When the process's cumulative
            // inbound or outbound traffic reaches the cap, its rules are removed.
            // Uses the same rate-with-units parser as -d/-u so "1GB", "500MB" etc. work.
            if (i + 3 >= argc) {
                fprintf(stderr, C(CLI_ERR_STOP_AT_ARGS));
                return false;
            }
            const char *identifier = argv[++i];
            uint64_t qi = (uint64_t)parse_rate_with_units(argv[++i]);
            uint64_t qo = (uint64_t)parse_rate_with_units(argv[++i]);
            if (!append_rule(args, identifier, 0.0, 0.0, qi, qo, NULL)) return false;

        } else if ((strcmp(argv[i], "--schedule") == 0 || strcmp(argv[i], "-T") == 0)) {
            // -T <HHMM-HHMM~days>
            // Stamps a schedule onto the most recently parsed per-process target
            // (-c / -S -> last RuleEntry; -p / -z / none -> global_schedule).
            // Examples:
            //   -T 0800-1800         (time window, any day)
            //   -T ~1-5              (Mon-Fri, any time)
            //   -T 0800-1800~1-5     (Mon-Fri, 08:00-18:00)
            //   -T 2200-0600~6,7     (overnight Sat-Sun)
            NEXT_ARG("--schedule");
            Schedule sched;
            schedule_init(&sched);
            if (!schedule_parse(argv[i], &sched)) {
                fprintf(stderr, C(CLI_ERR_SCHEDULE_FORMAT), argv[i]);
                return false;
            }
            // Stamp onto last RuleEntry if one exists, otherwise set global schedule
            if (args->rules_head) {
                struct RuleEntry *last = args->rules_head;
                while (last->next) last = last->next;
                last->schedule = sched;
            } else {
                args->global_schedule = sched;
            }

        } else if ((strcmp(argv[i], "--quota-check-interval") == 0 || 
                    strcmp(argv[i], "-Q") == 0)) {
            NEXT_ARG("--quota-check-interval");
            args->quota_check_interval_ms = (unsigned int)atoi(argv[i]);
            if (args->quota_check_interval_ms < 1000) {
                fprintf(stderr, C(CLI_WARN_QUOTA_INTERVAL),
                        args->quota_check_interval_ms);
            }

        } else if ((strcmp(argv[i], "--stats-interval") == 0 || 
                    strcmp(argv[i], "-I") == 0)) {
            NEXT_ARG("--stats-interval");
            args->stats_interval_ms = (unsigned int)atoi(argv[i]);
            if (args->stats_interval_ms < 500) {
                fprintf(stderr, C(CLI_WARN_STATS_INTERVAL),
                        args->stats_interval_ms);
                args->stats_interval_ms = 500;
            }

        } else if ((strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-C") == 0)) {
            NEXT_ARG("--config");
            args->config_path = argv[i]; // points into argv - not owned

        } else {
            fprintf(stderr, C(CLI_ERR_UNKNOWN_ARG), argv[i]);
            print_help(argv[0]);
            return false;
        }

#undef NEXT_ARG
    }
    return true;
}

// -----------------------------------------------------------------------
// Config-file: line parser with multi-line continuation support
// -----------------------------------------------------------------------

// State is held in local statics so the function is not re-entrant, but
// that is fine - config files are always parsed sequentially on one thread.
static bool parse_config_line(FILE *fp,
                               char *line, size_t line_size,
                               char *key_out,   size_t key_size,
                               char *value_out, size_t value_size,
                               bool *continued) {
    static char accumulated_value[MAX_CONFIG_VALUE_LEN * 4] = "";
    static bool in_continuation = false;
    static char pending_key[MAX_CONFIG_KEY_LEN] = "";

    *continued = false;

    if (!in_continuation) {
        accumulated_value[0] = '\0';
        pending_key[0] = '\0';
    }

    char raw_line[MAX_CONFIG_LINE_LEN];
    if (!fgets(raw_line, sizeof(raw_line), fp)) {
        // EOF - flush any partial continuation
        if (in_continuation && accumulated_value[0] != '\0') {
            strncpy(key_out, pending_key, key_size - 1); key_out[key_size - 1] = '\0';
            strncpy(value_out, accumulated_value, value_size - 1); value_out[value_size - 1] = '\0';
            in_continuation = false;
            return true;
        }
        return false;
    }

    raw_line[strcspn(raw_line, "\r\n")] = '\0';

    // Explicit backslash continuation
    size_t len = strlen(raw_line);
    bool explicit_continue = (len > 0 && raw_line[len - 1] == '\\');
    if (explicit_continue) { raw_line[--len] = '\0'; }

    char *trimmed = trim_whitespace(raw_line);

    // Skip blank lines and comments (unless continuing)
    if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
        if (in_continuation) { *continued = true; }
        return false;
    }

    char *equals = strchr(trimmed, '=');
    bool  has_key = (equals != NULL);

    if (has_key && !in_continuation) {
        // New key = value line
        size_t key_len = (size_t)(equals - trimmed);
        if (key_len >= key_size) key_len = key_size - 1;
        strncpy(key_out, trimmed, key_len); key_out[key_len] = '\0';
        trim_whitespace(key_out);

        char *value_start = equals + 1;
        while (isspace((unsigned char)*value_start)) value_start++;

        // Strip inline comment
        char *comment = strpbrk(value_start, "#;");
        if (comment) *comment = '\0';

        // Strip trailing whitespace
        char *vend = value_start + strlen(value_start) - 1;
        while (vend > value_start && isspace((unsigned char)*vend)) vend--;
        vend[1] = '\0';

        bool implicit_continue = (strlen(trimmed) > 0 &&
                                   trimmed[strlen(trimmed) - 1] == ',');

        strncpy(accumulated_value, value_start, sizeof(accumulated_value) - 1);
        accumulated_value[sizeof(accumulated_value) - 1] = '\0';
        strncpy(pending_key, key_out, sizeof(pending_key) - 1);
        pending_key[sizeof(pending_key) - 1] = '\0';

        if (explicit_continue || implicit_continue) {
            in_continuation = true; *continued = true; return false;
        }

        strncpy(value_out, accumulated_value, value_size - 1);
        value_out[value_size - 1] = '\0';
        return true;

    } else if (in_continuation) {
        // Continuation line - append to accumulated value
        char *comment = strpbrk(trimmed, "#;");
        if (comment) *comment = '\0';
        char *vend = trimmed + strlen(trimmed) - 1;
        while (vend > trimmed && isspace((unsigned char)*vend)) vend--;
        vend[1] = '\0';

        bool implicit_continue = (strlen(trimmed) > 0 &&
                                   trimmed[strlen(trimmed) - 1] == ',');

        size_t acc_len = strlen(accumulated_value);
        if (acc_len > 0 && accumulated_value[acc_len - 1] == ',') {
            strncat(accumulated_value, trimmed, sizeof(accumulated_value) - acc_len - 1);
        } else {
            size_t available = sizeof(accumulated_value) - acc_len - 1;
            if (acc_len + 1 + strlen(trimmed) < sizeof(accumulated_value)) {  // Check if we have room for space + null
                accumulated_value[acc_len] = ' ';
                accumulated_value[acc_len + 1] = '\0';
                strncat(accumulated_value, trimmed, available - 2);
            }
        }

        if (explicit_continue || implicit_continue) {
            *continued = true; return false;
        }

        strncpy(key_out, pending_key, key_size - 1); key_out[key_size - 1] = '\0';
        strncpy(value_out, accumulated_value, value_size - 1); value_out[value_size - 1] = '\0';
        in_continuation = false; accumulated_value[0] = '\0';
        return true;
    }

    return false; // Unrecognised line shape
}

// -----------------------------------------------------------------------
// Config-file: apply one key/value pair by routing through parse_args
// -----------------------------------------------------------------------

// Map INI key -> CLI flag and call parse_args with a synthetic two/three
// element argv so we reuse all the validation logic in one place.
static bool apply_config_value(const char *key, const char *value,
                                ParsedArgs *args) {
    char program_name[] = "<config>";

    // Boolean flags that take no value argument
    if (strcmp(key, "statistics") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
            strcmp(value, "yes")  == 0 || strcmp(value, "on") == 0)
            args->enable_statistics = true;
        return true;
    }
    if (strcmp(key, "quiet") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
            strcmp(value, "yes")  == 0 || strcmp(value, "on") == 0)
            args->quiet_mode = true;
        return true;
    }
    if (strcmp(key, "list-nics") == 0 || strcmp(key, "list_nics") == 0) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
            strcmp(value, "yes")  == 0 || strcmp(value, "on") == 0)
            list_network_interfaces();
        return true; // Never causes a config-load failure
    }

    // --stop-at needs special handling: the value string contains 3 space-separated parts
    if (strcmp(key, "stop-at") == 0 || strcmp(key, "stop_at") == 0) {
        char *value_copy = strdup(value);
        if (!value_copy) {
            fprintf(stderr, C(CLI_OOM_CONFIG_VAL), key);
            return false;
        }

        char *inner_ctx = NULL;
        char *identifier = strtok_s(value_copy, " \t", &inner_ctx);
        char *quota_in = strtok_s(NULL,   " \t", &inner_ctx);
        char *quota_out = strtok_s(NULL,   " \t", &inner_ctx);
        char *extra = strtok_s(NULL,   " \t", &inner_ctx);

        bool ok = true;
        if (!identifier || !quota_in || !quota_out || extra) {
            fprintf(stderr, C(CLI_ERR_STOP_AT_CONF), key);
            ok = false;
        } else {
            char *fake_argv[5] = { program_name, "--stop-at", identifier, quota_in, quota_out };
            ok = parse_args(5, fake_argv, args);
        }

        free(value_copy);
        return ok;
    }

    // Map key to CLI long flag
    const char *flag = NULL;
    if      (strcmp(key, "nic")                    == 0) flag = "--nic";
    else if (strcmp(key, "download")               == 0) flag = "--download";
    else if (strcmp(key, "upload")                 == 0) flag = "--upload";
    else if (strcmp(key, "download-buffer")        == 0 ||
             strcmp(key, "download_buffer")        == 0) flag = "--download-buffer";
    else if (strcmp(key, "upload-buffer")          == 0 ||
             strcmp(key, "upload_buffer")          == 0) flag = "--upload-buffer";
    else if (strcmp(key, "tcp-limit")              == 0 ||
             strcmp(key, "tcp_limit")              == 0) flag = "--tcp-limit";
    else if (strcmp(key, "udp-limit")              == 0 ||
             strcmp(key, "udp_limit")              == 0) flag = "--udp-limit";
    else if (strcmp(key, "process")                == 0) flag = "--process";
    else if (strcmp(key, "rule")                   == 0) flag = "--rule";
    else if (strcmp(key, "pid")                    == 0) flag = "--pid";
    else if (strcmp(key, "burst")                  == 0) flag = "--burst";
    else if (strcmp(key, "disable-after")          == 0 ||
             strcmp(key, "disable_after")          == 0) flag = "--disable-after";
    else if (strcmp(key, "process-update-interval")== 0 ||
             strcmp(key, "process_update_interval")== 0) flag = "--process-update-interval";
    else if (strcmp(key, "priority")               == 0) flag = "--priority";
    else if (strcmp(key, "latency")                == 0) flag = "--latency";
    else if (strcmp(key, "packet-loss")            == 0 ||
             strcmp(key, "packet_loss")            == 0) flag = "--packet-loss";
    else if (strcmp(key, "stop-at")                == 0 ||
             strcmp(key, "stop_at")                == 0) flag = "--stop-at";
    else if (strcmp(key, "schedule")               == 0) flag = "--schedule";
    else if (strcmp(key, "quota-check-interval")   == 0 ||
             strcmp(key, "quota_check_interval")   == 0) flag = "--quota-check-interval";
    else if (strcmp(key, "stats-interval")         == 0 ||
             strcmp(key, "stats_interval")         == 0) flag = "--stats-interval";
    else if (strcmp(key, "lang")                   == 0) flag = "--lang";

    // Build a synthetic 3-element argv: {"<cfg>", flag, value}
    char *fake_argv[3] = { program_name, (char *)flag, (char *)value };
    return parse_args(3, fake_argv, args);
}

// -----------------------------------------------------------------------
// load_config_file
// -----------------------------------------------------------------------

bool load_config_file(const char *path, ParsedArgs *args) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, C(CLI_ERR_CONFIG_OPEN), path);
        return false;
    }

    char line[MAX_CONFIG_LINE_LEN];
    char key[MAX_CONFIG_KEY_LEN];
    char value[MAX_CONFIG_VALUE_LEN];
    int line_num = 0;
    bool success = true;
    bool continued = false;

    while (true) {
        if (!continued) line_num++;

        bool got_entry = parse_config_line(fp, line, sizeof(line),
                                            key, sizeof(key),
                                            value, sizeof(value),
                                            &continued);
        if (!got_entry) {
            if (feof(fp)) break;
            if (continued) continue;
            continue; // blank / comment line
        }

        // Normalise key to lowercase for case-insensitive matching
        for (char *p = key; *p; p++) *p = (char)tolower((unsigned char)*p);

        if (!apply_config_value(key, value, args)) {
            fprintf(stderr, C(CLI_ERR_CONFIG_BAD_VALUE),
                    path, line_num, key);
            success = false;
            break;
        }
    }

    fclose(fp);
    return success;
}

// -----------------------------------------------------------------------
// Help / version
// -----------------------------------------------------------------------

void print_version(void) {
    printf(C(CLI_VERSION_FMT), APP_VERSION_A);
}

void print_help(const char *program_path) {
    char name[MAX_PATH];
    get_program_name_r(program_path, name, sizeof(name));
    printf(C(CLI_USAGE), name);
    printf(C(CLI_OPTIONS_HEADER));
    printf(C(CLI_HELP_CONFIG));
    printf(C(CLI_HELP_LANG));
    printf(C(CLI_HELP_PRIORITY), WINDIVERT_PRIORITY_LOWEST, WINDIVERT_PRIORITY_HIGHEST);
    printf(C(CLI_HELP_PROCESS));
    printf(C(CLI_HELP_PID));
    printf(C(CLI_HELP_RULE));
    printf(C(CLI_HELP_STOP_AT));
    printf(C(CLI_HELP_STOP_AT_CONT));
    printf(C(CLI_HELP_SCHEDULE));
    printf(C(CLI_HELP_SCHEDULE_DAYS));
    printf(C(CLI_HELP_SCHEDULE_EX));
    printf(C(CLI_HELP_QUOTA_INTERVAL), QUOTA_CHECK_INTERVAL);
    printf(C(CLI_HELP_STATS_INTERVAL), STATS_UPDATE_INTERVAL);
    printf(C(CLI_HELP_PROC_INTERVAL));
    printf(C(CLI_HELP_DISABLE_AFTER));
    printf(C(CLI_HELP_DOWNLOAD));
    printf(C(CLI_HELP_UPLOAD));
    printf(C(CLI_HELP_DL_BUFFER), DEFAULT_DL_BUFFER);
    printf(C(CLI_HELP_UL_BUFFER), DEFAULT_UL_BUFFER);
    printf(C(CLI_HELP_TCP_LIMIT));
    printf(C(CLI_HELP_UDP_LIMIT));
    printf(C(CLI_HELP_BURST));
    printf(C(CLI_HELP_LATENCY));
    printf(C(CLI_HELP_PACKET_LOSS));
    printf(C(CLI_HELP_NIC));
    printf(C(CLI_HELP_LIST_NICS));
    printf(C(CLI_HELP_STATISTICS));
    printf(C(CLI_HELP_QUIET));
    printf(C(CLI_HELP_VERSION));
    printf(C(CLI_HELP_HELP));
}
