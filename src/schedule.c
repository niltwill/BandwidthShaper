// schedule.c
// Implementation of the compact schedule module.
// See schedule.h for the string grammar.

#include "common.h"
#include "schedule.h"

// =========================================================================
// Internal helpers
// =========================================================================

// Parse "HHMM" at *p; advance *p past consumed chars.
// Returns minutes-since-midnight on success, -1 on error.
static int parse_hhmm(const char **p) {
    const char *s = *p;
    for (int i = 0; i < 4; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
    }
    int hh = (s[0] - '0') * 10 + (s[1] - '0');
    int mm = (s[2] - '0') * 10 + (s[3] - '0');
    if (hh > 23 || mm > 59) return -1;
    *p += 4;
    return hh * 60 + mm;
}

// Parse a day-spec (range "1-5" or list "1,3,5") into a bitmask.
// Returns the mask on success (non-zero if at least one day was set),
// or 0 on parse error.
static unsigned parse_days(const char *p) {
    unsigned mask = 0;
    while (*p) {
        if (*p < '1' || *p > '7') return 0;
        int day = *p - '0';
        p++;

        if (*p == '-') {
            // Range: "d-e"
            p++;
            if (*p < '1' || *p > '7') return 0;
            int end_day = *p - '0';
            p++;
            if (end_day < day) return 0;  // enforce ascending for ranges
            for (int d = day; d <= end_day; d++)
                mask |= (1u << d);
        } else {
            // Single day
            mask |= (1u << day);
        }

        if (*p == ',') {
            p++;  // consume separator and continue
        } else if (*p == '\0') {
            break;
        } else {
            return 0;  // unexpected character
        }
    }
    return mask;
}

// =========================================================================
// Public API
// =========================================================================

bool schedule_parse(const char *str, Schedule *out) {
    schedule_init(out);
    if (!str || str[0] == '\0') return true;  // empty = no constraint

    const char *p = str;

    // Determine whether the string starts with a time (4 digits then '-' then
    // 4 digits) or with a day-spec (single digit 1-7).

    bool leading_time = (p[0] >= '0' && p[0] <= '2'
                      && p[1] >= '0' && p[1] <= '9'
                      && p[2] >= '0' && p[2] <= '5'
                      && p[3] >= '0' && p[3] <= '9'
                      && p[4] == '-'
                      && p[5] >= '0' && p[5] <= '2');

    if (leading_time) {
        int start = parse_hhmm(&p);
        if (start < 0) return false;
        if (*p != '-') return false;
        p++;
        int end = parse_hhmm(&p);
        if (end < 0) return false;

        out->has_time  = true;
        out->start_min = start;
        out->end_min   = end;

        // Optional day spec after '~'
        if (*p == '~') {
            p++;
            unsigned mask = parse_days(p);
            if (mask == 0) return false;
            out->has_days  = true;
            out->days_mask = mask;
        } else if (*p != '\0') {
            return false;  // trailing garbage
        }
    } else {
        // Day-spec only
        unsigned mask = parse_days(p);
        if (mask == 0) return false;
        out->has_days  = true;
        out->days_mask = mask;
    }

    return true;
}

bool schedule_parsew(const wchar_t *str, Schedule *out) {
    if (!str) { schedule_init(out); return true; }
    char narrow[SCHEDULE_STR_MAX];
    int i;
    for (i = 0; i < SCHEDULE_STR_MAX - 1 && str[i]; i++)
        narrow[i] = (char)(str[i] & 0x7F);
    narrow[i] = '\0';
    return schedule_parse(narrow, out);
}

// -------------------------------------------------------------------------

void schedule_format(const Schedule *s, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return;
    if (schedule_is_empty(s)) { buf[0] = '\0'; return; }

    char tmp[SCHEDULE_STR_MAX];
    int pos = 0;

    if (s->has_time) {
        int sh = s->start_min / 60, sm = s->start_min % 60;
        int eh = s->end_min / 60, em = s->end_min % 60;
        pos += snprintf(tmp + pos, sizeof(tmp) - pos,
                        "%02d%02d-%02d%02d", sh, sm, eh, em);
    }

    if (s->has_days) {
        if (s->has_time) tmp[pos++] = '~';

        // Try to emit a compact range if bits are contiguous
        int first = -1, last = -1;
        int count = 0;
        bool contiguous = true;
        int prev = -1;
        for (int d = 1; d <= 7; d++) {
            if (s->days_mask & (1u << d)) {
                count++;
                if (first < 0) first = d;
                last = d;
                if (prev >= 0 && d != prev + 1) contiguous = false;
                prev = d;
            }
        }

        if (contiguous && count > 1) {
            pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%d-%d", first, last);
        } else {
            bool any = false;
            for (int d = 1; d <= 7; d++) {
                if (s->days_mask & (1u << d)) {
                    if (any) tmp[pos++] = ',';
                    tmp[pos++] = (char)('0' + d);
                    any = true;
                }
            }
        }
    }

    tmp[pos] = '\0';
    snprintf(buf, buf_size, "%s", tmp);
}

void schedule_formatw(const Schedule *s, wchar_t *buf, size_t buf_size) {
    char narrow[SCHEDULE_STR_MAX];
    schedule_format(s, narrow, sizeof(narrow));
    size_t i = 0;
    for (; i < buf_size - 1 && narrow[i]; i++)
        buf[i] = (wchar_t)(unsigned char)narrow[i];
    buf[i] = L'\0';
}

// -------------------------------------------------------------------------

bool schedule_is_active(const Schedule *s, int hour, int minute, int iso_weekday) {
    if (schedule_is_empty(s)) return true;

    int now_min = hour * 60 + minute;

    // Check day of week first
    if (s->has_days) {
        if (iso_weekday < 1 || iso_weekday > 7) return false;
        if (!(s->days_mask & (1u << iso_weekday))) return false;
    }

    // Check time window
    if (s->has_time) {
        if (s->start_min < s->end_min) {
            // Normal window (e.g. 08:00-16:00)
            if (now_min < s->start_min || now_min >= s->end_min) return false;
        } else if (s->start_min > s->end_min) {
            // Overnight window (e.g. 22:00-06:00)
            if (now_min < s->start_min && now_min >= s->end_min) return false;
        } else {
            // start == end: zero-length window, treat as always active
            // (edge case; user probably didn't set time properly)
        }
    }

    return true;
}

bool schedule_is_active_now(const Schedule *s) {
    if (schedule_is_empty(s)) return true;

    SYSTEMTIME st;
    GetLocalTime(&st);

    // SYSTEMTIME.wDayOfWeek: 0=Sunday, 1=Monday ... 6=Saturday
    // Convert to ISO-8601: 1=Monday ... 7=Sunday
    int iso_dow = (st.wDayOfWeek == 0) ? 7 : (int)st.wDayOfWeek;

    return schedule_is_active(s, (int)st.wHour, (int)st.wMinute, iso_dow);
}

// -------------------------------------------------------------------------

static const wchar_t *DAY_ABBR[8] = {
    L"",          // index 0 unused
    L"Mon", L"Tue", L"Wed", L"Thu", L"Fri", L"Sat", L"Sun"
};

void schedule_describe(const Schedule *s, wchar_t *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return;
    if (schedule_is_empty(s)) { wcsncpy(buf, L"(always active)", buf_size); return; }

    wchar_t tmp[128] = {0};
    int pos = 0;

    // Time part
    if (s->has_time) {
        int sh = s->start_min / 60, sm = s->start_min % 60;
        int eh = s->end_min / 60, em = s->end_min % 60;
        bool overnight = (s->start_min > s->end_min);
        
        int needed = swprintf(tmp + pos, 128 - pos,
                              L"%02d:%02d-%02d:%02d%s",
                              sh, sm, eh, em,
                              overnight ? L" (overnight)" : L"");
        if (needed > 0) pos += needed;
        if (pos >= 128 - 5) goto done;  // Leave room for day part
    }

    // Day part
    if (s->has_days) {
        if (s->has_time) {
            if (pos < 128 - 2) {
                tmp[pos++] = L',';
                tmp[pos++] = L' ';
            } else {
                goto done;
            }
        }

        // Check for a contiguous range
        int first = -1, last = -1, count = 0;
        bool contiguous = true;
        int prev = -1;
        for (int d = 1; d <= 7; d++) {
            if (s->days_mask & (1u << d)) {
                count++;
                if (first < 0) first = d;
                last = d;
                if (prev >= 0 && d != prev + 1) contiguous = false;
                prev = d;
            }
        }

        if (contiguous && count > 1) {
            int needed = swprintf(tmp + pos, 128 - pos,
                                  L"%s-%s", DAY_ABBR[first], DAY_ABBR[last]);
            if (needed > 0) pos += needed;
        } else {
            bool any = false;
            for (int d = 1; d <= 7; d++) {
                if (s->days_mask & (1u << d)) {
                    if (any) {
                        if (pos >= 128 - 3) goto done;  // Need room for ", " and at least one char
                        tmp[pos++] = L',';
                        tmp[pos++] = L' ';
                    }
                    int needed = swprintf(tmp + pos, 128 - pos, L"%s", DAY_ABBR[d]);
                    if (needed > 0) pos += needed;
                    any = true;
                }
            }
        }
    }

done:
    tmp[pos] = L'\0';
    wcsncpy(buf, tmp, buf_size - 1);
    buf[buf_size - 1] = L'\0';
}
