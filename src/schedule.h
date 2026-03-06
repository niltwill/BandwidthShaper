#ifndef SCHEDULE_H
#define SCHEDULE_H

// schedule.h
// Compact schedule support for BandwidthShaper.
//
// A schedule string encodes an optional time window and/or an optional
// set of weekdays using a single ASCII token that the ListView can display
// and persist to the INI file.
//
// Grammar (all parts are optional, at least one must be present):
//
//   <schedule>  ::= <time> [ "~" <days> ]
//                 | <days>
//   <time>      ::= HHMM "-" HHMM          (24-h, e.g. "0800-1600")
//   <days>      ::= <range> | <list>
//   <range>     ::= DIGIT "-" DIGIT        (e.g. "1-5"  = Mon-Fri)
//   <list>      ::= DIGIT { "," DIGIT }    (e.g. "1,3,5" = Mon,Wed,Fri)
//   DIGIT       ::= "1".."7"               (1=Monday, 7=Sunday, ISO-8601)
//
// Examples:
//   "0800-1600~1-5"   time 08:00-16:00, Monday-Friday
//   "1400-2000~1,3,5" time 14:00-20:00, Mon/Wed/Fri only
//   "0600-1200"       time only, any day of the week
//   "1,2"             day-of-week only, Monday and Tuesday, any time
//   ""                no schedule (rules always active)
//
// Implementation note on midnight-spanning windows:
//   When start_min >= end_min (e.g. "2200-0600") the window wraps around
//   midnight and the "in-window" test is inverted accordingly.

#include "common.h"
#include <stddef.h>  // only needed here, so not in common.h

// ---------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------

// Maximum length of a serialised schedule string (null-terminated).
// "HHMM-HHMM~1,2,3,4,5,6,7" = 24 chars + '\0' = 25, so 32 is ample.
#define SCHEDULE_STR_MAX 32

// Represents a parsed schedule.  All fields are zero when there is no
// schedule constraint at all (see schedule_is_empty).
typedef struct {
    // Time-of-day window
    bool     has_time;      // true if a time window is set
    int      start_min;     // window start in minutes since midnight [0..1439]
    int      end_min;       // window end in minutes since midnight [0..1439]

    // Day-of-week mask (bit 0 unused; bits 1-7 correspond to Mon-Sun / ISO 1-7)
    bool     has_days;      // true if a day-of-week filter is set
    unsigned days_mask;     // bit N set means ISO weekday N is active
} Schedule;

// ---------------------------------------------------------------------
// Construction helpers
// ---------------------------------------------------------------------

// Zero-initialise a Schedule (= "no constraints").
static inline void schedule_init(Schedule *s) {
    s->has_time  = false;
    s->start_min = 0;
    s->end_min   = 0;
    s->has_days  = false;
    s->days_mask = 0;
}

// Returns true when the schedule has no constraints at all
// (i.e. rules are always applied).
static inline bool schedule_is_empty(const Schedule *s) {
    return !s->has_time && !s->has_days;
}

// ---------------------------------------------------------------------
// Parse / format
// ---------------------------------------------------------------------

// Parse a compact schedule string into *out.
// Returns true on success; on failure *out is zero-initialised and false
// is returned.  An empty string ("") is valid and yields an empty schedule.
bool schedule_parse(const char *str, Schedule *out);

// Wide-char variant.
bool schedule_parsew(const wchar_t *str, Schedule *out);

// Serialise *s into buf (max SCHEDULE_STR_MAX bytes including '\0').
// Writes "" for an empty schedule.
void schedule_format(const Schedule *s, char *buf, size_t buf_size);

// Wide-char variant.
void schedule_formatw(const Schedule *s, wchar_t *buf, size_t buf_size);

// ---------------------------------------------------------------------
// Time-matching
// ---------------------------------------------------------------------

// Returns true if the current local wall-clock falls within the schedule.
// An empty schedule always returns true (no constraints = always active).
bool schedule_is_active_now(const Schedule *s);

// Same but against an explicit (hour, minute, iso_weekday) triple
// so callers can test without changing the system clock.
// iso_weekday: 1=Monday ... 7=Sunday.
bool schedule_is_active(const Schedule *s, int hour, int minute, int iso_weekday);

// ---------------------------------------------------------------------
// Human-readable summary (for tooltips / status)
// ---------------------------------------------------------------------

// Fill buf with a short English description, e.g.
//   "08:00-16:00, Mon-Fri"
//   "Mon, Wed, Fri"
//   "22:00-06:00 (overnight)"
// buf_size should be at least 64 chars.
void schedule_describe(const Schedule *s, wchar_t *buf, size_t buf_size);

#endif // SCHEDULE_H
