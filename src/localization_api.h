#ifndef LOCALIZATION_API_H
#define LOCALIZATION_API_H

#include <wchar.h>
#include "localization_ids.h"

// These must be here so the macros below can reference them
extern const char * const *g_cli_strings;
extern const wchar_t * const *g_gui_strings;

// =========================================================================
// Access macros
// =========================================================================
// C(id) – narrow string (printf/fprintf)
// T(id) – wide string (SetDlgItemTextW/swprintf)
#define C(id) (g_cli_strings[id])
#define T(id) (g_gui_strings[id])

// =========================================================================
// API Prototypes
// =========================================================================

/**
 * @brief Set the active language.
 * @param lang One of the LANG constants. Defaults to English if invalid.
 */
void loc_set_language(LangId lang);

/**
 * @brief Get the currently active language.
 */
LangId loc_get_language(void);

/**
 * @brief Get a display name for a language (e.g. L"English").
 */
const wchar_t *loc_language_name(LangId lang);

#endif // LOCALIZATION_API_H
