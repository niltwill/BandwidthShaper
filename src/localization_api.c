// localization_api.c
#include "localization_api.h"

// Forward declarations
// (Defined in localization_data.c)
extern const char * const *g_cli_strings;
extern const wchar_t * const *g_gui_strings;

static LangId s_active_lang = LOC_LANG_EN;

void loc_set_language(LangId lang) {
    switch (lang) {
        case LOC_LANG_EN:
            // These pointers come from localization_data.c
            extern const char * const lang_cli_en[]; 
            extern const wchar_t * const lang_gui_en[];

            g_cli_strings = lang_cli_en;
            g_gui_strings = lang_gui_en;
            s_active_lang = LOC_LANG_EN;
            break;

        case LOC_LANG_HU:
            // These pointers come from localization_data.c
            extern const char * const lang_cli_hu[]; 
            extern const wchar_t * const lang_gui_hu[];

            g_cli_strings = lang_cli_hu;
            g_gui_strings = lang_gui_hu;
            s_active_lang = LOC_LANG_HU;
            break;

        // Add cases for DE, FR, etc. here. 
        // e.g. case LOC_LANG_DE: { ... } break;

        default:
            // Fallback to English
            extern const char * const lang_cli_en[];
            extern const wchar_t * const lang_gui_en[];
            g_cli_strings = lang_cli_en;
            g_gui_strings = lang_gui_en;
            s_active_lang = LOC_LANG_EN;
            break;
    }
}

LangId loc_get_language(void) {
    return s_active_lang;
}

const wchar_t *loc_language_name(LangId lang) {
    switch (lang) {
        case LOC_LANG_EN: return T(GUI_OPT_LOC_LANG_EN);
        case LOC_LANG_HU: return T(GUI_OPT_LOC_LANG_HU);
        default:          return T(GUI_OPT_LOC_LANG_UNK);
    }
}
