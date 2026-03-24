/**
 * yuzu/plugin.h — Stable C ABI for Yuzu plugins
 *
 * This header defines the only ABI boundary between the agent host and plugin
 * shared libraries. It is intentionally kept as a C-compatible interface so
 * that plugins can be written in any language that supports a C FFI, and so
 * that binary compatibility is maintained across compiler/STL upgrades.
 *
 * Every plugin shared library MUST export a single function with C linkage:
 *
 *   const YuzuPluginDescriptor* yuzu_plugin_descriptor(void);
 *
 * Use the YUZU_PLUGIN_EXPORT macro (plugin.hpp) to generate this automatically
 * when writing C++ plugins.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ── Version ────────────────────────────────────────────────────────────────── */

#define YUZU_PLUGIN_ABI_VERSION 3

/**
 * Compile-time SDK version string embedded in every plugin descriptor.
 * The agent logs this at load time for diagnostics.
 */
#define YUZU_PLUGIN_SDK_VERSION "0.1.0"

/**
 * Plugins compiled against ABI version 1 are still loadable.
 * The agent checks descriptor->abi_version >= YUZU_PLUGIN_ABI_VERSION_MIN.
 */
#define YUZU_PLUGIN_ABI_VERSION_MIN 1

/* ── Forward declarations ────────────────────────────────────────────────────── */

typedef struct YuzuPluginContext YuzuPluginContext;
typedef struct YuzuCommandContext YuzuCommandContext;

/* ── Key/value parameter bag ─────────────────────────────────────────────────── */

typedef struct {
    const char* key;
    const char* value;
} YuzuParam;

/* ── Command handler signature ───────────────────────────────────────────────── */

/**
 * YuzuCommandHandler is called by the agent to execute an action.
 *
 * @param ctx        Opaque context for sending output/progress back.
 * @param action     Null-terminated action name (e.g. "list", "install").
 * @param params     Array of key-value parameters; may be NULL.
 * @param param_count Length of the params array.
 * @return           0 on success, non-zero on failure.
 */
typedef int (*YuzuCommandHandler)(YuzuCommandContext* ctx, const char* action,
                                  const YuzuParam* params, size_t param_count);

/* ── Plugin descriptor ────────────────────────────────────────────────────────── */

/**
 * YuzuPluginDescriptor is returned by yuzu_plugin_descriptor().
 * The struct must remain valid for the lifetime of the plugin (i.e. static).
 */
typedef struct {
    /** Must equal YUZU_PLUGIN_ABI_VERSION. Checked at load time. */
    uint32_t abi_version;

    /** Short unique identifier (e.g. "inventory", "patch"). */
    const char* name;

    /** Semantic version string (e.g. "1.0.0"). */
    const char* version;

    /** Human-readable description. */
    const char* description;

    /**
     * Null-terminated array of action names this plugin handles.
     * e.g. { "list", "install", "uninstall", NULL }
     */
    const char* const* actions;

    /**
     * Called once when the plugin is loaded.
     * @return 0 on success, non-zero to abort loading.
     */
    int (*init)(YuzuPluginContext* ctx);

    /**
     * Called once when the plugin is about to be unloaded.
     * Release all resources here.
     */
    void (*shutdown)(YuzuPluginContext* ctx);

    /** Dispatches an action to this plugin. */
    YuzuCommandHandler execute;

    /**
     * SDK version string the plugin was compiled against (ABI v3+).
     * Null for plugins compiled with ABI version < 3.
     */
    const char* sdk_version;

} YuzuPluginDescriptor;

/* ── Required export symbol ──────────────────────────────────────────────────── */

/**
 * Every plugin must export this function.
 * The returned pointer must be to a statically allocated descriptor.
 */
typedef const YuzuPluginDescriptor* (*yuzu_plugin_descriptor_fn)(void);

/* For agent core functions (import when used by plugins/agent) */
#ifdef _WIN32
#ifdef YUZU_AGENT_CORE_BUILDING
#define YUZU_EXPORT __declspec(dllexport)
#else
#define YUZU_EXPORT __declspec(dllimport)
#endif
#else
#define YUZU_EXPORT __attribute__((visibility("default")))
#endif

/* For plugin exports (always export from plugin DLLs) */
#ifdef _WIN32
#define YUZU_PLUGIN_API __declspec(dllexport)
#else
#define YUZU_PLUGIN_API __attribute__((visibility("default")))
#endif

/* ── Context helpers (implemented by the agent host) ─────────────────────────── */

/**
 * Send a line of UTF-8 output text back to the server.
 * May be called multiple times from within execute() for streaming output.
 */
YUZU_EXPORT void yuzu_ctx_write_output(YuzuCommandContext* ctx, const char* text);

/**
 * Report progress (0–100). Optional; agents may display this in the UI.
 */
YUZU_EXPORT void yuzu_ctx_report_progress(YuzuCommandContext* ctx, int percent);

/**
 * Retrieve a named configuration value set by the server for this plugin.
 * Returns NULL if the key is not present.
 */
YUZU_EXPORT const char* yuzu_ctx_get_config(YuzuPluginContext* ctx, const char* key);

/**
 * Retrieve a named secret (e.g. credential) injected by the server.
 * Returns NULL if not present.
 */
YUZU_EXPORT const char* yuzu_ctx_get_secret(YuzuPluginContext* ctx, const char* key);

/* ── KV Storage (ABI v2) — persistent SQLite-backed storage per plugin ─────── */

/**
 * Store a key-value pair in the plugin's persistent namespace.
 * @return 0 on success, non-zero on error.
 */
YUZU_EXPORT int yuzu_ctx_storage_set(YuzuPluginContext* ctx, const char* key, const char* value);

/**
 * Retrieve a value by key from the plugin's persistent namespace.
 * @return Allocated string on success, NULL if key not found.
 *         Caller must free with yuzu_free_string().
 */
YUZU_EXPORT const char* yuzu_ctx_storage_get(YuzuPluginContext* ctx, const char* key);

/**
 * Delete a key from the plugin's persistent namespace.
 * @return 0 on success, non-zero on error.
 */
YUZU_EXPORT int yuzu_ctx_storage_delete(YuzuPluginContext* ctx, const char* key);

/**
 * Check whether a key exists in the plugin's persistent namespace.
 * @return 0 if exists, 1 if not found, negative on error.
 */
YUZU_EXPORT int yuzu_ctx_storage_exists(YuzuPluginContext* ctx, const char* key);

/**
 * List keys matching a prefix from the plugin's persistent namespace.
 * Returns a JSON array string, e.g. '["key1","key2"]'.
 * @return Allocated JSON string, or NULL on error. Free with yuzu_free_string().
 */
YUZU_EXPORT const char* yuzu_ctx_storage_list(YuzuPluginContext* ctx, const char* prefix);

/* ── SDK utility functions (format conversion) ──────────────────────────────── */

/**
 * Free a string allocated by SDK utility functions (table_to_json, etc.).
 * Passing NULL is safe (no-op).
 */
YUZU_EXPORT void yuzu_free_string(char* str);

/**
 * Convert pipe-delimited rows to a JSON array of objects.
 *
 * @param input         Pipe-delimited text (UTF-8, newline-separated rows).
 * @param column_names  Array of column name strings.
 * @param column_count  Length of column_names array.
 * @return Allocated JSON string, or NULL on error. Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_table_to_json(const char* input, const char* const* column_names,
                                     size_t column_count);

/**
 * Convert a JSON array of objects to pipe-delimited rows.
 *
 * @param json_input    JSON string (must be an array of objects).
 * @param column_names  Array of column name strings (keys to extract, in order).
 * @param column_count  Length of column_names array.
 * @return Allocated pipe-delimited string, or NULL on error.
 *         Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_json_to_table(const char* json_input, const char* const* column_names,
                                     size_t column_count);

/**
 * Normalize line endings in a string: \r\n and \r become \n.
 *
 * @param input  UTF-8 text with any mix of line endings.
 * @return Allocated string with normalized \n endings.
 *         Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_split_lines(const char* input);

/**
 * Generate a newline-separated sequence of numbered identifiers.
 *
 * @param start   Starting number.
 * @param count   How many identifiers to generate.
 * @param prefix  Prefix prepended to each number (may be NULL for no prefix).
 * @return Allocated string, or NULL on error. Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_generate_sequence(int start, int count, const char* prefix);

/* ── Secure temporary file utilities ────────────────────────────────────────── */

/**
 * Create a secure temporary file with restricted permissions.
 * POSIX: uses mkstemps() with mode 0600 (owner read/write only).
 * Windows: uses CreateFile with CREATE_NEW and owner-only DACL.
 *
 * @param prefix       Filename prefix (e.g., "yuzu-"). NULL defaults to "yuzu-".
 * @param suffix       File extension (e.g., ".tmp"). NULL defaults to ".tmp".
 * @param directory    Override temp directory. NULL uses the system default.
 * @param path_out     Buffer to receive the null-terminated absolute path.
 * @param path_out_size Size of path_out in bytes (recommend >= 512).
 * @return             0 on success, non-zero on failure.
 */
YUZU_EXPORT int yuzu_create_temp_file(const char* prefix, const char* suffix, const char* directory,
                                      char* path_out, size_t path_out_size);

/**
 * Create a secure temporary directory with restricted permissions.
 * POSIX: uses mkdtemp() with mode 0700 (owner only).
 * Windows: creates directory with owner-only DACL.
 *
 * @param prefix       Directory name prefix (e.g., "yuzu-"). NULL defaults to "yuzu-".
 * @param directory    Override parent directory. NULL uses the system default.
 * @param path_out     Buffer to receive the null-terminated absolute path.
 * @param path_out_size Size of path_out in bytes (recommend >= 512).
 * @return             0 on success, non-zero on failure.
 */
YUZU_EXPORT int yuzu_create_temp_dir(const char* prefix, const char* directory, char* path_out,
                                     size_t path_out_size);

/* ── Trigger registration (agent-side event-driven execution) ───────────── */

/**
 * Register a trigger from a plugin. When the trigger condition is met, the
 * agent will dispatch the plugin action specified in the config_json.
 *
 * @param ctx            Plugin context from init().
 * @param trigger_id     Unique trigger identifier (scoped to this plugin).
 * @param trigger_type   Type string: "interval", "filesystem", "service", "agent-startup".
 * @param config_json    JSON object with trigger-specific configuration:
 *                       - interval:    {"interval_seconds": 300, "plugin": "...", "action": "...", "parameters": {...}}
 *                       - filesystem:  {"watch_path": "/etc/hosts", "plugin": "...", "action": "...", "parameters": {...}}
 *                       - service:     {"service_name": "sshd", "expected_status": "stopped", "plugin": "...", "action": "...", "parameters": {...}}
 *                       - agent-startup: {"plugin": "...", "action": "...", "parameters": {...}}
 *                       Optional field: "debounce_seconds" (integer, suppress re-fires within window).
 * @return               0 on success, non-zero on failure.
 */
YUZU_EXPORT int yuzu_register_trigger(YuzuPluginContext* ctx, const char* trigger_id,
                                      const char* trigger_type, const char* config_json);

/**
 * Unregister a previously registered trigger.
 *
 * @param ctx            Plugin context.
 * @param trigger_id     The trigger ID to remove.
 * @return               0 on success, non-zero if not found.
 */
YUZU_EXPORT int yuzu_unregister_trigger(YuzuPluginContext* ctx, const char* trigger_id);

#ifdef __cplusplus
} /* extern "C" */
#endif
