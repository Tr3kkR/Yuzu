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

#define YUZU_PLUGIN_ABI_VERSION 1

/* ── Forward declarations ────────────────────────────────────────────────────── */

typedef struct YuzuPluginContext  YuzuPluginContext;
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
typedef int (*YuzuCommandHandler)(
    YuzuCommandContext* ctx,
    const char*         action,
    const YuzuParam*    params,
    size_t              param_count
);

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

} YuzuPluginDescriptor;

/* ── Required export symbol ──────────────────────────────────────────────────── */

/**
 * Every plugin must export this function.
 * The returned pointer must be to a statically allocated descriptor.
 */
typedef const YuzuPluginDescriptor* (*yuzu_plugin_descriptor_fn)(void);

/* For agent core functions (import when used by plugins/agent) */
#ifdef _WIN32
#  ifdef YUZU_AGENT_CORE_BUILDING
#    define YUZU_EXPORT __declspec(dllexport)
#  else
#    define YUZU_EXPORT __declspec(dllimport)
#  endif
#else
#  define YUZU_EXPORT __attribute__((visibility("default")))
#endif

/* For plugin exports (always export from plugin DLLs) */
#ifdef _WIN32
#  define YUZU_PLUGIN_API __declspec(dllexport)
#else
#  define YUZU_PLUGIN_API __attribute__((visibility("default")))
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
YUZU_EXPORT int yuzu_create_temp_file(
    const char* prefix,
    const char* suffix,
    const char* directory,
    char*       path_out,
    size_t      path_out_size);

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
YUZU_EXPORT int yuzu_create_temp_dir(
    const char* prefix,
    const char* directory,
    char*       path_out,
    size_t      path_out_size);

#ifdef __cplusplus
}  /* extern "C" */
#endif
