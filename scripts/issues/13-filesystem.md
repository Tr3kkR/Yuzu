## Summary

New **filesystem** plugin for file system queries and operations: check file existence, list directories, get file version/hash, and perform file management actions.

## Actions

- **exists** — Params: `path` (required). Checks if a file or directory exists. Output: `exists|true/false`, `type|file/directory`, `size|N`.
- **list_dir** — Params: `path` (required), `pattern` (optional). Lists files in a directory, optionally filtered by glob pattern. Output: `entry|name|type|size|modified` per entry.
- **file_version** — Params: `path` (required). Returns the file version (Windows PE version info) or package version. Output: `version|X.Y.Z.W`.
- **file_hash** — Params: `path` (required), `algorithm` (optional, default sha256). Computes a cryptographic hash of a file (SHA-256, SHA-1, MD5). Output: `hash|HEXSTRING`, `algorithm|sha256`, `size|N`.
- **delete** — Params: `path` (required). Deletes a file or empty directory. Output: `status|ok/error`, `message|...`.
- **copy** — Params: `source` (required), `dest` (required). Copies a file from source to destination. Output: `status|ok/error`, `message|...`.
- **mkdir** — Params: `path` (required). Creates a directory (and parent directories if needed). Output: `status|ok/error`, `message|...`.
- **chmod** — Params: `path` (required), `permissions` (required). Modifies file permissions (Unix octal or Windows ACL descriptor). Output: `status|ok/error`, `message|...`.

## Notes

- **file_version** is primarily a Windows concept (PE resource version). On Linux, return empty or package version if the file belongs to a package.
- **file_hash**: Use OpenSSL EVP on Linux, BCrypt on Windows (same pattern as procfetch).
- **Security**: Delete, copy, and chmod are destructive — audit log all invocations. Consider path validation to prevent directory traversal attacks.
- Use `std::filesystem` for most portable operations (exists, list_dir, mkdir, copy).

## Files

- `agents/plugins/filesystem/src/filesystem_plugin.cpp` (new)
- `agents/plugins/filesystem/CMakeLists.txt` (new)
- `agents/plugins/filesystem/meson.build` (new)
