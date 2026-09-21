#pragma once

/**
 * asset_tags_store.hpp — state-file I/O for the asset_tags plugin (#232).
 *
 * Header-only and logger-free: both functions return an error string the
 * caller logs, so the persistence lifecycle (create, replace, no leftover
 * temp, POSIX 0600, failure path, restart reload) is unit-testable without
 * loading the plugin. The pure (de)serialisation lives in
 * asset_tags_parsers.hpp.
 *
 * Write path: sibling `<dest>.tmp`, written and CLOSED (and checked) in its
 * own scope, then renamed over the target. The stream must be closed before
 * anything else touches the temp: an open handle makes the Windows rename
 * fail with a sharing violation. The caller serialises writers (the plugin
 * holds its state mutex across serialise + write), which is what makes the
 * fixed temp name race-free.
 *
 * Permissions: on POSIX the closed temp is tightened to 0600 before the
 * rename (checked; a failure is reported in `err` but does not block
 * persistence). There is a short window between create and chmod where the
 * temp carries the umask-derived mode; accepted because the file holds
 * non-secret operator tags (see the plugin README's sensitivity note). The
 * Windows DACL is not tightened — the same documented follow-up as
 * agent_csr.cpp's write_public_file.
 */

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace yuzu::asset_tags {

/// Read the state file. A missing file is a normal first run: returns nullopt
/// with `err` EMPTY. An unreadable file (or a non-regular path) returns
/// nullopt with `err` set.
inline std::optional<std::string> read_state_file(const std::filesystem::path& p,
                                                  std::string& err) {
    namespace fs = std::filesystem;
    err.clear();

    std::error_code ec;
    const auto st = fs::status(p, ec);
    if (st.type() == fs::file_type::not_found)
        return std::nullopt;
    if (ec) {
        err = "cannot stat: " + ec.message();
        return std::nullopt;
    }
    if (!fs::is_regular_file(st)) {
        err = "not a regular file";
        return std::nullopt;
    }

    std::ifstream f(p, std::ios::binary);
    if (!f) {
        err = "cannot open for reading";
        return std::nullopt;
    }
    std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (f.bad()) {
        err = "read error";
        return std::nullopt;
    }
    return content;
}

/// Atomically replace `dest` with `bytes` (temp + rename). Returns true when
/// the file was replaced. `err` is set on failure, and may also be set on a
/// true return to carry a non-fatal warning (POSIX chmod failure). The temp is
/// removed on every failure path.
inline bool write_state_file_atomic(const std::filesystem::path& dest, std::string_view bytes,
                                    std::string& err) {
    namespace fs = std::filesystem;
    err.clear();

    std::error_code ec;
    const auto parent = dest.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            err = "cannot create directory " + parent.string() + ": " + ec.message();
            return false;
        }
        if (!fs::is_directory(parent, ec)) {
            err = "not a directory: " + parent.string();
            return false;
        }
    }

    fs::path tmp = dest;
    tmp += ".tmp";

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "cannot open " + tmp.string() + " for writing";
            return false;
        }
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        out.flush();
        out.close();
        if (!out) {
            std::error_code rm_ec;
            fs::remove(tmp, rm_ec);
            err = "write to " + tmp.string() + " failed";
            return false;
        }
    }

#ifndef _WIN32
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace,
                    ec);
    if (ec)
        err = "could not restrict " + tmp.string() + " to 0600: " + ec.message();
#endif

    std::error_code rename_ec;
    fs::rename(tmp, dest, rename_ec);
    if (rename_ec) {
        std::error_code rm_ec;
        fs::remove(tmp, rm_ec);
        err = "cannot rename " + tmp.string() + " over " + dest.string() + ": " +
              rename_ec.message();
        return false;
    }
    return true;
}

} // namespace yuzu::asset_tags
