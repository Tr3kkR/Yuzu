#pragma once

/**
 * asset_tags_store.hpp — state-file I/O for the asset_tags plugin (#232).
 *
 * Header-only and logger-free: both functions return std::expected, so the
 * persistence lifecycle (create, replace, no leftover temp, POSIX 0600,
 * failure path, restart reload) is unit-testable without loading the plugin.
 * The pure (de)serialisation lives in asset_tags_parsers.hpp.
 *
 * Write path: sibling `<dest>.tmp`, written and CLOSED (and checked) in its
 * own scope, then renamed over the target. The stream must be closed before
 * anything else touches the temp: an open handle makes the Windows rename
 * fail with a sharing violation. The caller serialises writers (the plugin
 * holds its state mutex across serialise + write), which is what makes the
 * fixed temp name race-free.
 *
 * Permissions: on POSIX the closed temp is tightened to 0600 before the
 * rename (checked; a failure is reported as a WriteWarning but does not block
 * persistence). There is a short window between create and chmod where the
 * temp carries the umask-derived mode; accepted because the file holds
 * non-secret operator tags (see the plugin README's sensitivity note). The
 * Windows DACL is not tightened — the same documented follow-up as
 * agent_csr.cpp's write_public_file.
 */

#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace yuzu::asset_tags {

/// A failed read or write; `message` is human-readable and names the path.
struct IoError {
    std::string message;
};

/// A non-fatal condition attached to a SUCCESSFUL write (the file was
/// replaced): today only the POSIX chmod-to-0600 failure.
struct WriteWarning {
    std::string message;
};

namespace detail {

/// Removes the staged temp file on every exit path until dismissed (after
/// the rename has consumed it). Declared before the stream that creates the
/// temp, so it runs after that stream is closed.
class TempFileGuard {
public:
    explicit TempFileGuard(std::filesystem::path p) : path_(std::move(p)) {}
    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;
    ~TempFileGuard() {
        if (armed_) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
        }
    }
    void dismiss() noexcept { armed_ = false; }

private:
    std::filesystem::path path_;
    bool armed_{true};
};

} // namespace detail

/// Read the state file. A missing file is a normal first run: returns an
/// engaged expected holding nullopt. An unreadable file (or a non-regular
/// path) is an IoError.
[[nodiscard]] inline std::expected<std::optional<std::string>, IoError>
read_state_file(const std::filesystem::path& p) {
    namespace fs = std::filesystem;

    std::error_code ec;
    const auto st = fs::status(p, ec);
    if (st.type() == fs::file_type::not_found)
        return std::nullopt;
    if (ec)
        return std::unexpected(IoError{"cannot stat " + p.string() + ": " + ec.message()});
    if (!fs::is_regular_file(st))
        return std::unexpected(IoError{p.string() + ": not a regular file"});

    std::ifstream f(p, std::ios::binary);
    if (!f)
        return std::unexpected(IoError{"cannot open " + p.string() + " for reading"});
    std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (f.bad())
        return std::unexpected(IoError{"read error on " + p.string()});
    return content;
}

/// Atomically replace `dest` with `bytes` (temp + rename). On success the
/// value is an optional WriteWarning (engaged only when the POSIX chmod to
/// 0600 failed; the file was still replaced). The temp never outlives a
/// failure.
[[nodiscard]] inline std::expected<std::optional<WriteWarning>, IoError>
write_state_file_atomic(const std::filesystem::path& dest, std::string_view bytes) {
    namespace fs = std::filesystem;

    std::error_code ec;
    const auto parent = dest.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec)
            return std::unexpected(
                IoError{"cannot create directory " + parent.string() + ": " + ec.message()});
        if (!fs::is_directory(parent, ec))
            return std::unexpected(IoError{"not a directory: " + parent.string()});
    }

    fs::path tmp = dest;
    tmp += ".tmp";
    detail::TempFileGuard temp_guard{tmp};

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out)
            return std::unexpected(IoError{"cannot open " + tmp.string() + " for writing"});
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        out.flush();
        out.close();
        if (!out)
            return std::unexpected(IoError{"write to " + tmp.string() + " failed"});
    }

    std::optional<WriteWarning> warning;
#ifndef _WIN32
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace,
                    ec);
    if (ec)
        warning = WriteWarning{"could not restrict " + tmp.string() + " to 0600: " + ec.message()};
#endif

    std::error_code rename_ec;
    fs::rename(tmp, dest, rename_ec);
    if (rename_ec)
        return std::unexpected(IoError{"cannot rename " + tmp.string() + " over " + dest.string() +
                                       ": " + rename_ec.message()});
    temp_guard.dismiss();
    return warning;
}

} // namespace yuzu::asset_tags
