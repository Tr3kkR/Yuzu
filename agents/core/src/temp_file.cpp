/**
 * temp_file.cpp — Cross-platform secure temporary file/directory creation
 *
 * POSIX:   mkstemps() for files (mode 0600), mkdtemp() for dirs (mode 0700).
 * Windows: CreateFile/CreateDirectory with owner-only DACL + crypto-random names.
 */

#include <yuzu/plugin.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <bcrypt.h>
#include <sddl.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

#ifdef _WIN32

// Generate 16 crypto-random bytes and format as 32-char hex string.
static bool generate_random_hex(char* out, size_t hex_len) {
    if (hex_len < 32)
        return false;
    UCHAR bytes[16];
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return false;
    }
    for (int i = 0; i < 16; ++i) {
        std::snprintf(out + i * 2, 3, "%02x", bytes[i]);
    }
    return true;
}

// Create an owner-only SECURITY_ATTRIBUTES. Caller must LocalFree sd.
static bool make_owner_only_sa(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& sd) {
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sd = nullptr;
    // D:P(A;;GA;;;OW) = Protected DACL, allow Generic All to Owner only
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)", SDDL_REVISION_1,
                                                              &sd, nullptr)) {
        return false;
    }
    sa.lpSecurityDescriptor = sd;
    return true;
}

// Get the temp directory as a wide string.
static bool get_temp_dir_w(const char* directory, wchar_t* out, DWORD out_size) {
    if (directory && directory[0]) {
        return MultiByteToWideChar(CP_UTF8, 0, directory, -1, out, out_size) != 0;
    }
    return GetTempPathW(out_size, out) != 0;
}

// Build "dir\prefixHEXsuffix" wide-string path, return UTF-8 length.
static std::wstring build_temp_path_w(const wchar_t* dir, const char* prefix, const char* hex,
                                      const char* suffix) {
    std::wstring result(dir);
    if (!result.empty() && result.back() != L'\\' && result.back() != L'/') {
        result += L'\\';
    }
    // Append prefix + hex + suffix (all ASCII, safe to widen char-by-char)
    for (const char* p = prefix; *p; ++p)
        result += static_cast<wchar_t>(*p);
    for (const char* p = hex; *p; ++p)
        result += static_cast<wchar_t>(*p);
    if (suffix) {
        for (const char* p = suffix; *p; ++p)
            result += static_cast<wchar_t>(*p);
    }
    return result;
}

static int wide_to_utf8(const wchar_t* wide, char* out, size_t out_size) {
    int written = WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, static_cast<int>(out_size),
                                      nullptr, nullptr);
    return (written > 0) ? 0 : -1;
}

#endif // _WIN32

extern "C" {

YUZU_EXPORT int yuzu_create_temp_file(const char* prefix, const char* suffix, const char* directory,
                                      char* path_out, size_t path_out_size) {
    if (!path_out || path_out_size == 0)
        return -1;

    const char* pfx = (prefix && prefix[0]) ? prefix : "yuzu-";
    const char* sfx = (suffix && suffix[0]) ? suffix : ".tmp";

#ifdef _WIN32
    wchar_t temp_dir_w[MAX_PATH];
    if (!get_temp_dir_w(directory, temp_dir_w, MAX_PATH))
        return -1;

    char hex[33]{};
    if (!generate_random_hex(hex, sizeof(hex)))
        return -1;

    auto full_path = build_temp_path_w(temp_dir_w, pfx, hex, sfx);
    if (full_path.size() >= MAX_PATH)
        return -1;

    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    make_owner_only_sa(sa, sd);

    HANDLE hFile = CreateFileW(full_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                               0, // no sharing
                               &sa,
                               CREATE_NEW, // fail if exists — prevents TOCTOU race
                               FILE_ATTRIBUTE_TEMPORARY, nullptr);

    if (sd)
        LocalFree(sd);

    if (hFile == INVALID_HANDLE_VALUE)
        return -1;
    CloseHandle(hFile);

    if (wide_to_utf8(full_path.c_str(), path_out, path_out_size) != 0) {
        DeleteFileW(full_path.c_str());
        return -1;
    }
    return 0;

#else
    std::string temp_dir;
    if (directory && directory[0]) {
        temp_dir = directory;
    } else {
        std::error_code ec;
        temp_dir = fs::temp_directory_path(ec).string();
        if (ec)
            return -1;
    }

    // mkstemps template: dir/prefixXXXXXXsuffix
    auto sfx_len = static_cast<int>(std::strlen(sfx));
    std::string tmpl = temp_dir + "/" + pfx + "XXXXXX" + sfx;

    int fd = mkstemps(tmpl.data(), sfx_len);
    if (fd < 0)
        return -1;
    close(fd);

    if (tmpl.size() + 1 > path_out_size) {
        unlink(tmpl.c_str());
        return -1;
    }
    std::memcpy(path_out, tmpl.c_str(), tmpl.size() + 1);
    return 0;
#endif
}

YUZU_EXPORT int yuzu_create_temp_dir(const char* prefix, const char* directory, char* path_out,
                                     size_t path_out_size) {
    if (!path_out || path_out_size == 0)
        return -1;

    const char* pfx = (prefix && prefix[0]) ? prefix : "yuzu-";

#ifdef _WIN32
    wchar_t temp_dir_w[MAX_PATH];
    if (!get_temp_dir_w(directory, temp_dir_w, MAX_PATH))
        return -1;

    char hex[33]{};
    if (!generate_random_hex(hex, sizeof(hex)))
        return -1;

    auto full_path = build_temp_path_w(temp_dir_w, pfx, hex, nullptr);
    if (full_path.size() >= MAX_PATH)
        return -1;

    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    make_owner_only_sa(sa, sd);

    BOOL ok = CreateDirectoryW(full_path.c_str(), &sa);
    if (sd)
        LocalFree(sd);
    if (!ok)
        return -1;

    if (wide_to_utf8(full_path.c_str(), path_out, path_out_size) != 0) {
        RemoveDirectoryW(full_path.c_str());
        return -1;
    }
    return 0;

#else
    std::string temp_dir;
    if (directory && directory[0]) {
        temp_dir = directory;
    } else {
        std::error_code ec;
        temp_dir = fs::temp_directory_path(ec).string();
        if (ec)
            return -1;
    }

    std::string tmpl = temp_dir + "/" + pfx + "XXXXXX";

    if (mkdtemp(tmpl.data()) == nullptr)
        return -1;

    if (tmpl.size() + 1 > path_out_size) {
        rmdir(tmpl.c_str());
        return -1;
    }
    std::memcpy(path_out, tmpl.c_str(), tmpl.size() + 1);
    return 0;
#endif
}

} // extern "C"
