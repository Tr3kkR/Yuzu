// Test fixture for cpp/yuzu/plugin-windows-process-spawn-non-literal.
// Compiled in a Windows context; relies on declarations rather than full
// <windows.h> include so the fixture stays portable for CodeQL extraction.

#include <cstddef>

// Minimal stand-in declarations matching the real Win32 signatures.
typedef void* HANDLE;
typedef int BOOL;
typedef unsigned long DWORD;
typedef const wchar_t* LPCWSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPWSTR;
typedef char* LPSTR;
typedef void* LPVOID;
typedef void* HWND;
typedef void* HINSTANCE;

struct STARTUPINFOW {};
struct PROCESS_INFORMATION {};
typedef STARTUPINFOW* LPSTARTUPINFOW;
typedef PROCESS_INFORMATION* LPPROCESS_INFORMATION;
struct SECURITY_ATTRIBUTES {};
typedef SECURITY_ATTRIBUTES* LPSECURITY_ATTRIBUTES;

extern "C" {
BOOL CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
HINSTANCE ShellExecuteW(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, int);
unsigned int WinExec(LPCSTR, unsigned int);
}

void bad_create_process_runtime_command_line(wchar_t* cmd_line) {
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    // BAD — non-literal lpCommandLine
    CreateProcessW(L"C:\\foo.exe", cmd_line, nullptr, nullptr,                // $ Alert
                   0, 0, nullptr, nullptr, &si, &pi);
}

void bad_create_process_runtime_app_name(LPCWSTR app, wchar_t* fixed) {
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    // BAD — non-literal lpApplicationName
    CreateProcessW(app, fixed, nullptr, nullptr,                              // $ Alert
                   0, 0, nullptr, nullptr, &si, &pi);
}

void bad_shell_execute_runtime_file(LPCWSTR file) {
    // BAD — non-literal lpFile
    ShellExecuteW(nullptr, L"open", file, nullptr, nullptr, 0);               // $ Alert
}

void bad_shell_execute_runtime_params(LPCWSTR params) {
    // BAD — non-literal lpParameters
    ShellExecuteW(nullptr, L"open", L"C:\\foo.exe", params, nullptr, 0);      // $ Alert
}

void bad_winexec_runtime(const char* cmd) {
    // BAD — non-literal lpCmdLine
    WinExec(cmd, 0);                                                          // $ Alert
}

void good_create_process_literals() {
    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    // GOOD — both lpApplicationName and lpCommandLine are literals.
    // Note: lpCommandLine to CreateProcessW is technically LPWSTR (mutable),
    // but a wide string literal cast to LPWSTR is still constant-foldable for CodeQL.
    wchar_t fixed_cmd[] = L"C:\\foo.exe --safe";
    CreateProcessW(L"C:\\foo.exe", fixed_cmd, nullptr, nullptr,
                   0, 0, nullptr, nullptr, &si, &pi);
}

void good_winexec_literal() {
    // GOOD — literal command line
    WinExec("C:\\Windows\\System32\\notepad.exe", 0);
}
