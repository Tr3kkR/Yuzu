// Test fixture for cpp/yuzu/plugin-command-exec-non-literal.
//
// File path is treated as if it were agents/plugins/example/src/test.cpp
// by the CodeQL test harness (the path is rewritten via the .qlref file
// or, if the harness runs in-tree, by being placed under the matching
// directory). For local validation, copy into a real plugin path or use
// the sentinel-style "fake-extractor-input" approach.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

void bad_system_with_string_var(const std::string& cmd) {
    // BAD — non-literal first argument
    std::system(cmd.c_str());                                    // $ Alert
}

void bad_popen_with_concat(const char* user_input) {
    // BAD — string concatenation produces non-literal
    std::string composed = std::string("/usr/bin/foo ") + user_input;
    FILE* p = popen(composed.c_str(), "r");                      // $ Alert
    if (p) pclose(p);
}

void bad_execvp_with_runtime_path(const char* path) {
    char* const argv[] = {const_cast<char*>("foo"), nullptr};
    // BAD — runtime path
    execvp(path, argv);                                          // $ Alert
}

void good_system_literal() {
    // GOOD — string literal argument
    std::system("/usr/bin/uptime");
}

void good_popen_literal() {
    // GOOD — string literal argument
    FILE* p = popen("/usr/bin/uname -r", "r");
    if (p) pclose(p);
}

void good_execvp_literal_path() {
    char* const argv[] = {const_cast<char*>("uname"), const_cast<char*>("-r"), nullptr};
    // GOOD — literal path
    execvp("/usr/bin/uname", argv);
}

void good_constexpr_path() {
    // GOOD — constant-foldable
    constexpr const char* kPath = "/usr/bin/whoami";
    std::system(kPath);
}
