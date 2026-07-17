/**
 * test_certificates_macos.cpp -- pure parse/validate/mapping vectors for the
 * certificates plugin's macOS login-keychain support (macos_console_user.hpp,
 * A-1.11).
 *
 * Everything here runs against fixture strings -- no `stat`/`id`/`launchctl`/
 * `sudo`/`security` subprocess, no real console session, no macOS required --
 * because the helpers are pure by design (same header-for-testability pattern
 * as installed_apps_inventory.hpp / test_installed_apps_inventory.cpp). Runs
 * on EVERY host (incl. MSVC), same as test_dex_macos.cpp.
 *
 * The shell-injection-guard vectors (is_valid_username / is_valid_uid /
 * build_login_keychain_read_command) are the load-bearing ones: every value
 * this header validates ends up interpolated into a popen'd command line in
 * certificates_plugin.cpp, so "rejects an unsafe value" here is a direct
 * proxy for "never runs an attacker-influenced shell command."
 */

#include <catch2/catch_test_macros.hpp>

#include <macos_console_user.hpp>

#include <string>

using namespace yuzu::macos;

// ── parse_console_user_output ────────────────────────────────────────────────

TEST_CASE("parse_console_user_output trims whitespace around the stat payload",
         "[certificates][macos]") {
    SECTION("trailing newline, the common `stat -f%Su` case") {
        CHECK(parse_console_user_output("alice\n") == "alice");
    }
    SECTION("trailing CRLF") {
        CHECK(parse_console_user_output("alice\r\n") == "alice");
    }
    SECTION("leading and trailing blanks") {
        CHECK(parse_console_user_output("  alice  \n") == "alice");
    }
    SECTION("already-clean input is left alone") {
        CHECK(parse_console_user_output("alice") == "alice");
    }
    SECTION("empty input stays empty") {
        CHECK(parse_console_user_output("").empty());
    }
    SECTION("whitespace-only input becomes empty") {
        CHECK(parse_console_user_output("  \n\t ").empty());
    }
    SECTION("the no-console-user sentinel round-trips unchanged") {
        CHECK(parse_console_user_output("root\n") == "root");
    }
}

// ── is_no_console_user ───────────────────────────────────────────────────────

TEST_CASE("is_no_console_user identifies the login-window / headless sentinel",
         "[certificates][macos]") {
    CHECK(is_no_console_user("root"));
    CHECK(is_no_console_user(""));
    CHECK_FALSE(is_no_console_user("alice"));
    CHECK_FALSE(is_no_console_user("rootuser")); // exact match only, not a prefix
    CHECK_FALSE(is_no_console_user("toor"));
    // Case-sensitive by design: `stat -f%Su` always emits lowercase "root"
    // for the sentinel, so a literal "Root" is (if unusual) a real username,
    // not the no-session marker.
    CHECK_FALSE(is_no_console_user("Root"));
}

// ── is_valid_username (shell-injection guard) ────────────────────────────────

TEST_CASE("is_valid_username accepts the safe-identifier allowlist",
         "[certificates][macos]") {
    CHECK(is_valid_username("alice"));
    CHECK(is_valid_username("alice.smith"));
    CHECK(is_valid_username("alice_smith-2"));
    CHECK(is_valid_username("ALICE123"));
    // Syntactically valid as an identifier -- is_no_console_user is the
    // separate, semantic "no session" check; the two are orthogonal.
    CHECK(is_valid_username("root"));
}

TEST_CASE("is_valid_username rejects empty and shell-metacharacter input",
         "[certificates][macos]") {
    CHECK_FALSE(is_valid_username(""));
    CHECK_FALSE(is_valid_username("alice; rm -rf /"));
    CHECK_FALSE(is_valid_username("alice`whoami`"));
    CHECK_FALSE(is_valid_username("$(whoami)"));
    CHECK_FALSE(is_valid_username("alice space"));
    CHECK_FALSE(is_valid_username("alice\"quote"));
    CHECK_FALSE(is_valid_username("alice'quote"));
    CHECK_FALSE(is_valid_username("alice|pipe"));
    CHECK_FALSE(is_valid_username("alice&bg"));
    CHECK_FALSE(is_valid_username("../../etc/passwd"));
    CHECK_FALSE(is_valid_username("alice/bob"));
    CHECK_FALSE(is_valid_username("alice\nbob"));
    CHECK_FALSE(is_valid_username("alice\tbob"));
}

TEST_CASE("is_valid_username rejects option-like leading characters",
         "[certificates][macos]") {
    // A leading '-' would let `id -u <username>` misread the value as one
    // of its own flags rather than an account name to look up -- argument
    // injection, distinct from the shell-metacharacter checks above.
    CHECK_FALSE(is_valid_username("-G"));
    CHECK_FALSE(is_valid_username("--help"));
    CHECK_FALSE(is_valid_username("-a"));
    // A leading '.' is syntactically in the per-character allowlist but is
    // never how a real macOS account name starts; excluded defensively too.
    CHECK_FALSE(is_valid_username(".hidden"));
    // A non-leading '-' or '.' is still fine.
    CHECK(is_valid_username("a-b"));
    CHECK(is_valid_username("a.b"));
}

// ── is_valid_uid (shell-injection guard) ─────────────────────────────────────

TEST_CASE("is_valid_uid accepts numeric-only, non-empty input", "[certificates][macos]") {
    CHECK(is_valid_uid("501"));
    CHECK(is_valid_uid("0"));
    CHECK(is_valid_uid("1"));
    CHECK(is_valid_uid("4294967295"));
}

TEST_CASE("is_valid_uid rejects empty, non-numeric, and injection input",
         "[certificates][macos]") {
    CHECK_FALSE(is_valid_uid(""));
    CHECK_FALSE(is_valid_uid("abc"));
    CHECK_FALSE(is_valid_uid("50a"));
    CHECK_FALSE(is_valid_uid("-1"));
    CHECK_FALSE(is_valid_uid(" 501"));
    CHECK_FALSE(is_valid_uid("501 "));
    CHECK_FALSE(is_valid_uid("501; rm -rf /"));
    CHECK_FALSE(is_valid_uid("0x1F5"));
}

// ── Keychain path mapping ─────────────────────────────────────────────────────

TEST_CASE("system_keychain_path and root_keychain_path are the fixed system paths",
         "[certificates][macos]") {
    CHECK(system_keychain_path() == "/Library/Keychains/System.keychain");
    CHECK(root_keychain_path() ==
         "/System/Library/Keychains/SystemRootCertificates.keychain");
}

TEST_CASE("login_keychain_path builds a ~username-relative path from the username",
         "[certificates][macos]") {
    // ~username (not a bare ~) so the OUTER shell resolves it via that
    // specific account's directory-services home, independent of the
    // invoking (daemon) process's own $HOME -- see the function comment.
    CHECK(login_keychain_path("alice") == "~alice/Library/Keychains/login.keychain-db");
    CHECK(login_keychain_path("bob.smith") ==
         "~bob.smith/Library/Keychains/login.keychain-db");
}

// ── resolve_store_plan ───────────────────────────────────────────────────────

TEST_CASE("resolve_store_plan: store=login", "[certificates][macos]") {
    SECTION("console user present -> login only") {
        auto plan = resolve_store_plan("login", true);
        CHECK(plan.want_login);
        CHECK_FALSE(plan.want_system);
        CHECK_FALSE(plan.want_root);
        CHECK_FALSE(plan.sentinel_required);
    }
    SECTION("no console user -> unfulfillable, sentinel required") {
        auto plan = resolve_store_plan("login", false);
        CHECK(plan.sentinel_required);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.want_system);
        CHECK_FALSE(plan.want_root);
    }
}

TEST_CASE("resolve_store_plan: store=System is independent of console-user state",
         "[certificates][macos]") {
    for (bool has_console_user : {true, false}) {
        auto plan = resolve_store_plan("System", has_console_user);
        CHECK(plan.want_system);
        CHECK_FALSE(plan.want_root);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
}

TEST_CASE("resolve_store_plan: store=root is independent of console-user state",
         "[certificates][macos]") {
    for (bool has_console_user : {true, false}) {
        auto plan = resolve_store_plan("root", has_console_user);
        CHECK(plan.want_root);
        CHECK_FALSE(plan.want_system);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
}

TEST_CASE("resolve_store_plan: store=all", "[certificates][macos]") {
    SECTION("console user present -> system + root + login, never a sentinel") {
        auto plan = resolve_store_plan("all", true);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
    SECTION("no console user -> system + root only, login silently omitted") {
        auto plan = resolve_store_plan("all", false);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required); // System + root are still real results
    }
}

TEST_CASE("resolve_store_plan: unrecognized/default values behave like \"all\"",
         "[certificates][macos]") {
    SECTION("empty string (defensive -- the shared dispatcher always defaults to \"all\")") {
        auto plan = resolve_store_plan("", true);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK(plan.want_login);
    }
    SECTION("a Windows-flavoured store name passed out of habit") {
        auto plan = resolve_store_plan("MY", false);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK_FALSE(plan.want_login);
        CHECK_FALSE(plan.sentinel_required);
    }
    SECTION("a wholly unrecognized value") {
        auto plan = resolve_store_plan("bogus", true);
        CHECK(plan.want_system);
        CHECK(plan.want_root);
        CHECK(plan.want_login);
    }
}

// ── resolve_delete_keychain_path ─────────────────────────────────────────────

TEST_CASE("resolve_delete_keychain_path: \"root\" targets the root keychain",
         "[certificates][macos]") {
    auto path = resolve_delete_keychain_path("root");
    REQUIRE(path.has_value());
    CHECK(*path == root_keychain_path());
}

TEST_CASE("resolve_delete_keychain_path: \"MY\"/\"System\" preserve the System.keychain default",
         "[certificates][macos]") {
    auto sys = resolve_delete_keychain_path("System");
    REQUIRE(sys.has_value());
    CHECK(*sys == system_keychain_path());

    auto my = resolve_delete_keychain_path("MY"); // cross-platform dispatcher default
    REQUIRE(my.has_value());
    CHECK(*my == system_keychain_path());
}

TEST_CASE("resolve_delete_keychain_path: unsupported stores are rejected, "
         "never silently redirected",
         "[certificates][macos]") {
    // A destructive action must never target a keychain the caller didn't
    // ask for -- "login" (not implemented for delete) and "all" (no
    // single-keychain meaning) and garbage input all reject rather than
    // falling back to System.keychain.
    CHECK_FALSE(resolve_delete_keychain_path("login").has_value());
    CHECK_FALSE(resolve_delete_keychain_path("all").has_value());
    CHECK_FALSE(resolve_delete_keychain_path("").has_value());
    CHECK_FALSE(resolve_delete_keychain_path("bogus").has_value());
}

// ── build_login_keychain_read_command (shell-injection guard) ───────────────

TEST_CASE("build_login_keychain_read_command: caller already root -- no outer sudo hop",
         "[certificates][macos]") {
    // Mirrors quarantine_plugin.cpp's sudo_prefix(): today's shipped
    // LaunchDaemon runs as root, so `launchctl asuser` (which itself
    // requires root) needs no escalation -- only the inner drop to the
    // target console user does.
    auto cmd = build_login_keychain_read_command("501", "alice", /*caller_is_root=*/true);
    CHECK(cmd == "/bin/launchctl asuser 501 /usr/bin/sudo -n -u alice /usr/bin/security "
                "find-certificate -a -p ~alice/Library/Keychains/login.keychain-db "
                "2>/dev/null");
}

TEST_CASE("build_login_keychain_read_command: non-root caller escalates via an outer sudo",
         "[certificates][macos]") {
    // The target `_yuzu` least-privilege account (#1455) is NOT root, so it
    // must sudo to root itself before launchctl asuser will admit it -- this
    // is exactly the command the sudoers handoff grant needs to cover.
    auto cmd = build_login_keychain_read_command("501", "alice", /*caller_is_root=*/false);
    CHECK(cmd == "/usr/bin/sudo -n /bin/launchctl asuser 501 /usr/bin/sudo -n -u alice "
                "/usr/bin/security find-certificate -a -p "
                "~alice/Library/Keychains/login.keychain-db 2>/dev/null");
}

TEST_CASE("build_login_keychain_read_command rejects an invalid uid", "[certificates][macos]") {
    CHECK(build_login_keychain_read_command("abc", "alice", true).empty());
    CHECK(build_login_keychain_read_command("", "alice", true).empty());
    CHECK(build_login_keychain_read_command("501; rm -rf /", "alice", true).empty());
    // Invalid input is rejected the same way regardless of caller_is_root.
    CHECK(build_login_keychain_read_command("abc", "alice", false).empty());
}

TEST_CASE("build_login_keychain_read_command rejects an invalid username",
         "[certificates][macos]") {
    CHECK(build_login_keychain_read_command("501", "alice; rm -rf /", true).empty());
    CHECK(build_login_keychain_read_command("501", "", true).empty());
    CHECK(build_login_keychain_read_command("501", "alice`whoami`", true).empty());
    CHECK(build_login_keychain_read_command("501", "$(whoami)", true).empty());
    CHECK(build_login_keychain_read_command("501", "alice space", true).empty());
    CHECK(build_login_keychain_read_command("501", "-G", true).empty());
}

TEST_CASE("build_login_keychain_read_command rejects when both uid and username are invalid",
         "[certificates][macos]") {
    CHECK(build_login_keychain_read_command("", "", true).empty());
    CHECK(build_login_keychain_read_command("nope", "nope; rm -rf /", true).empty());
}
