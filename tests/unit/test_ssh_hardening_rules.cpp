/**
 * test_ssh_hardening_rules.cpp — Unit tests for the ssh_hardening plugin's
 * pure parsing/evaluation logic (ssh_hardening_rules.hpp).
 *
 * Covers: parse_sshd_config_content() line/Match/Include parsing, and the
 * evaluate_* compliance functions against the Mozilla Modern OpenSSH
 * baseline. Deliberately platform-independent (no filesystem access), so it
 * runs on every CI platform even though the plugin itself is Linux-only.
 */

#include "ssh_hardening_rules.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::ssh_hardening;

// ── parse_sshd_config_content ───────────────────────────────────────────────

TEST_CASE("parse: simple directives", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content(
        "Port 22\n"
        "PermitRootLogin no\n"
        "KexAlgorithms curve25519-sha256@libssh.org\n");

    REQUIRE(parsed.entries.size() == 3);
    CHECK(parsed.entries[0].kind == Entry::Kind::Directive);
    CHECK(parsed.entries[0].directive.keyword == "port");
    CHECK(parsed.entries[0].directive.value == "22");
    CHECK(parsed.entries[2].directive.keyword == "kexalgorithms");
    CHECK(parsed.entries[2].directive.value == "curve25519-sha256@libssh.org");
    CHECK_FALSE(parsed.hit_match);
}

TEST_CASE("parse: blank lines and comments are skipped", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content(
        "# a comment\n"
        "\n"
        "   \n"
        "  # indented comment\n"
        "Port 22\n");
    REQUIRE(parsed.entries.size() == 1);
    CHECK(parsed.entries[0].directive.keyword == "port");
}

TEST_CASE("parse: Keyword=value form is accepted", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content("Ciphers=aes256-ctr,aes128-ctr\n");
    REQUIRE(parsed.entries.size() == 1);
    CHECK(parsed.entries[0].directive.keyword == "ciphers");
    CHECK(parsed.entries[0].directive.value == "aes256-ctr,aes128-ctr");
}

TEST_CASE("parse: directive names are case-insensitive", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content("kExAlGoRiThMs foo\n");
    REQUIRE(parsed.entries.size() == 1);
    CHECK(parsed.entries[0].directive.keyword == "kexalgorithms");
}

TEST_CASE("parse: Match stops entry recording and sets hit_match", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content(
        "Ciphers aes256-ctr\n"
        "Match User anonymous\n"
        "PasswordAuthentication yes\n");
    REQUIRE(parsed.entries.size() == 1);
    CHECK(parsed.entries[0].directive.keyword == "ciphers");
    CHECK(parsed.hit_match);
}

TEST_CASE("parse: Include is captured as raw glob tokens at its file position",
          "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content(
        "Include /etc/ssh/sshd_config.d/*.conf\n"
        "Ciphers aes256-ctr\n");
    REQUIRE(parsed.entries.size() == 2);
    CHECK(parsed.entries[0].kind == Entry::Kind::Include);
    REQUIRE(parsed.entries[0].include_globs.size() == 1);
    CHECK(parsed.entries[0].include_globs[0] == "/etc/ssh/sshd_config.d/*.conf");
    CHECK(parsed.entries[1].kind == Entry::Kind::Directive);
}

TEST_CASE("parse: Include with multiple whitespace-separated patterns", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content("Include a.conf b.conf\n");
    REQUIRE(parsed.entries.size() == 1);
    REQUIRE(parsed.entries[0].include_globs.size() == 2);
    CHECK(parsed.entries[0].include_globs[0] == "a.conf");
    CHECK(parsed.entries[0].include_globs[1] == "b.conf");
}

TEST_CASE("parse: HostKey repeats are each their own entry", "[ssh_hardening][parse]") {
    auto parsed = parse_sshd_config_content(
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        "HostKey /etc/ssh/ssh_host_rsa_key\n");
    REQUIRE(parsed.entries.size() == 2);
    CHECK(parsed.entries[0].directive.value == "/etc/ssh/ssh_host_ed25519_key");
    CHECK(parsed.entries[1].directive.value == "/etc/ssh/ssh_host_rsa_key");
}

// ── first_value / all_values ────────────────────────────────────────────────

TEST_CASE("first_value: first occurrence wins (sshd_config semantics)",
          "[ssh_hardening][evaluate]") {
    std::vector<Directive> directives = {
        {"ciphers", "aes256-ctr"},
        {"ciphers", "3des-cbc"},
    };
    auto v = first_value(directives, "ciphers");
    REQUIRE(v.has_value());
    CHECK(*v == "aes256-ctr");
}

TEST_CASE("first_value: absent directive returns nullopt", "[ssh_hardening][evaluate]") {
    std::vector<Directive> directives = {{"port", "22"}};
    CHECK_FALSE(first_value(directives, "ciphers").has_value());
}

TEST_CASE("all_values: collects every HostKey occurrence in order", "[ssh_hardening][evaluate]") {
    std::vector<Directive> directives = {
        {"hostkey", "/etc/ssh/ssh_host_ed25519_key"},
        {"port", "22"},
        {"hostkey", "/etc/ssh/ssh_host_rsa_key"},
    };
    auto v = all_values(directives, "hostkey");
    REQUIRE(v.size() == 2);
    CHECK(v[0] == "/etc/ssh/ssh_host_ed25519_key");
    CHECK(v[1] == "/etc/ssh/ssh_host_rsa_key");
}

// ── evaluate_algorithm_directive ────────────────────────────────────────────

TEST_CASE("evaluate_algorithm_directive: exact approved list passes",
          "[ssh_hardening][evaluate]") {
    auto r = evaluate_algorithm_directive(
        "Ciphers", std::string("chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"),
        kApprovedCiphers);
    CHECK(r.passed);
    CHECK(r.severity == "INFO");
}

TEST_CASE("evaluate_algorithm_directive: weak algorithm fails", "[ssh_hardening][evaluate]") {
    auto r = evaluate_algorithm_directive("Ciphers", std::string("aes256-ctr,3des-cbc,arcfour"),
                                          kApprovedCiphers);
    CHECK_FALSE(r.passed);
    CHECK(r.severity == "HIGH");
    CHECK(r.detail.find("3des-cbc") != std::string::npos);
    CHECK(r.detail.find("arcfour") != std::string::npos);
    // aes256-ctr is approved, so it must NOT be reported as disallowed.
    CHECK(r.detail.find("aes256-ctr,") == std::string::npos);
}

TEST_CASE("evaluate_algorithm_directive: unset directive is MEDIUM, not a pass",
          "[ssh_hardening][evaluate]") {
    auto r = evaluate_algorithm_directive("KexAlgorithms", std::nullopt, kApprovedKexAlgorithms);
    CHECK_FALSE(r.passed);
    CHECK(r.severity == "MEDIUM");
}

TEST_CASE("evaluate_algorithm_directive: '+' modifier cannot be resolved -> MEDIUM",
          "[ssh_hardening][evaluate]") {
    auto r = evaluate_algorithm_directive("MACs", std::string("+umac-128@openssh.com"),
                                          kApprovedMacs);
    CHECK_FALSE(r.passed);
    CHECK(r.severity == "MEDIUM");
}

TEST_CASE("evaluate_algorithm_directive: '-' and '^' modifiers also flagged",
          "[ssh_hardening][evaluate]") {
    auto minus = evaluate_algorithm_directive("MACs", std::string("-hmac-md5"), kApprovedMacs);
    CHECK(minus.severity == "MEDIUM");
    auto caret =
        evaluate_algorithm_directive("MACs", std::string("^umac-128@openssh.com"), kApprovedMacs);
    CHECK(caret.severity == "MEDIUM");
}

TEST_CASE("evaluate_algorithm_directive: empty value is flagged", "[ssh_hardening][evaluate]") {
    auto r = evaluate_algorithm_directive("Ciphers", std::string(""), kApprovedCiphers);
    CHECK_FALSE(r.passed);
    CHECK(r.severity == "MEDIUM");
}

// ── evaluate_host_keys / classify_host_key_type ─────────────────────────────

TEST_CASE("classify_host_key_type: recognizes each key type", "[ssh_hardening][evaluate]") {
    CHECK(classify_host_key_type("/etc/ssh/ssh_host_ed25519_key") == "ed25519");
    CHECK(classify_host_key_type("/etc/ssh/ssh_host_rsa_key") == "rsa");
    CHECK(classify_host_key_type("/etc/ssh/ssh_host_ecdsa_key") == "ecdsa");
    CHECK(classify_host_key_type("/etc/ssh/ssh_host_dsa_key") == "dsa");
    CHECK(classify_host_key_type("/etc/ssh/ssh_host_unknown_key") == "unknown");
}

TEST_CASE("classify_host_key_type: ecdsa is not misclassified as dsa",
          "[ssh_hardening][evaluate]") {
    // "ecdsa" contains "dsa" as a substring -- the classifier must check
    // ecdsa before dsa or every ECDSA host key would be flagged as legacy DSA.
    CHECK(classify_host_key_type("/etc/ssh/ssh_host_ecdsa_key") == "ecdsa");
}

TEST_CASE("evaluate_host_keys: all approved types passes", "[ssh_hardening][evaluate]") {
    auto r = evaluate_host_keys({"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key",
                                 "/etc/ssh/ssh_host_ecdsa_key"});
    CHECK(r.passed);
    CHECK(r.severity == "INFO");
}

TEST_CASE("evaluate_host_keys: legacy dsa key fails", "[ssh_hardening][evaluate]") {
    auto r = evaluate_host_keys({"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_dsa_key"});
    CHECK_FALSE(r.passed);
    CHECK(r.severity == "HIGH");
    CHECK(r.detail.find("dsa") != std::string::npos);
}

TEST_CASE("evaluate_host_keys: no HostKey directives is MEDIUM, not a pass",
          "[ssh_hardening][evaluate]") {
    auto r = evaluate_host_keys({});
    CHECK_FALSE(r.passed);
    CHECK(r.severity == "MEDIUM");
}

// ── evaluate_ssh_hardening (end-to-end over a flattened directive stream) ──

TEST_CASE("evaluate_ssh_hardening: the Mozilla example config passes clean",
          "[ssh_hardening][evaluate]") {
    std::vector<Directive> effective = {
        {"hostkey", "/etc/ssh/ssh_host_ed25519_key"},
        {"hostkey", "/etc/ssh/ssh_host_rsa_key"},
        {"hostkey", "/etc/ssh/ssh_host_ecdsa_key"},
        {"kexalgorithms",
         "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,"
         "diffie-hellman-group-exchange-sha256"},
        {"ciphers", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
                    "aes256-ctr,aes192-ctr,aes128-ctr"},
        {"macs", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@"
                 "openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"},
    };

    auto results = evaluate_ssh_hardening(effective);
    REQUIRE(results.size() == 4);
    for (const auto& r : results) {
        CAPTURE(r.title, r.detail);
        CHECK(r.passed);
        CHECK(r.severity == "INFO");
    }
}

TEST_CASE("evaluate_ssh_hardening: a default/unhardened config fails every check",
          "[ssh_hardening][evaluate]") {
    std::vector<Directive> effective = {{"port", "22"}}; // nothing SSH-hardening-related set

    auto results = evaluate_ssh_hardening(effective);
    REQUIRE(results.size() == 4);
    for (const auto& r : results) {
        CAPTURE(r.title, r.detail);
        CHECK_FALSE(r.passed);
    }
}

TEST_CASE("evaluate_ssh_hardening: first-wins semantics mean a weak later Ciphers line "
          "does not override an earlier approved one",
          "[ssh_hardening][evaluate]") {
    std::vector<Directive> effective = {
        {"ciphers", "aes256-ctr"},
        {"ciphers", "3des-cbc"},
    };
    auto results = evaluate_ssh_hardening(effective);
    auto it = std::find_if(results.begin(), results.end(),
                           [](const auto& r) { return r.title == "Ciphers"; });
    REQUIRE(it != results.end());
    CHECK(it->passed);
}
