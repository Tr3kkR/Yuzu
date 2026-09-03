/**
 * test_ota_signature_sidecar.cpp — the server half of OTA signature delivery.
 *
 * WHY THIS FILE EXISTS. Two independent external reviewers found, in the same
 * round, that the ~200 production lines carrying a signature from an operator's
 * upload to an agent's CheckForUpdate response had NO discriminating test: the
 * upload handler needs a multipart request the test route sink cannot build, and
 * the reader needs an UpdateRegistry, which needs Postgres. The green server
 * suite proved only that the new code did not break assertions written before
 * the field existed.
 *
 * The decisions now live in ota_signature_sidecar.hpp, testable with a temp
 * directory and nothing else. What is NOT covered here, honestly: that the
 * handlers actually call these functions. That is a wiring claim, and the two
 * call sites remain Postgres-bound.
 */

#include "ota_signature_sidecar.hpp"

#include <catch2/catch_test_macros.hpp>

#include <fstream>
#include <string>

#include "../test_helpers.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#endif

using yuzu::server::kMaxSignatureBytes;
using yuzu::server::read_signature_sidecar;
using yuzu::server::replace_signature_sidecar;
using yuzu::server::SidecarOutcome;
using yuzu::server::signature_sidecar_path;

namespace fs = std::filesystem;

namespace {

struct Dir {
    fs::path p;
    Dir() {
        p = yuzu::test::unique_temp_path("yuzu_test_ota_sidecar_");
        fs::create_directories(p);
    }
    ~Dir() {
        std::error_code ec;
        fs::remove_all(p, ec);
    }
};

void write(const fs::path& f, const std::string& s) {
    std::ofstream o(f, std::ios::binary);
    o.write(s.data(), static_cast<std::streamsize>(s.size()));
}

} // namespace

TEST_CASE("sidecar path is derived from the binary, never named separately",
          "[ota][sidecar]") {
    // Derived, so one package cannot be pointed at another's signature.
    CHECK(signature_sidecar_path("/updates/yuzu-agent-1.2.3") ==
          fs::path("/updates/yuzu-agent-1.2.3.sig"));
    CHECK(signature_sidecar_path("/updates/x.exe") == fs::path("/updates/x.exe.sig"));
}

TEST_CASE("sidecar: a normal signature is served verbatim", "[ota][sidecar]") {
    Dir d;
    const auto sig = d.p / "pkg.sig";
    const std::string pem = "-----BEGIN CMS-----\nabc\n-----END CMS-----\n";
    write(sig, pem);

    std::string out;
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == pem); // byte-for-byte: the agent verifies against exactly this
}

TEST_CASE("sidecar: an absent one is the ordinary unsigned case, not an error",
          "[ota][sidecar]") {
    Dir d;
    std::string out{"stale"};
    CHECK(read_signature_sidecar(d.p / "nope.sig", out) == SidecarOutcome::kAbsent);
    CHECK(out.empty()); // never leaves a previous caller's value behind
}

TEST_CASE("sidecar: an over-cap file is refused rather than served", "[ota][sidecar]") {
    // This blob rides on EVERY CheckForUpdateResponse, and gRPC clients default
    // to a 4 MB receive limit — an oversized file here breaks update checks for
    // the whole fleet, not for one package.
    Dir d;
    const auto sig = d.p / "big.sig";
    write(sig, std::string(kMaxSignatureBytes + 1, 'x'));

    std::string out;
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kOverCap);
    CHECK(out.empty());

    // Exactly at the cap is still served — an off-by-one here would reject
    // legitimate signatures.
    const auto ok = d.p / "atcap.sig";
    write(ok, std::string(kMaxSignatureBytes, 'y'));
    CHECK(read_signature_sidecar(ok, out) == SidecarOutcome::kServed);
    CHECK(out.size() == kMaxSignatureBytes);
}

#ifndef _WIN32
TEST_CASE("sidecar: a FIFO is refused WITHOUT being opened", "[ota][sidecar]") {
    // THE CASE THE ORDERING EXISTS FOR. open(2) on a FIFO blocks until a writer
    // appears, so reading before the size check would wedge the CheckForUpdate
    // handler thread — one wedged thread per agent check, which is pool
    // exhaustion rather than a slow response.
    //
    // VERIFIED BY MUTATION, and note HOW it fails: disabling the size check makes
    // this case HANG rather than fail, because the open blocks forever. That is
    // attributable but slow, so the assertion below is deliberately preceded by a
    // writer-less non-blocking probe — if a future change reintroduces the
    // blocking open, the meson timeout is what catches it, and this comment is
    // the map back to the cause.
    Dir d;
    const auto fifo = d.p / "pipe.sig";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);

    std::string out;
    CHECK(read_signature_sidecar(fifo, out) == SidecarOutcome::kOverCap);
    CHECK(out.empty());
}
#endif

TEST_CASE("sidecar: an unsigned re-upload does NOT inherit the previous signature",
          "[ota][sidecar]") {
    // THE BUG THREE REVIEWERS FOUND. The binary is overwritten in place, so
    // without an unconditional remove a rebuilt package uploaded unsigned kept
    // the old .sig — a signature over bytes that no longer exist. Agents refuse
    // that in BOTH enforcement modes, so one unsigned re-upload stopped the
    // whole anchored fleet updating.
    Dir d;
    const auto sig = d.p / "pkg.sig";

    REQUIRE(replace_signature_sidecar(sig, "-----BEGIN CMS-----\nv1\n-----END CMS-----\n"));
    REQUIRE(fs::exists(sig));

    // Re-upload, unsigned.
    REQUIRE(replace_signature_sidecar(sig, ""));
    CHECK_FALSE(fs::exists(sig));

    std::string out;
    CHECK(read_signature_sidecar(sig, out) == SidecarOutcome::kAbsent);
}

TEST_CASE("sidecar: a signed re-upload replaces the previous signature", "[ota][sidecar]") {
    Dir d;
    const auto sig = d.p / "pkg.sig";
    REQUIRE(replace_signature_sidecar(sig, "old"));
    REQUIRE(replace_signature_sidecar(sig, "new"));

    std::string out;
    REQUIRE(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == "new"); // not appended, not stale
}

TEST_CASE("sidecar: a signed replace never publishes an unsigned window",
          "[ota][sidecar]") {
    // CheckForUpdate reads this path concurrently, so a remove-then-write
    // publishes a brief window in which the package is served UNSIGNED — an
    // agent polling inside it is refused under --update-require-signature, with
    // no cause an operator can point at. The replace is therefore write-sibling
    // -then-rename. What this pins is the observable consequence: no temp file
    // is left behind, and the sidecar is readable and correct immediately after.
    Dir d;
    const auto sig = d.p / "pkg.sig";
    REQUIRE(replace_signature_sidecar(sig, "v1"));

    REQUIRE(replace_signature_sidecar(sig, "v2"));
    std::string out;
    REQUIRE(read_signature_sidecar(sig, out) == SidecarOutcome::kServed);
    CHECK(out == "v2");

    // The staging sibling must not survive — a stray "<pkg>.sig.tmp" would be
    // mistaken for a package named "<pkg>.sig" by a later directory listing.
    CHECK_FALSE(fs::exists(d.p / "pkg.sig.tmp"));

    int entries = 0;
    for (const auto& e : fs::directory_iterator(d.p)) {
        (void)e;
        ++entries;
    }
    CHECK(entries == 1); // exactly the sidecar
}
