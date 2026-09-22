/**
 * test_asset_tags_sync_lock.cpp -- TU-inclusion seam over
 * asset_tags_plugin.cpp (#232, code-review F-codex-2): proves the S21 fix --
 * `sync` writes the state file while STILL holding the plugin's state mutex
 * -- without a production test hook and without a timing assumption.
 *
 * How: the store writes `<dest>.tmp`, and the test pre-creates that name as
 * a FIFO whose pipe buffer it has already filled. Three event-ordered steps:
 *   1. A blocking O_RDONLY open of the FIFO returns exactly when the plugin
 *      opens it for writing -- so the test never starts draining before the
 *      writer has arrived (an empty pipe would let a large write through in
 *      one go).
 *   2. The plugin's write(2) then parks: the pipe is full of junk and its
 *      payload is far larger than PIPE_BUF (a small write is atomic and would
 *      complete as soon as that much room appeared). The test drains one byte
 *      at a time until the payload's first byte shows -- at that instant the
 *      writer is provably inside write_state_file_atomic with most of its
 *      payload still to write -- and asserts `g_mu.try_lock()` FAILS.
 *      Moving the write outside the lock (the original defect, the review's
 *      M2 mutant) makes try_lock succeed.
 *   3. The writer thread re-opens the FIFO once its dispatch returns, so if
 *      a store regression stops touching `<dest>.tmp` the handshake still
 *      completes and the case FAILS instead of hanging the suite.
 * Nothing sleeps or polls a clock.
 *
 * TU-inclusion precedent: test_execution_artifacts_win_internals.cpp (#4392)
 * and autoruns_macos.cpp's seam. The plugin's C export is renamed away so
 * this executable does not define `yuzu_plugin_descriptor`; the in-TU
 * instance is driven through the real LocalDispatcher via a hand-built
 * descriptor, so execute() runs against a genuine CommandContext.
 *
 * POSIX-only body (mkfifo). The lock structure under test is identical on
 * Windows -- there is no per-OS leg in this plugin -- so nothing platform-
 * specific goes untested; the parking mechanism simply has no Windows twin.
 * Empty TU there, kept present for meson's unconditional source list.
 */
#if defined(_WIN32)

// Nothing to test on Windows -- see the file banner above.

#else // !defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

// TU-inclusion seam: neutralise the C export before pulling the plugin in,
// then build our own descriptor over the in-TU instance below.
#undef YUZU_PLUGIN_EXPORT
#define YUZU_PLUGIN_EXPORT(ClassName) /* no C export in the test executable */
#include "asset_tags_plugin.cpp"
#undef YUZU_PLUGIN_EXPORT

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <string>
#include <thread>

namespace {

using namespace yuzu::asset_tags;

AssetTagsPlugin& tu_plugin() {
    static AssetTagsPlugin p;
    return p;
}

int tu_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* params,
               size_t param_count) {
    yuzu::CommandContext cmd_ctx{ctx};
    yuzu::Params p{{params, param_count}};
    return tu_plugin().execute(cmd_ctx, action, p);
}

const YuzuPluginDescriptor kTuDescriptor{
    .abi_version = YUZU_PLUGIN_ABI_VERSION,
    .name = "asset_tags",
    .version = "0.1.0",
    .description = "asset_tags (TU-inclusion seam)",
    .actions = tu_plugin().actions(),
    .init = nullptr,
    .shutdown = nullptr,
    .execute = tu_execute,
    .sdk_version = YUZU_PLUGIN_SDK_VERSION,
    .action_descriptors = nullptr,
    .action_descriptor_count = 0,
};

// Fill the FIFO's pipe buffer through a non-blocking writer so the NEXT
// blocking writer parks on its first byte. Returns the junk byte count.
std::size_t fill_pipe(int wfd) {
    std::array<char, 65536> junk{};
    junk.fill('J');
    std::size_t total = 0;
    for (std::size_t chunk = junk.size(); chunk >= 1;) {
        const ssize_t n = ::write(wfd, junk.data(), chunk);
        if (n > 0) {
            total += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        chunk /= 2; // EAGAIN at this size: try smaller until 1 byte fails too
    }
    return total;
}

// One blocking read of exactly one byte; false on EOF or error.
bool read_one(int fd, char& c) {
    for (;;) {
        const ssize_t n = ::read(fd, &c, 1);
        if (n < 0 && errno == EINTR)
            continue;
        return n == 1;
    }
}

} // namespace

TEST_CASE("asset_tags sync writes the state file while holding g_mu (S21)",
          "[agent][asset_tags_sync_lock]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_lock_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);

    const fs::path dest = dir.path / "asset_tags.json";
    fs::path fifo = dest;
    fifo += ".tmp";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);

    // Reader first (non-blocking, so it needs no writer yet), then our own
    // writer, then fill, then drop our writer: the junk stays queued while
    // the reader is open, and the FIFO now has NO writer, which is what makes
    // the blocking open below a handshake with the plugin's own open.
    const int rfd = ::open(fifo.c_str(), O_RDONLY | O_NONBLOCK);
    REQUIRE(rfd >= 0);
    {
        const int wfd = ::open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
        REQUIRE(wfd >= 0);
        REQUIRE(fill_pipe(wfd) > 0);
        ::close(wfd);
    }
    REQUIRE(::fcntl(rfd, F_SETFL, 0) == 0); // reads below block on the event, never spin

    // Direct state setup -- no init(), so no store thread and no config. The
    // change log is pre-filled so the serialised payload is far larger than
    // PIPE_BUF and than one pipe page: a write that small is ATOMIC (the
    // kernel completes it in one go as soon as that much room exists), which
    // would let the writer finish and unlock before we look. A large write is
    // copied piecemeal as room appears and cannot complete while we hold the
    // pipe full.
    {
        std::lock_guard lock(g_mu);
        g_state = {};
        for (std::size_t i = 0; i < kMaxChangeLog; ++i)
            g_state.change_log.push_back(ChangeRecord{"role", std::string(kMaxValueBytes, 'o'),
                                                      std::string(kMaxValueBytes, 'n'),
                                                      static_cast<int64_t>(i)});
        REQUIRE(serialize_state(g_state).size() > 4 * 4096);
        g_store_path = dest;
    }

    // No REQUIRE (test-aborting) below this line: the writer thread must
    // always be released and joined.
    const char* value = "a";
    const std::array<YuzuParam, 1> params{{{"role", value}}};
    yuzu::agent::LocalDispatcher::Result result;
    std::atomic<bool> writer_done{false};
    std::thread writer([&] {
        yuzu::agent::LocalDispatcher dispatcher;
        result = dispatcher.run(&kTuDescriptor, "sync", params);
        writer_done.store(true);
        // Step 3: complete the handshake even if the dispatch never opened
        // the FIFO, so a store regression fails the case instead of hanging
        // it. Needs a reader (rfd is still open); nothing is written.
        const int w = ::open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
        if (w >= 0)
            ::close(w);
    });

    // Step 1: returns when SOME writer opens -- the plugin's, or the
    // thread's post-dispatch one.
    const int handshake = ::open(fifo.c_str(), O_RDONLY);
    CHECK(handshake >= 0);
    if (handshake >= 0)
        ::close(handshake);
    const bool arrived_parked = !writer_done.load();
    CHECK(arrived_parked); // false: the dispatch finished without writing through <dest>.tmp

    if (arrived_parked) {
        // Step 2: drain the junk byte by byte. Each byte we take lets the
        // parked writer put exactly one more in, so the pipe stays full and
        // the writer stays parked; the first non-junk byte is the payload's
        // opening brace.
        std::string payload;
        for (;;) {
            char c = 0;
            if (!read_one(rfd, c)) {
                FAIL_CHECK("FIFO closed before the payload arrived");
                break;
            }
            if (c != 'J') {
                payload.push_back(c);
                break;
            }
        }
        CHECK(payload == "{");

        // THE assertion: the writer is inside write_state_file_atomic and the
        // state mutex must still be held by it.
        const bool lock_was_free = g_mu.try_lock();
        CHECK_FALSE(lock_was_free);
        if (lock_was_free)
            g_mu.unlock();

        // Release: drain the rest of the payload; EOF follows the plugin's
        // close (the FIFO has no other writer).
        char buf[4096];
        for (;;) {
            const ssize_t n = ::read(rfd, buf, sizeof buf);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            payload.append(buf, static_cast<std::size_t>(n));
        }
        writer.join();

        CHECK(result.rc == 0);
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        // What crossed the pipe is the post-mutation snapshot, serialised
        // under the same hold.
        std::lock_guard lock(g_mu);
        CHECK(payload == serialize_state(g_state));
        CHECK(g_state.tags.at("role") == "a");
    } else {
        writer.join();
    }
    ::close(rfd);
    std::lock_guard lock(g_mu);
    g_store_path.clear();
}

#endif // !defined(_WIN32)
