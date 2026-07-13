/**
 * test_shutdown_pipe.cpp — pins the REAL ShutdownWatcher (agents/core/src/shutdown_watcher.hpp).
 *
 * WHY THIS EXISTS, and why it tests the real class rather than a copy of it.
 *
 * The agent's graceful shutdown runs through a self-pipe: the signal handler writes ONE byte,
 * and a watcher thread parked in read() wakes and runs the teardown. A single wrong flag
 * silently disables all of it — `pipe2(fds, O_CLOEXEC | O_NONBLOCK)` sets O_NONBLOCK on BOTH
 * descriptors, so the watcher's read() returns EAGAIN immediately, the thread exits within
 * microseconds, and SIGTERM stops triggering a graceful stop. Nothing LOOKS broken: the
 * process still dies via the signal's default disposition.
 *
 * That exact bug shipped once. The test at the time RE-IMPLEMENTED the pipe ("build it the
 * same way the watcher does") and so pinned a COPY — it passed while the real code was
 * broken. Hence the class now lives in a header and this file drives the real type. Testing a
 * copy is not testing. (governance Gate-8 cpp-safety.)
 */

#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "shutdown_watcher.hpp"

#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <thread>
#include <unistd.h>

using namespace std::chrono_literals;
using yuzu::agent::ShutdownWatcher;

TEST_CASE("ShutdownWatcher: the READ end blocks, the WRITE end does not, both are CLOEXEC",
          "[shutdown]") {
    std::atomic<int> wfd{-1};
    ShutdownWatcher w{wfd, [] { return true; }};
    REQUIRE(w.ok());

    // THE regression assertion. With O_NONBLOCK on the read end the watcher exits instantly
    // and graceful shutdown is silently dead. This asserts against the REAL fds the real
    // constructor created — the previous version asserted against a hand-built copy and
    // therefore could not catch this.
    CHECK((::fcntl(w.read_fd_for_test(), F_GETFL) & O_NONBLOCK) == 0);  // read end BLOCKS
    CHECK((::fcntl(w.write_fd_for_test(), F_GETFL) & O_NONBLOCK) != 0); // write end does NOT

    // Both ends CLOEXEC: the agent shells out constantly (trigger engine + several plugins),
    // and an inherited write end hands every child — including anything exec'd at lower
    // privilege — a lever to shut the agent down.
    CHECK((::fcntl(w.read_fd_for_test(), F_GETFD) & FD_CLOEXEC) != 0);
    CHECK((::fcntl(w.write_fd_for_test(), F_GETFD) & FD_CLOEXEC) != 0);

    // The handler's fd slot is published.
    CHECK(wfd.load() == w.write_fd_for_test());
}

TEST_CASE("ShutdownWatcher: a kSignal byte reaches the teardown callback", "[shutdown]") {
    std::atomic<int> wfd{-1};
    std::atomic<bool> tore_down{false};
    {
        ShutdownWatcher w{wfd, [&] {
                              tore_down = true;
                              return true;
                          }};
        REQUIRE(w.ok());

        // Nothing written yet: the watcher must still be PARKED. If the read end were
        // non-blocking it would already have exited — and SIGTERM would be a no-op.
        std::this_thread::sleep_for(120ms);
        CHECK_FALSE(tore_down.load());

        // Exactly what on_signal does.
        const char sig = ShutdownWatcher::kSignal;
        REQUIRE(::write(wfd.load(), &sig, 1) == 1);

        // The watcher must run the teardown. (The dtor joins, so leaving this scope waits.)
        for (int i = 0; i < 200 && !tore_down.load(); ++i)
            std::this_thread::sleep_for(5ms);
    }
    CHECK(tore_down.load());
}

TEST_CASE("ShutdownWatcher: the destructor's kQuit retires it WITHOUT running the teardown",
          "[shutdown]") {
    // ~ShutdownWatcher wakes the watcher with kQuit rather than closing the write end to EOF
    // it — closing would let a signal handler that had already loaded the fd write into a
    // RECYCLED descriptor. The watcher must wake and NOT call the teardown.
    std::atomic<int> wfd{-1};
    std::atomic<bool> tore_down{false};
    {
        ShutdownWatcher w{wfd, [&] {
                              tore_down = true;
                              return true;
                          }};
        REQUIRE(w.ok());
        // Leave the scope with no signal: the dtor sends kQuit and joins. Must not hang.
    }
    CHECK_FALSE(tore_down.load());
}

TEST_CASE("ShutdownWatcher: a signal arriving before the Agent exists must not CONSUME it",
          "[shutdown]") {
    // A signal during boot (before g_agent is published) hits a callback that returns false.
    // The watcher must KEEP WAITING. If it exited instead, it would be consumed and every
    // LATER signal — the real SIGTERM — would be a silent no-op, leaving the agent
    // unkillable by anything but SIGKILL.
    std::atomic<int> wfd{-1};
    std::atomic<int> calls{0};
    std::atomic<bool> agent_ready{false};
    std::atomic<bool> tore_down{false};

    ShutdownWatcher w{wfd, [&] {
                          ++calls;
                          if (!agent_ready.load())
                              return false; // "Agent not published yet" — keep waiting
                          tore_down = true;
                          return true;
                      }};
    REQUIRE(w.ok());

    // Early signal: callback says "not yet".
    const char sig = ShutdownWatcher::kSignal;
    REQUIRE(::write(wfd.load(), &sig, 1) == 1);
    for (int i = 0; i < 200 && calls.load() == 0; ++i)
        std::this_thread::sleep_for(5ms);
    CHECK(calls.load() == 1);
    CHECK_FALSE(tore_down.load());

    // The watcher must still be alive to serve the REAL signal.
    agent_ready = true;
    REQUIRE(::write(wfd.load(), &sig, 1) == 1);
    for (int i = 0; i < 200 && !tore_down.load(); ++i)
        std::this_thread::sleep_for(5ms);
    CHECK(tore_down.load()); // it was NOT consumed by the early signal
}

TEST_CASE("ShutdownWatcher: a late write on a retired watcher must not raise SIGPIPE",
          "[shutdown]") {
    // The fds are deliberately never closed. If the read end were closed while the write end
    // lived, a straggler handler's write() — or the dtor's own sentinel — would hit a pipe
    // with no reader, raise SIGPIPE (SIG_DFL in this process) and KILL the agent (exit 141).
    std::atomic<int> wfd{-1};
    int saved_wfd = -1;
    {
        ShutdownWatcher w{wfd, [] { return true; }};
        REQUIRE(w.ok());
        saved_wfd = w.write_fd_for_test();
    } // dtor: retires the watcher, does NOT close the fds

    // A straggler handler still holding the fd writes. It must be harmless — if this process
    // is still alive on the next line, there was no SIGPIPE.
    const char sig = ShutdownWatcher::kSignal;
    const ssize_t n = ::write(saved_wfd, &sig, 1);
    CHECK(n == 1);
    SUCCEED("no SIGPIPE — the process survived a late write");
}

#endif // !_WIN32
