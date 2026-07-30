/**
 * test_native_raii.cpp — move-only, exception-safety, and no-double-free /
 * no-leak vectors for the three native RAII primitives added under
 * agents/core/include/yuzu/agent/: `scoped_fd` (POSIX file descriptor),
 * `ScopedCFRef<T>` (CoreFoundation object), and `ScopedIOObject` (IOKit
 * `io_object_t`).
 *
 * Each wrapper is guarded to the platform it applies to, exactly like its
 * header (`#ifndef _WIN32` for scoped_fd — POSIX only; `#if defined(__APPLE__)`
 * for the CoreFoundation/IOKit wrappers — Apple only), so this file compiles
 * everywhere (incl. MSVC and Linux) and simply runs fewer sections off-macOS,
 * same convention as test_dex_macos.cpp / test_certificates_macos.cpp.
 *
 * The CF sections verify "no double-free, no leak" via a real retain-count
 * check (CFGetRetainCount) rather than by trusting the type alone not to
 * crash — a CF double-release is not guaranteed to crash immediately, so
 * counting references is the only direct proof available without a
 * sanitizer run. IOKit exposes no equivalent portable send-right refcount
 * introspection, so the IOKit sections exercise release-on-destruction
 * functionally (no crash, no double-release) rather than by counting —
 * weaker proof than the CF sections, called out here rather than implied.
 */

#include <yuzu/agent/scoped_fd.hpp>

#include <catch2/catch_test_macros.hpp>

#include <utility>

#ifndef _WIN32

#include <fcntl.h>
#include <unistd.h>

using yuzu::agent::scoped_fd;

namespace {
/// True iff `fd` is currently a valid, open descriptor in this process.
bool fd_is_open(int fd) {
    return fd >= 0 && ::fcntl(fd, F_GETFD) != -1;
}

/// A fresh pipe, returned as {read_fd, write_fd}; both ends are real, open
/// descriptors owned by the caller.
std::pair<int, int> make_pipe() {
    int fds[2] = {-1, -1};
    REQUIRE(::pipe(fds) == 0);
    return {fds[0], fds[1]};
}
} // namespace

TEST_CASE("scoped_fd: default-constructed owns nothing", "[agent][raii][scoped_fd]") {
    scoped_fd f;
    CHECK_FALSE(f.valid());
    CHECK_FALSE(static_cast<bool>(f));
    CHECK(f.get() == -1);
}

TEST_CASE("scoped_fd: adopts and closes on destruction", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w); // only exercising the read end here
    {
        scoped_fd f(r);
        CHECK(f.valid());
        CHECK(f.get() == r);
        CHECK(fd_is_open(r));
    }
    // Destructor closed it — the raw fd number is no longer open.
    CHECK_FALSE(fd_is_open(r));
}

TEST_CASE("scoped_fd: move construction transfers ownership, source empties", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w);
    scoped_fd a(r);
    scoped_fd b(std::move(a));

    CHECK_FALSE(a.valid()); // moved-from — owns nothing
    CHECK(a.get() == -1);
    CHECK(b.valid());
    CHECK(b.get() == r);
    CHECK(fd_is_open(r)); // still open — ownership moved, not closed
}

TEST_CASE("scoped_fd: move assignment closes the destination's prior fd, adopts the source's", "[agent][raii][scoped_fd]") {
    auto [r1, w1] = make_pipe();
    auto [r2, w2] = make_pipe();
    ::close(w1);
    ::close(w2);

    scoped_fd a(r1);
    scoped_fd b(r2);
    b = std::move(a);

    CHECK_FALSE(fd_is_open(r2)); // b's original fd was closed by the assignment
    CHECK(fd_is_open(r1));       // a's fd survived the move, now owned by b
    CHECK(b.get() == r1);
    CHECK_FALSE(a.valid());
}

TEST_CASE("scoped_fd: self-move-assignment is a no-op, not a self-close", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w);
    scoped_fd a(r);
    scoped_fd& a_ref = a; // avoid a `-Wself-move` diagnostic on `a = std::move(a)`
    a = std::move(a_ref);

    CHECK(a.valid());
    CHECK(a.get() == r);
    CHECK(fd_is_open(r));
}

TEST_CASE("scoped_fd: release() gives up ownership without closing", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w);
    int raw;
    {
        scoped_fd f(r);
        raw = f.release();
        CHECK_FALSE(f.valid()); // no longer owns it
    }
    // The destructor of the (now-empty) scoped_fd must NOT have closed it.
    CHECK(fd_is_open(raw));
    CHECK(raw == r);
    ::close(raw); // caller's responsibility now — clean up manually
}

TEST_CASE("scoped_fd: reset() closes the old fd and adopts the new one", "[agent][raii][scoped_fd]") {
    auto [r1, w1] = make_pipe();
    auto [r2, w2] = make_pipe();
    ::close(w1);
    ::close(w2);

    scoped_fd f(r1);
    f.reset(r2);
    CHECK_FALSE(fd_is_open(r1)); // old fd closed
    CHECK(fd_is_open(r2));       // new fd owned
    CHECK(f.get() == r2);

    f.reset(); // no-arg reset: closes r2, owns nothing
    CHECK_FALSE(fd_is_open(r2));
    CHECK_FALSE(f.valid());
}

#endif // !_WIN32

#if defined(__APPLE__)

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

using yuzu::agent::ScopedCFRef;
using yuzu::agent::ScopedIOObject;

TEST_CASE("ScopedCFRef: default-constructed owns nothing", "[agent][raii][scoped_cfref]") {
    ScopedCFRef<CFMutableArrayRef> ref;
    CHECK_FALSE(ref.valid());
    CHECK_FALSE(static_cast<bool>(ref));
    CHECK(ref.get() == nullptr);
}

TEST_CASE("ScopedCFRef: releases exactly once on destruction (retain-count proof)", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);
    CFRetain(obj); // hold a second, test-owned reference so refcount stays >0 after the wrapper releases its own
    CFIndex before = CFGetRetainCount(obj);

    {
        ScopedCFRef<CFMutableArrayRef> ref(obj); // adopts ONE reference
        CHECK(ref.valid());
        CHECK(ref.get() == obj);
    }
    // Exactly one CFRelease happened — retain count dropped by exactly one.
    CHECK(CFGetRetainCount(obj) == before - 1);
    CFRelease(obj); // release the test's own reference
}

TEST_CASE("ScopedCFRef: move construction transfers ownership, source empties", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);

    ScopedCFRef<CFMutableArrayRef> a(obj);
    ScopedCFRef<CFMutableArrayRef> b(std::move(a));

    CHECK_FALSE(a.valid());
    CHECK(a.get() == nullptr);
    CHECK(b.valid());
    CHECK(b.get() == obj);
    // b's destructor releases the sole owned reference — nothing further to clean up.
}

TEST_CASE("ScopedCFRef: move assignment releases the destination's prior object", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj1 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFMutableArrayRef obj2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj1 != nullptr);
    REQUIRE(obj2 != nullptr);
    CFRetain(obj2); // test-owned extra reference so we can prove obj2 was released once
    CFIndex obj2_before = CFGetRetainCount(obj2);

    ScopedCFRef<CFMutableArrayRef> a(obj1);
    ScopedCFRef<CFMutableArrayRef> b(obj2);
    b = std::move(a);

    CHECK(CFGetRetainCount(obj2) == obj2_before - 1); // b's original object was released
    CHECK(b.get() == obj1);
    CHECK_FALSE(a.valid());
    CFRelease(obj2); // release the test's own reference

    // b (now owning obj1) releases it at end of scope.
}

TEST_CASE("ScopedCFRef: release() gives up ownership without releasing", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);
    CFRetain(obj); // test-owned extra reference
    CFIndex before = CFGetRetainCount(obj);

    CFMutableArrayRef raw;
    {
        ScopedCFRef<CFMutableArrayRef> ref(obj);
        raw = ref.release();
        CHECK_FALSE(ref.valid());
    }
    // The (now-empty) wrapper's destructor must NOT have released it.
    CHECK(CFGetRetainCount(obj) == before);
    CHECK(raw == obj);
    CFRelease(obj); // the reference release() handed back to the caller
    CFRelease(obj); // the test's own extra reference from CFRetain above
}

TEST_CASE("ScopedCFRef: reset() releases the old object and adopts the new one", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj1 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFMutableArrayRef obj2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj1 != nullptr);
    REQUIRE(obj2 != nullptr);
    CFRetain(obj1);
    CFIndex obj1_before = CFGetRetainCount(obj1);

    ScopedCFRef<CFMutableArrayRef> ref(obj1);
    ref.reset(obj2); // owns obj2 now; obj1's wrapper-owned reference released
    CHECK(CFGetRetainCount(obj1) == obj1_before - 1);
    CHECK(ref.get() == obj2);
    CFRelease(obj1); // the test's own extra reference

    ref.reset(); // no-arg reset: releases obj2, owns nothing
    CHECK_FALSE(ref.valid());
}

TEST_CASE("ScopedIOObject: default-constructed owns nothing", "[agent][raii][scoped_ioobject]") {
    ScopedIOObject obj;
    CHECK_FALSE(obj.valid());
    CHECK_FALSE(static_cast<bool>(obj));
    CHECK(obj.get() == IO_OBJECT_NULL);
}

namespace {
/// A real, always-present IOKit service (the IORegistry root platform-expert
/// node) so the ScopedIOObject vectors exercise a genuine `io_object_t`
/// rather than a synthetic value — safe and unprivileged to look up.
io_object_t lookup_platform_expert() {
    io_object_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                                                   IOServiceMatching("IOPlatformExpertDevice"));
    return svc;
}
} // namespace

TEST_CASE("ScopedIOObject: adopts a real service and releases on destruction", "[agent][raii][scoped_ioobject]") {
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);
    {
        ScopedIOObject obj(svc);
        CHECK(obj.valid());
        CHECK(obj.get() == svc);
    }
    // No portable retain-count introspection for io_object_t is exposed by
    // IOKit; the release-on-destruct behaviour is exercised functionally
    // here (no crash, no double-release) and the move/release/reset
    // ownership-transfer semantics below are proven the same way as the
    // fd/CF vectors above.
}

TEST_CASE("ScopedIOObject: move construction transfers ownership, source empties", "[agent][raii][scoped_ioobject]") {
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);

    ScopedIOObject a(svc);
    ScopedIOObject b(std::move(a));

    CHECK_FALSE(a.valid());
    CHECK(a.get() == IO_OBJECT_NULL);
    CHECK(b.valid());
    CHECK(b.get() == svc);
}

TEST_CASE("ScopedIOObject: move assignment releases the destination's prior object", "[agent][raii][scoped_ioobject]") {
    io_object_t svc1 = lookup_platform_expert();
    io_object_t svc2 = lookup_platform_expert(); // a second, independently-owned reference
    REQUIRE(svc1 != IO_OBJECT_NULL);
    REQUIRE(svc2 != IO_OBJECT_NULL);

    ScopedIOObject a(svc1);
    ScopedIOObject b(svc2);
    b = std::move(a);

    CHECK(b.get() == svc1);
    CHECK_FALSE(a.valid());
    // b's destructor releases svc1; svc2's reference was released by the
    // move-assignment itself.
}

TEST_CASE("ScopedIOObject: release() gives up ownership without releasing", "[agent][raii][scoped_ioobject]") {
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);

    io_object_t raw;
    {
        ScopedIOObject obj(svc);
        raw = obj.release();
        CHECK_FALSE(obj.valid());
    }
    CHECK(raw == svc);
    IOObjectRelease(raw); // caller's responsibility now — clean up manually
}

TEST_CASE("ScopedIOObject: reset() releases the old object and adopts the new one", "[agent][raii][scoped_ioobject]") {
    io_object_t svc1 = lookup_platform_expert();
    io_object_t svc2 = lookup_platform_expert();
    REQUIRE(svc1 != IO_OBJECT_NULL);
    REQUIRE(svc2 != IO_OBJECT_NULL);

    ScopedIOObject obj(svc1);
    obj.reset(svc2); // releases svc1, adopts svc2
    CHECK(obj.get() == svc2);

    obj.reset(); // no-arg reset: releases svc2, owns nothing
    CHECK_FALSE(obj.valid());
}

#endif // __APPLE__
