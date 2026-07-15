/**
 * guard_fsevents.cpp — see guard_fsevents.hpp.
 *
 * Modern FSEvents wiring: FSEventStreamSetDispatchQueue onto ONE private
 * serial queue (no dedicated CFRunLoop thread, no runloop marshalling).
 * Teardown ordering per stream is Stop → Invalidate → Release →
 * dispatch_sync_f(no-op) — the synchronous no-op drains any in-flight
 * callback on the serial queue, so an Entry (the stream's context pointer)
 * is never freed while a callback can still dereference it, and no emit runs
 * after unwatch()/stop() return.
 */

#include <yuzu/agent/guard_fsevents.hpp>

#if defined(__APPLE__)

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

#include <map>
#include <mutex>
#include <utility>

namespace yuzu::agent {

struct FsEventsWatchCore::Impl {
    // Entries are heap-allocated so each FSEventStreamContext.info stays a
    // stable pointer for the stream's whole life. The map is guarded by m_;
    // callbacks never touch the map — only their own Entry.
    struct Entry {
        Impl* impl{nullptr};
        std::string key;
        FSEventStreamRef stream{nullptr};
    };

    std::mutex m;
    std::map<std::string, std::unique_ptr<Entry>> entries;
    dispatch_queue_t queue{nullptr};
    // Set once in start(), cleared only after the final drain in stop() —
    // callbacks read them without m. Happens-before proof: start() writes them
    // under m; watch() (which must follow start()) re-acquires m before
    // FSEventStreamStart hands the stream to the queue, and libdispatch's
    // enqueue/dequeue ordering carries that edge into every callback. On the
    // teardown side no callback survives the dispatch_sync_f drain, after
    // which stop() is the only toucher.
    FsWatchEmitFn emit;
    FsWatchFaultFn fault;
    bool started{false};

    // FSEvents C callback — static member so it can name Entry (Impl is a
    // private nested type; an anonymous-namespace function could not).
    static void callback(ConstFSEventStreamRef stream, void* info, size_t num_events,
                         void* event_paths, const FSEventStreamEventFlags event_flags[],
                         const FSEventStreamEventId event_ids[]);
};

namespace {

void drain_noop(void*) {}

// Stop → Invalidate → Release. Safe from any thread for dispatch-queue
// streams; the caller drains the queue afterwards before freeing the Entry.
void teardown_stream(FSEventStreamRef stream) {
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
}

// Kernel/daemon could not attribute the change precisely: coalescing overflow
// (MustScanSubDirs, {Kernel,User}Dropped, EventIdsWrapped), the watched root
// itself moved/deleted/created (RootChanged — WatchRoot), or volume churn under
// the path (Mount/Unmount). Consumers must re-read state, not trust the path.
constexpr FSEventStreamEventFlags kReconcileFlags =
    kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagRootChanged |
    kFSEventStreamEventFlagMount | kFSEventStreamEventFlagUnmount |
    kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagUserDropped |
    kFSEventStreamEventFlagEventIdsWrapped;

} // namespace

void FsEventsWatchCore::Impl::callback(ConstFSEventStreamRef /*stream*/, void* info,
                                       size_t num_events, void* event_paths,
                                       const FSEventStreamEventFlags event_flags[],
                                       const FSEventStreamEventId /*event_ids*/[]) {
    auto* entry = static_cast<Entry*>(info);
    // Without kFSEventStreamCreateFlagUseCFTypes the paths arrive as char**.
    auto** paths = static_cast<char**>(event_paths);
    for (size_t i = 0; i < num_events; ++i) {
        FsWatchEvent ev;
        ev.key = entry->key;
        if (paths && paths[i])
            ev.path = paths[i];
        ev.must_reconcile = (event_flags[i] & kReconcileFlags) != 0;
        if (entry->impl->emit)
            entry->impl->emit(ev);
    }
}

FsEventsWatchCore::FsEventsWatchCore() : impl_(std::make_unique<Impl>()) {}

FsEventsWatchCore::~FsEventsWatchCore() { stop(); }

void FsEventsWatchCore::start(FsWatchEmitFn emit, FsWatchFaultFn fault) {
    std::lock_guard lk(impl_->m);
    if (impl_->started)
        return;
    impl_->emit = std::move(emit);
    impl_->fault = std::move(fault);
    impl_->queue = dispatch_queue_create("com.yuzu.guardian.fsevents", DISPATCH_QUEUE_SERIAL);
    impl_->started = true;
}

std::expected<void, std::string> FsEventsWatchCore::watch(const std::string& key,
                                                          const std::string& path) {
    std::lock_guard lk(impl_->m);
    if (!impl_->started || !impl_->queue)
        return std::unexpected("FSEvents watch core is not started");
    // Reserve the map slot BEFORE creating the stream: the only throwing
    // operation (node allocation) happens while nothing needs cleanup, so a
    // started stream can never leak with a dangling context (sec-M1).
    auto [it, inserted] = impl_->entries.try_emplace(key);
    if (!inserted)
        return std::unexpected("duplicate watch key '" + key + "'");

    auto entry = std::make_unique<Impl::Entry>();
    entry->impl = impl_.get();
    entry->key = key;

    CFStringRef cf_path =
        CFStringCreateWithFileSystemRepresentation(kCFAllocatorDefault, path.c_str());
    if (!cf_path) {
        impl_->entries.erase(it);
        return std::unexpected("CFString conversion failed for '" + path + "'");
    }
    const void* values[1] = {cf_path};
    CFArrayRef cf_paths = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
    if (!cf_paths) {
        CFRelease(cf_path);
        impl_->entries.erase(it);
        return std::unexpected("CFArray creation failed for '" + path + "'");
    }

    // The context struct is copied by FSEventStreamCreate; only entry's address
    // must stay stable (it does — heap, freed after the post-teardown drain).
    FSEventStreamContext ctx{0, entry.get(), nullptr, nullptr, nullptr};
    FSEventStreamRef stream = FSEventStreamCreate(
        kCFAllocatorDefault, &Impl::callback, &ctx, cf_paths, kFSEventStreamEventIdSinceNow,
        /*latency*/ 0.0,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |
            kFSEventStreamCreateFlagWatchRoot);
    CFRelease(cf_paths);
    CFRelease(cf_path);
    if (!stream) {
        impl_->entries.erase(it);
        return std::unexpected("FSEventStreamCreate failed for '" + path + "'");
    }

    entry->stream = stream;
    FSEventStreamSetDispatchQueue(stream, impl_->queue);
    if (!FSEventStreamStart(stream)) {
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        impl_->entries.erase(it);
        return std::unexpected("FSEventStreamStart failed for '" + path + "'");
    }
    it->second = std::move(entry);
    return {};
}

void FsEventsWatchCore::unwatch(const std::string& key) {
    // The whole teardown (extract + stop/invalidate + drain) runs under m so
    // concurrent unwatch()/stop() serialize — the header promises thread-safe
    // teardown, and an unlocked drain raced stop()'s queue release (C-1).
    // Holding m across dispatch_sync_f cannot deadlock: callbacks never take m.
    std::lock_guard lk(impl_->m);
    auto it = impl_->entries.find(key);
    if (it == impl_->entries.end())
        return; // unknown key — idempotent no-op
    std::unique_ptr<Impl::Entry> entry = std::move(it->second);
    impl_->entries.erase(it);
    if (entry && entry->stream)
        teardown_stream(entry->stream);
    if (impl_->queue)
        dispatch_sync_f(impl_->queue, nullptr, &drain_noop); // drain in-flight callbacks
    // entry (the stream's context target) is freed only now, post-drain.
}

void FsEventsWatchCore::stop() {
    // Fully serialized with watch()/unwatch() under m, same deadlock argument
    // as unwatch() — callbacks never take m.
    std::lock_guard lk(impl_->m);
    if (!impl_->started)
        return;
    impl_->started = false;
    auto entries = std::move(impl_->entries);
    impl_->entries.clear();
    for (auto& [key, entry] : entries)
        if (entry && entry->stream)
            teardown_stream(entry->stream);
    if (impl_->queue) {
        dispatch_sync_f(impl_->queue, nullptr, &drain_noop); // no emit runs past this point
        dispatch_release(impl_->queue);
        impl_->queue = nullptr;
    }
    // Callbacks are fully drained — safe to drop them (and the entries) now.
    impl_->emit = nullptr;
    impl_->fault = nullptr;
}

} // namespace yuzu::agent

#else // !__APPLE__ — stub so callers/tests build everywhere (dex_macos convention)

namespace yuzu::agent {

struct FsEventsWatchCore::Impl {};

FsEventsWatchCore::FsEventsWatchCore() : impl_(std::make_unique<Impl>()) {}
FsEventsWatchCore::~FsEventsWatchCore() = default;
void FsEventsWatchCore::start(FsWatchEmitFn, FsWatchFaultFn) {}
std::expected<void, std::string> FsEventsWatchCore::watch(const std::string&, const std::string&) {
    return std::unexpected("FSEvents watch core is only available on macOS");
}
void FsEventsWatchCore::unwatch(const std::string&) {}
void FsEventsWatchCore::stop() {}

} // namespace yuzu::agent

#endif // __APPLE__
