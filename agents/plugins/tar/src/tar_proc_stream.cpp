/**
 * tar_proc_stream.cpp — ProcEventRing implementation (see tar_proc_stream.hpp).
 *
 * Platform-agnostic: the bounded push→pull bridge shared by the ETW (Windows) and
 * Endpoint Security (macOS) process collectors. No platform headers.
 */

#include "tar_proc_stream.hpp"

#include <utility>

namespace yuzu::tar {

bool ProcEventRing::push(ProcEvent ev) {
    std::lock_guard<std::mutex> lk(mu_);
    if (buf_.size() >= cap_) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    buf_.push_back(std::move(ev));
    return true;
}

std::vector<ProcEvent> ProcEventRing::drain() {
    std::vector<ProcEvent> out;
    std::lock_guard<std::mutex> lk(mu_);
    out.swap(buf_);
    // swap() leaves buf_ with zero capacity; re-reserve so the next push() under the
    // lock cannot reallocate. The no-reallocation-in-the-handler invariant the ctor
    // establishes (a realloc could throw std::bad_alloc across the ETW/ES C frame)
    // must survive every drain, not just the first.
    buf_.reserve(cap_);
    return out;
}

} // namespace yuzu::tar
