#pragma once

/**
 * test_log_capture.hpp — RAII spdlog default-logger capture into a string.
 *
 * Promoted from the inline block in test_licensing_sync.cpp's
 * "k_agent never appears in the blob or in captured logs" test (governance
 * CON-S4 — promote-at-second-user; second user:
 * test_guardian_engine_spark_reconcile.cpp #2238).
 *
 * A separate header rather than folding into test_helpers.hpp: this pulls in
 * spdlog's ostream sink, which most test_helpers.hpp consumers don't need.
 */

#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <sstream>
#include <string>

namespace yuzu::test {

/// RAII spdlog default-logger capture into a string.
///
/// RESTORE AND QUIESCE BEFORE text(): call stop() (or let the destructor run)
/// BEFORE asserting on text(), AND stop/join every component that may still
/// log through the captured logger — text() reads the underlying stream
/// without the ostream sink's lock, so a still-running worker thread writing
/// through a pre-restore logger copy (a shared_ptr it captured before stop())
/// is a data race against the read.
struct LogCapture {
    explicit LogCapture(spdlog::level::level_enum lvl = spdlog::level::trace)
        : prev_(spdlog::default_logger()), prev_level_(spdlog::get_level()) {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss_);
        auto logger = std::make_shared<spdlog::logger>("test_log_capture", sink);
        logger->set_level(lvl);
        spdlog::set_default_logger(logger);
        spdlog::set_level(lvl);
    }

    /// Restore the previous default logger + level. Idempotent.
    void stop() {
        if (stopped_)
            return;
        spdlog::set_default_logger(prev_);
        spdlog::set_level(prev_level_);
        stopped_ = true;
    }

    /// Captured text so far. Only safe to call after stop() (see class doc).
    [[nodiscard]] std::string text() const { return oss_.str(); }

    ~LogCapture() { stop(); }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;
    LogCapture(LogCapture&&) = delete;
    LogCapture& operator=(LogCapture&&) = delete;

private:
    std::ostringstream oss_;
    std::shared_ptr<spdlog::logger> prev_;
    spdlog::level::level_enum prev_level_;
    bool stopped_{false};
};

} // namespace yuzu::test
