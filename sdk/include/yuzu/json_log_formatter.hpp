#pragma once

#include <spdlog/formatter.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/details/fmt_helper.h>

#include <chrono>
#include <string>

namespace yuzu {

/// Custom spdlog formatter that outputs JSON structured log lines.
/// Format: {"timestamp":"...","level":"...","component":"...","thread":N,"message":"..."}
class JsonLogFormatter final : public spdlog::formatter {
public:
    explicit JsonLogFormatter(std::string component = "server")
        : component_(std::move(component)) {}

    void format(const spdlog::details::log_msg& msg,
                spdlog::memory_buf_t& dest) override {
        // ISO 8601 timestamp with milliseconds
        auto time_t = std::chrono::system_clock::to_time_t(msg.time);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            msg.time.time_since_epoch()) % 1000;
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &time_t);
#else
        gmtime_r(&time_t, &tm_buf);
#endif

        char ts[32];
        auto len = std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);
        auto ts_str = std::string(ts, len) + "." +
            std::to_string(ms.count()) + "Z";
        // Pad ms to 3 digits
        auto ms_val = ms.count();
        if (ms_val < 10) ts_str = std::string(ts, len) + ".00" + std::to_string(ms_val) + "Z";
        else if (ms_val < 100) ts_str = std::string(ts, len) + ".0" + std::to_string(ms_val) + "Z";
        else ts_str = std::string(ts, len) + "." + std::to_string(ms_val) + "Z";

        // Escape the message for JSON
        auto raw_msg = std::string_view(msg.payload.data(), msg.payload.size());
        auto escaped = json_escape(raw_msg);

        auto level_str = spdlog::level::to_string_view(msg.level);

        auto line = std::string("{\"timestamp\":\"") + ts_str +
            "\",\"level\":\"" + std::string(level_str.data(), level_str.size()) +
            "\",\"component\":\"" + component_ +
            "\",\"thread\":" + std::to_string(msg.thread_id) +
            ",\"message\":\"" + escaped + "\"}\n";

        dest.append(line.data(), line.data() + line.size());
    }

    [[nodiscard]] std::unique_ptr<formatter> clone() const override {
        return std::make_unique<JsonLogFormatter>(component_);
    }

private:
    static std::string json_escape(std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x",
                                      static_cast<unsigned int>(c));
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }
        return out;
    }

    std::string component_;
};

}  // namespace yuzu
