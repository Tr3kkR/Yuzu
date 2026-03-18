#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <format>
#include <cmath>

namespace yuzu {

// ── Label set (key-value pairs for metric dimensions) ────────────────────────

using Labels = std::vector<std::pair<std::string, std::string>>;

inline std::string labels_key(const Labels& labels) {
    std::string key;
    for (const auto& [k, v] : labels) {
        if (!key.empty()) key += ',';
        key += k + "=\"" + v + "\"";
    }
    return key;
}

inline std::string labels_prometheus(const Labels& labels) {
    if (labels.empty()) return {};
    std::string out = "{";
    for (size_t i = 0; i < labels.size(); ++i) {
        if (i > 0) out += ',';
        out += labels[i].first + "=\"" + labels[i].second + "\"";
    }
    out += '}';
    return out;
}

// ── Counter ─────────────────────────────────────────────────────────────────

class Counter {
public:
    void increment(double v = 1.0) {
        std::lock_guard lock(mu_);
        value_ += v;
    }
    double value() const {
        std::lock_guard lock(mu_);
        return value_;
    }

private:
    mutable std::mutex mu_;
    double value_ = 0.0;
};

// ── Gauge ───────────────────────────────────────────────────────────────────

class Gauge {
public:
    void set(double v) {
        std::lock_guard lock(mu_);
        value_ = v;
    }
    void increment(double v = 1.0) {
        std::lock_guard lock(mu_);
        value_ += v;
    }
    void decrement(double v = 1.0) {
        std::lock_guard lock(mu_);
        value_ -= v;
    }
    double value() const {
        std::lock_guard lock(mu_);
        return value_;
    }

private:
    mutable std::mutex mu_;
    double value_ = 0.0;
};

// ── Histogram ───────────────────────────────────────────────────────────────

class Histogram {
public:
    explicit Histogram(std::vector<double> buckets = default_buckets())
        : boundaries_(std::move(buckets)),
          bucket_counts_(boundaries_.size() + 1, 0) {}

    void observe(double value) {
        std::lock_guard lock(mu_);
        sum_ += value;
        count_++;
        for (size_t i = 0; i < boundaries_.size(); ++i) {
            if (value <= boundaries_[i]) {
                bucket_counts_[i]++;
            }
        }
        bucket_counts_.back()++;  // +Inf bucket
    }

    struct Snapshot {
        double sum;
        uint64_t count;
        std::vector<double> boundaries;
        std::vector<uint64_t> cumulative_counts;
    };

    Snapshot snapshot() const {
        std::lock_guard lock(mu_);
        Snapshot s;
        s.sum = sum_;
        s.count = count_;
        s.boundaries = boundaries_;
        // Make cumulative
        s.cumulative_counts.resize(boundaries_.size() + 1);
        uint64_t cumulative = 0;
        for (size_t i = 0; i < boundaries_.size(); ++i) {
            cumulative += bucket_counts_[i];
            s.cumulative_counts[i] = cumulative;
        }
        s.cumulative_counts.back() = count_;
        return s;
    }

    static std::vector<double> default_buckets() {
        return {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0};
    }

private:
    mutable std::mutex mu_;
    std::vector<double> boundaries_;
    std::vector<uint64_t> bucket_counts_;
    double sum_ = 0.0;
    uint64_t count_ = 0;
};

// ── Labeled metric families ─────────────────────────────────────────────────

template <typename T>
class MetricFamily {
public:
    T& labels(const Labels& l) {
        auto key = labels_key(l);
        std::lock_guard lock(mu_);
        return instances_[key].metric;
    }

    T& no_labels() {
        return labels({});
    }

    struct Entry {
        Labels label_set;
        T metric;
    };

    void clear() {
        std::lock_guard lock(mu_);
        instances_.clear();
    }

    // For serialization
    std::vector<std::pair<std::string, T*>> all() {
        std::lock_guard lock(mu_);
        std::vector<std::pair<std::string, T*>> result;
        for (auto& [key, entry] : instances_) {
            result.emplace_back(key, &entry.metric);
        }
        return result;
    }

private:
    struct LabeledInstance {
        T metric;
    };
    std::mutex mu_;
    std::unordered_map<std::string, LabeledInstance> instances_;
};

// ── Registry — collects all metrics and serializes to Prometheus format ─────

class MetricsRegistry {
public:
    struct MetricInfo {
        std::string name;
        std::string help;
        std::string type;  // "counter", "gauge", "histogram"
    };

    Counter& counter(const std::string& name) {
        std::lock_guard lock(mu_);
        return counters_[name].no_labels();
    }

    Counter& counter(const std::string& name, const Labels& l) {
        std::lock_guard lock(mu_);
        return counters_[name].labels(l);
    }

    Gauge& gauge(const std::string& name) {
        std::lock_guard lock(mu_);
        return gauges_[name].no_labels();
    }

    Gauge& gauge(const std::string& name, const Labels& l) {
        std::lock_guard lock(mu_);
        return gauges_[name].labels(l);
    }

    Histogram& histogram(const std::string& name) {
        std::lock_guard lock(mu_);
        return histograms_[name].no_labels();
    }

    Histogram& histogram(const std::string& name, const Labels& l) {
        std::lock_guard lock(mu_);
        return histograms_[name].labels(l);
    }

    void clear_gauge_family(const std::string& name) {
        std::lock_guard lock(mu_);
        if (auto it = gauges_.find(name); it != gauges_.end()) {
            it->second.clear();
        }
    }

    void describe(const std::string& name, const std::string& help,
                  const std::string& type) {
        std::lock_guard lock(mu_);
        descriptions_[name] = {name, help, type};
    }

    std::string serialize() {
        std::lock_guard lock(mu_);
        std::string out;

        // Counters
        for (auto& [name, family] : counters_) {
            write_type_help(out, name, "counter");
            for (auto& [key, metric] : family.all()) {
                auto lbl = key.empty() ? "" : ("{" + key + "}");
                out += std::format("{}{} {}\n", name, lbl, metric->value());
            }
        }

        // Gauges
        for (auto& [name, family] : gauges_) {
            write_type_help(out, name, "gauge");
            for (auto& [key, metric] : family.all()) {
                auto lbl = key.empty() ? "" : ("{" + key + "}");
                out += std::format("{}{} {}\n", name, lbl, metric->value());
            }
        }

        // Histograms
        for (auto& [name, family] : histograms_) {
            write_type_help(out, name, "histogram");
            for (auto& [key, metric] : family.all()) {
                auto snap = metric->snapshot();
                auto base_labels = key.empty() ? "" : key;

                for (size_t i = 0; i < snap.boundaries.size(); ++i) {
                    auto le = format_double(snap.boundaries[i]);
                    auto lbl = base_labels.empty()
                        ? std::format("le=\"{}\"", le)
                        : std::format("{},le=\"{}\"", base_labels, le);
                    out += std::format("{}_bucket{{{}}} {}\n",
                        name, lbl, snap.cumulative_counts[i]);
                }
                // +Inf bucket
                auto inf_lbl = base_labels.empty()
                    ? "le=\"+Inf\""
                    : std::format("{},le=\"+Inf\"", base_labels);
                out += std::format("{}_bucket{{{}}} {}\n",
                    name, inf_lbl, snap.count);

                auto sum_lbl = base_labels.empty() ? "" : ("{" + base_labels + "}");
                out += std::format("{}_sum{} {}\n", name, sum_lbl, snap.sum);
                out += std::format("{}_count{} {}\n", name, sum_lbl, snap.count);
            }
        }

        return out;
    }

private:
    void write_type_help(std::string& out, const std::string& name,
                         const std::string& default_type) {
        auto it = descriptions_.find(name);
        if (it != descriptions_.end()) {
            out += std::format("# HELP {} {}\n", name, it->second.help);
            out += std::format("# TYPE {} {}\n", name, it->second.type);
        } else {
            out += std::format("# TYPE {} {}\n", name, default_type);
        }
    }

    static std::string format_double(double v) {
        if (v == std::floor(v) && v < 1e6) {
            return std::format("{}", static_cast<long long>(v));
        }
        return std::format("{}", v);
    }

    std::mutex mu_;
    std::unordered_map<std::string, MetricFamily<Counter>> counters_;
    std::unordered_map<std::string, MetricFamily<Gauge>> gauges_;
    std::unordered_map<std::string, MetricFamily<Histogram>> histograms_;
    std::unordered_map<std::string, MetricInfo> descriptions_;
};

}  // namespace yuzu
