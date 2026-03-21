#pragma once

#include <sqlite3.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

struct Notification {
    int64_t id{0};
    int64_t timestamp{0}; // epoch seconds
    std::string level;    // "info", "warn", "error", "success"
    std::string title;
    std::string message;
    bool read{false};
    bool dismissed{false};
};

class NotificationStore {
public:
    explicit NotificationStore(const std::filesystem::path& db_path);
    ~NotificationStore();

    NotificationStore(const NotificationStore&) = delete;
    NotificationStore& operator=(const NotificationStore&) = delete;

    bool is_open() const;

    /// Create a new notification. Returns the assigned id.
    int64_t create(const std::string& level, const std::string& title, const std::string& message);

    /// List all unread, non-dismissed notifications (newest first).
    std::vector<Notification> list_unread(int limit = 50) const;

    /// List all notifications (newest first).
    std::vector<Notification> list_all(int limit = 100, int offset = 0) const;

    /// Mark a notification as read.
    void mark_read(int64_t id);

    /// Dismiss a notification (soft-delete).
    void dismiss(int64_t id);

    /// Count unread, non-dismissed notifications.
    std::size_t count_unread() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
};

} // namespace yuzu::server
