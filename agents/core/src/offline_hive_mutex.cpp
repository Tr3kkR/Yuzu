#include <yuzu/agent/offline_hive_mutex.hpp>

namespace yuzu::agent {

std::mutex& offline_hive_mutex() {
    static std::mutex m;
    return m;
}

} // namespace yuzu::agent
