/**
 * Drives Agent::run() through its real registration and Subscribe reconnect
 * loop.  The test-local gRPC service is deliberately not an installed service:
 * it binds an ephemeral loopback port and is destroyed with this test.
 */

#ifndef _WIN32

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/updater.hpp>

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent.grpc.pb.h"
#include "test_helpers.hpp"

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace apb = yuzu::agent::v1;

namespace {

class OtaDisabledLifecycleService final : public apb::AgentService::Service {
public:
    grpc::Status Register(grpc::ServerContext*, const apb::RegisterRequest*,
                          apb::RegisterResponse* response) override {
        int registration = 0;
        {
            std::lock_guard lock(mu);
            registration = ++registrations;
        }
        response->set_accepted(true);
        response->set_session_id("ota-disabled-session-" + std::to_string(registration));
        cv.notify_all();
        return grpc::Status::OK;
    }

    grpc::Status Subscribe(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<apb::CommandRequest, apb::CommandResponse>* stream) override {
        int subscription = 0;
        {
            std::lock_guard lock(mu);
            subscription = ++subscriptions;
        }
        cv.notify_all();
        if (subscription == 1) {
            apb::CommandRequest command;
            command.set_command_id("ota-disabled-first-command");
            command.set_plugin("missing_test_plugin");
            command.set_action("first-command");
            if (!stream->Write(command))
                return grpc::Status::CANCELLED;
            apb::CommandResponse response;
            if (!stream->Read(&response))
                return grpc::Status::CANCELLED;
            if (response.command_id() != command.command_id() ||
                response.status() != apb::CommandResponse::REJECTED)
                return grpc::Status{grpc::StatusCode::FAILED_PRECONDITION,
                                    "unexpected first-command response"};
            {
                std::lock_guard lock(mu);
                first_command_rejected = true;
            }
            cv.notify_all();
            // A server-streaming handler stays alive until the agent's
            // session-loss path cancels its client context below.
            while (!context->IsCancelled())
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return grpc::Status::CANCELLED;
        }

        apb::CommandResponse ignored;
        while (!context->IsCancelled() && stream->Read(&ignored)) {}
        return grpc::Status::OK;
    }

    grpc::Status CheckForUpdate(grpc::ServerContext*, const apb::CheckForUpdateRequest*,
                                apb::CheckForUpdateResponse*) override {
        {
            std::lock_guard lock(mu);
            ++update_checks;
        }
        cv.notify_all();
        return grpc::Status::OK;
    }

    grpc::Status Heartbeat(grpc::ServerContext*, const apb::HeartbeatRequest*,
                           apb::HeartbeatResponse* response) override {
        // The agent turns NOT_FOUND into a Subscribe cancellation and a fresh
        // Register. Only emit it after the first command was delivered.
        std::lock_guard lock(mu);
        if (first_command_rejected)
            return grpc::Status{grpc::StatusCode::NOT_FOUND, "test session expired"};
        response->set_acknowledged(true);
        return grpc::Status::OK;
    }

    bool wait_for_second_registration() {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, std::chrono::seconds(15), [this] {
            return registrations >= 2 && subscriptions >= 2 && first_command_rejected;
        });
    }

    int registration_count() const {
        std::lock_guard lock(mu);
        return registrations;
    }

    int subscription_count() const {
        std::lock_guard lock(mu);
        return subscriptions;
    }

    int update_check_count() const {
        std::lock_guard lock(mu);
        return update_checks;
    }

    bool first_command_was_rejected() const {
        std::lock_guard lock(mu);
        return first_command_rejected;
    }

private:
    mutable std::mutex mu;
    std::condition_variable cv;
    int registrations{0};
    int subscriptions{0};
    int update_checks{0};
    bool first_command_rejected{false};
};

struct LoopbackHarness {
    OtaDisabledLifecycleService service;
    std::unique_ptr<grpc::Server> server;
    int port{0};

    LoopbackHarness() {
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
        builder.RegisterService(&service);
        server = builder.BuildAndStart();
    }

    ~LoopbackHarness() {
        if (server) {
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
            server->Wait();
        }
    }
};

struct AgentStopGuard {
    yuzu::agent::Agent& agent;

    ~AgentStopGuard() { agent.stop(); }
};

struct FileBackup {
    fs::path path;
    bool existed{false};
    std::vector<char> contents;

    explicit FileBackup(fs::path input) : path(std::move(input)), existed(fs::exists(path)) {
        if (!existed)
            return;
        std::ifstream input_file(path, std::ios::binary);
        contents.assign(std::istreambuf_iterator<char>{input_file}, std::istreambuf_iterator<char>{});
    }

    ~FileBackup() {
        std::error_code error;
        if (existed) {
            std::ofstream output_file(path, std::ios::binary | std::ios::trunc);
            output_file.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        } else {
            fs::remove(path, error);
        }
    }
};

struct ExecutableSidecarLock {
    int fd{-1};

    explicit ExecutableSidecarLock(const fs::path& executable) {
        const auto path = executable.parent_path() / ".yuzu_agent_ota_sidecar_test.lock";
        fd = ::open(path.c_str(), O_CREAT | O_RDWR, 0600);
        if (fd >= 0 && ::flock(fd, LOCK_EX) != 0) {
            (void)::close(fd);
            fd = -1;
        }
    }

    ~ExecutableSidecarLock() {
        if (fd >= 0) {
            (void)::flock(fd, LOCK_UN);
            (void)::close(fd);
        }
    }

    [[nodiscard]] bool locked() const noexcept { return fd >= 0; }
};

std::vector<char> read_bytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

void write_bytes(const fs::path& path, const std::vector<char>& contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

} // namespace

TEST_CASE("disabled OTA survives registration, first command, and reconnect without update RPC",
          "[agent][updater][no-auto-update][grpc]") {
    LoopbackHarness harness;
    REQUIRE(harness.server);
    REQUIRE(harness.port != 0);

    yuzu::test::TempDir temp{"yuzu_test_ota_disabled_lifecycle-"};
    const auto plugin_dir = temp.path / "plugins";
    const auto data_dir = temp.path / "data";
    REQUIRE(fs::create_directories(plugin_dir));
    REQUIRE(fs::create_directories(data_dir));

    yuzu::agent::Config config;
    config.server_address = "127.0.0.1:" + std::to_string(harness.port);
    config.agent_id = "ota-disabled-lifecycle-agent";
    config.plugin_dir = plugin_dir;
    config.data_dir = data_dir;
    config.tls_enabled = false;
    config.auto_provision_cert = false;
    config.auto_update = false;
    config.heartbeat_interval = std::chrono::seconds(1);
    config.inventory_disable = true;
    config.dex_disable = true;
    config.spark_disable = true;

    // Agent::run() calls current_executable_path(), so seed sidecars beside the
    // actual test executable, not a synthetic updater path. A flock serializes
    // this exceptional fixed-path probe across shared-identity test processes.
    // FileBackup restores any pre-existing build artifact on assertion exit.
    const auto executable = yuzu::agent::current_executable_path();
    const ExecutableSidecarLock sidecar_lock{executable};
    REQUIRE(sidecar_lock.locked());
    const auto old_binary = fs::path{executable.string() + ".old"};
    const auto verified_marker = executable.parent_path() / ".yuzu-update-verified";
    const FileBackup old_backup{old_binary};
    const FileBackup marker_backup{verified_marker};
    const std::vector<char> old_sentinel{'o', 'l', 'd', '-', 's', 'e', 'n', 't', 'i', 'n', 'e', 'l'};
    const std::vector<char> marker_sentinel{'m', 'a', 'r', 'k', 'e', 'r', '-', 's', 'e', 'n', 't', 'i', 'n', 'e', 'l'};
    write_bytes(old_binary, old_sentinel);
    write_bytes(verified_marker, marker_sentinel);

    auto agent = yuzu::agent::Agent::create(std::move(config));
    REQUIRE(agent);
    std::jthread runner([&] { agent->run(); });
    const AgentStopGuard stop_agent{*agent};

    const bool completed = harness.service.wait_for_second_registration();

    REQUIRE(completed);
    CHECK(harness.service.registration_count() >= 2);
    CHECK(harness.service.subscription_count() >= 2);
    CHECK(harness.service.first_command_was_rejected());
    CHECK(harness.service.update_check_count() == 0);
    CHECK(read_bytes(old_binary) == old_sentinel);
    CHECK(read_bytes(verified_marker) == marker_sentinel);
}

#endif
