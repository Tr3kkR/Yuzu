# Resource Ledger — macOS Endpoint Security development bundle

Range: `d295db964b0e3fa3fec7573f9fc9141c8c41f389..HEAD` (the final implementation
commit, including
governance corrections). This ledger covers the modified C++ updater path and
the new loopback lifecycle test. Packaging-script subprocesses are Python or
shell resources and are outside the C++ resource-ledger inventory.

| Resource | Owner | Acquisition | Release / transfer | Failure cleanup |
|---|---|---|---|---|
| Updater filesystem maintenance decision | `Updater` owned by `Agent` shared pointer | `Agent::run()` constructs and retains the existing updater | No new raw resource; `perform_startup_maintenance()` calls existing rollback/cleanup only when enabled | Disabled mode returns before any updater filesystem mutation; existing enabled-mode error handling is unchanged. |
| Loopback gRPC server | `LoopbackHarness::server` (`std::unique_ptr<grpc::Server>`) | `grpc::ServerBuilder::BuildAndStart()` after registering the member service | Destructor calls `Shutdown(deadline)` then `Wait()` before members are destroyed; no ownership transfer | Null server is asserted before agent construction. Destructor tolerates an empty server. |
| gRPC service / callback context | `LoopbackHarness::service` value member | Registered by address with its owning `ServerBuilder` during harness construction | Harness declaration order keeps `server` destroyed before `service`; server is shut down/waited first | If build/start returns null, no server owns the service and the test fails before creating the agent. |
| Agent runner thread | `std::jthread runner` | Starts `Agent::run()` after successful `Agent::create()` | `AgentStopGuard` stops the agent before `jthread` destruction; `jthread` then joins automatically | Catch2 assertion/timeout unwinding invokes `AgentStopGuard`, then joins; no joinable-thread termination path or detach. |
| Temporary plugin/data paths and SQLite files | `yuzu::test::TempDir` | Creates a `yuzu_test_`-prefixed test directory | RAII destructor removes the task-owned directory after agent/thread teardown | Construction failure prevents agent startup; no shared fixed path. |
| Executable-adjacent OTA sidecar test lock | `ExecutableSidecarLock` test value | `open(O_CREAT|O_RDWR)` plus advisory `flock(LOCK_EX)` on the test executable's parent | Destructor unlocks and closes the fd after `FileBackup` restoration | A failed open fails the test before sidecars are touched; the lock serializes the unavoidable fixed `.old`/marker probe across shared-identity processes. |
| Executable-adjacent OTA sidecar bytes | `FileBackup` test values | Snapshot any existing `.old` and marker before writing test sentinels | Destructors restore original bytes or remove only the sentinels this test created | Destructors run during assertion unwinding while the lock remains held, preventing concurrent backup/restore races. |
| Lifecycle synchronization state | `OtaDisabledLifecycleService` mutex, condition variable and value fields | Service construction | Value destruction after gRPC server shutdown | Every predicate update is under `mu` and followed by `notify_all`; wait predicate reads under the same mutex. |

No new HANDLE, raw socket, `FILE*`, SQLite handle/statement, OpenSSL object,
mapped library, allocated C string, C-ABI-owned buffer, `release()` transfer, or
cast is introduced in the C++ diff. The one new test-only fd is owned above. The packaging-only
`--verify-plugin-signature` CLI plumbing calls the existing verifier and owns no
new OS resource.
