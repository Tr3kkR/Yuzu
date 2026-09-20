# Resource Ledger - #4606 latency instrumentation (`Guardian T_detect` / `T_wire` / `T_server`)

This ledger lists every lock, buffer, callback context and borrowed view the #4606 benchmark
instrumentation introduces or moves, with its owner and release path, for the C++ diff on branch
`worktree-spark-4606-criterion10-instrumentation`. A Resource Ledger is a policy-floor artifact
(CLAUDE.md standing rule 2), so it is a standalone file rather than a line in a PR description or a
governance transcript. The Gate 1 summary of the governance run carried the first two rows; the
remaining rows were added as later fix rounds moved locks or added the shared neutraliser, and the
Gate 8 reviewers (`cpp-safety`, `security-guardian`) re-derived them independently.

Nothing in this change adds a file descriptor, HANDLE, SOCKET, `FILE*`, `sqlite3*`/`sqlite3_stmt*`,
OpenSSL or BCrypt object, allocated C string, mapped library, temp path, subprocess or thread. No
callback is registered; the one existing callback context it touches keeps its capture list.

## Agent: `agents/core/src/guardian_spark_runtime.{hpp,cpp}`, `guardian_spark_timing.{hpp,cpp}`, `agent.cpp`

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `last_eval_timings_mu_` (`std::mutex`) and `last_eval_timings_` (`std::vector<EvalTimingRecord>`) | `GuardianSparkRuntime` members, non-copyable, RAII | class construction | class destruction | Leaf lock: held only across the move-assign at the tail of `evaluate_key` and the copy in `last_eval_timings_for_test()`, always through `std::lock_guard`; never nested under `registry_mu_`, `eval_mu` or any other lock; no I/O under it. The move-assign is `noexcept`, so there is no failure path. |
| `staged` (`std::vector<EvalTimingRecord>`) | Local to `evaluate_key` | Populated in the `registry_mu_` commit section (`reserve(planned * 2)`) | Function exit, or moved into `last_eval_timings_` after the log lines are written | Owns its strings; no borrowed views. Every early return before staging leaves it empty. It is not read after the move. |
| `eval_lk` (`std::unique_lock` on the key's `eval_mu`; was `std::lock_guard`) | Function-scope RAII | `evaluate_key` entry | One explicit `unlock()` after the outbox waker and before any log I/O; scope exit on every earlier return | Same mutex as before, only the wrapper type and one unlock point changed. It is never re-locked, every return before the unlock releases by RAII, and nothing after the unlock touches per-key state. |
| `stream_write_mu_` scope in `send_guardian_outbox_entry` | `std::lock_guard` in an inner block | Before the stream null check | End of the inner block, before the `T_wire` log call | `return Retain` from inside the block is RAII-safe. The log runs strictly after `ok` is captured and inside `try`/`catch(...)`, so a log failure can never turn a real `Sent` into `Retain`. |
| `set_event_sink` lambda (callback context capturing `this`; existing) | `AgentImpl` | Existing | Existing | The capture list is unchanged. The body only adds a `try`/`catch(...)`-wrapped `T_wire` log after `emit_guardian_event` returns (that function now returns its `bool`). |
| `id_token` (`guardian_spark_timing.cpp`) | Pure function returning an owning `std::string` | Per call | Temporary, dies at the end of the enclosing `std::format` full-expression | Takes a `const std::string&` of a live record member; no view is stored. |

## Shared header and server: `common/include/yuzu/log_token.hpp`, `server/core/src/guardian_ingest.cpp`, `guaranteed_state_store.{hpp,cpp}`, `web_utils.hpp`

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `log_token(std::string_view)` / `log_id_token(std::string_view)` | Pure header-only functions returning owning `std::string`; the `string_view` parameter is borrowed for the call only | Per call | Returned string is a temporary or a local of the caller | Allocation failure throws `bad_alloc`. The `T_server` call sits inside the existing best-effort `try`/`catch(...)` block. The replay, conflict and error warn lines and the parse-failure warn call it outside a `try`; that is the same allocation class `sanitize_label` had on those lines (it also copied the string), and this code already accepts it. |
| `T_server` block (`ingest_guardian_response`) | Locals only (`std::string` temporaries, `int64_t` values) | Per Inserted, non-observation event | Block scope | No lock is held and no I/O other than the `spdlog::info` call; wrapped in `try`/`catch(...)` so it cannot escape onto the gRPC ingest thread. Runs after the outcome switch and before the observers, changes no outcome and returns nothing. |
| `EventInsertResult::committed_wall_ns` | Plain `int64_t` value member of a returned struct, in memory only | Set right after `txn.commit()` succeeds | Struct lifetime | Never persisted; `0` for every non-Inserted outcome. |
| `audit_token` forwarding to `log_token` | Inline function, no state | n/a | n/a | Behaviour is byte-identical to the body it replaced (pinned by `test_log_token.cpp` and `test_web_utils.cpp`). |

## Trigger rows and invariants this change was checked against

- Spark detection layer row: no `mtx_` is taken on a worker or callback; no mechanism `watch()`/`unwatch()` calls `emit()` or `fault()`; `spark_engine.*`, `spark_mechanism.*`, `hard_exit.hpp` and `reconcile_rule_locked()` are untouched.
- Durable command idempotency row: not triggered. The `agent.cpp` hunks are inside `send_guardian_outbox_entry` and the drift-sink lambda, not the Subscribe command loop's claim/record/release sites.
- `common/include/` firewall: `log_token.hpp` is pure decision code (no I/O, no store or wire types, no trust-boundary authority), so it needs no annotation in CLAUDE.md.
- Known and recorded, not resolved here: the log lines are written synchronously on the Spark consumer, convergence and send-worker threads, so a blocked log sink stalls whichever thread is writing. That is a flip precondition in `docs/spark-flip-gate.md` section 7, adjudicated ACCEPT-WITH-PRECONDITION by the architect Gate 8 reviewer.
