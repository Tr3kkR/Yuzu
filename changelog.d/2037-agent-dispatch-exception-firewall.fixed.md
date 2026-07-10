- **Agent no longer crashes under concurrent `execute_bundle` dispatch on Windows (#2037).** A C++
  exception thrown outside the plugin's `execute()` call (e.g. in metrics, output-flush, protobuf
  construction, or the gRPC stream write) escaped the dispatch thread pool's worker and triggered
  `std::terminate()`/`abort()`, killing the whole agent process — observed as `yuzu-agent.exe`
  exiting with 0xC0000409 under bundles with 3+ concurrent steps. The dispatch thread pool now
  contains any escaped exception at the worker boundary, and the affected command/step returns a
  terminal `FAILURE` status (with error detail `agent dispatch error: <what>`) instead of hanging
  until the server's timeout or bringing down the agent.
