- **The #2795/#2805 regression test now also asserts the ring's own
  `yuzu_mcp_stream_pin_displaced_total` stays at 0.** The existing test
  (`test_mcp_stream_bridge.cpp`, `"#2795/#2805: a failed pin release still
  admits..."`) already covered the two bridge-level admission counters
  (`yuzu_mcp_bridge_pin_release_raced_total`/`_failed_total`) and the
  bridge's own reclaim counter (`yuzu_mcp_bridge_pin_displaced_for_admission_total`),
  but never checked the ring's separate LRU-eviction counter — the one
  piece of #2795's original acceptance criteria not covered by the fix
  that shipped for it. Closes #2795.
