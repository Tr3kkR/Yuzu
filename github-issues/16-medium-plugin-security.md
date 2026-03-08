---
title: "[P2/MEDIUM] Add plugin code signing and allowlist"
labels: security, enhancement, P2
assignees: ""
---

## Summary

Plugins are loaded via `dlopen`/`LoadLibrary` with no integrity verification. Any `.so`/`.dll` file in the plugin directory is loaded and executed with full agent privileges. An attacker with write access to the plugin directory gets arbitrary code execution.

## Affected Files

- `agents/core/src/plugin_loader.cpp` — `load()` and `scan()` functions
- `agents/core/include/yuzu/agent/plugin_loader.hpp`
- `agents/core/src/main.cpp` — CLI flags

## Current Behavior

1. All `.so`/`.dll`/`.dylib` files in `--plugin-dir` are loaded
2. Only ABI version is validated
3. No signature or hash verification
4. No allowlist/denylist

## Recommended Fix (phased)

### Phase 1: Plugin allowlist (low effort)

```cpp
// CLI flag
app.add_option("--allowed-plugins", cfg.allowed_plugins,
    "Comma-separated list of allowed plugin names (default: all)");

// In scan():
if (!cfg.allowed_plugins.empty()) {
    if (!cfg.allowed_plugins.contains(descriptor->name)) {
        result.errors.push_back(LoadError{path, "plugin not in allowlist"});
        continue;
    }
}
```

### Phase 2: Hash verification (medium effort)

```cpp
// Ship a manifest file alongside plugins:
// plugins/manifest.json:
// { "chargen.so": "sha256:abc123...", "procfetch.so": "sha256:def456..." }

bool verify_plugin_hash(const fs::path& plugin_path, const std::string& expected_hash);
```

### Phase 3: Code signing (high effort)

Sign plugins with a private key during build; verify with embedded public key at load time using OpenSSL PKCS#7 or CMS.

### Additional: Plugin directory permissions

Document that `--plugin-dir` should be owned by root and not writable by the agent user:
```bash
chown root:root /opt/yuzu/plugins/
chmod 755 /opt/yuzu/plugins/
```

## Acceptance Criteria

- [ ] `--allowed-plugins` flag restricts which plugins are loaded
- [ ] Unknown plugins in directory are logged but not loaded
- [ ] Plugin manifest hash verification implemented
- [ ] Documentation covers secure plugin directory setup
- [ ] `RTLD_LAZY` changed to `RTLD_NOW` for immediate symbol validation
