# macOS agent packages

The default package remains the loose-binary lane:

```sh
bash deploy/packaging/macos/build-pkg.sh --bin-dir build-macos --version <version> --output dist
```

The opt-in development lane stages a signed, immutable `YuzuAgent.app` and keeps
plugins external at `/usr/local/lib/yuzu/plugins`:

```sh
python3 deploy/packaging/macos/build-app.py \
  --bin-dir build-macos --version <version> --bundle-id <registered-app-id> \
  --profile <original.provisionprofile> --sign-identity <SHA-1-identity> \
  --output-dir <empty-task-directory>
bash deploy/packaging/macos/build-pkg.sh --bundle-dir <empty-task-directory> \
  --version <version> --output dist
```

The helper requires `security cms` to decode the original profile, a current
explicit macOS App ID, ES Boolean entitlement, matching developer certificate,
and this Mac's **Provisioning UDID**. Apple silicon registration uses
`system_profiler SPHardwareDataType`'s `Provisioning UDID`; never substitute
`IOPlatformUUID`. Run `scripts/macos-device-registration.zsh` to obtain it.

Build this lane with `meson/native/macos-appleclang.ini`. The helper inspects
every staged Mach-O `LC_BUILD_VERSION` and refuses anything other than the
project's macOS 13.3 deployment target; `Info.plist` and installer metadata
cannot make a newer binary compatible.

The bundle LaunchDaemon runs as root, retains external plugins, and always passes
`--no-auto-update`. Data, logs, and trust anchors remain outside the sealed app.
Package transitions preserve them and retain package-owned code/configuration for
recovery. The package first writes its code and LaunchDaemon plist to package-owned
incoming paths; postinstall validates them, then promotes them and removes the
recovery snapshot only after launchd accepts the selected lane. A payload failure
before postinstall therefore leaves the active installation in place. Development
app signing does not installer-sign or notarize the `.pkg`.

Do not install the root LaunchDaemon, grant Full Disk Access, or test live
Endpoint Security without explicit test-rig authorization. A valid signature, a
running process, or polling fallback does not prove live ES: `tar.status` must
report `process_capture_method|endpoint_security`, followed by a unique observed
exec and exit with checked drop counters. The full Xcode SDK is required; Command
Line Tools builds only TAR's polling fallback. CMS sidecars must cover final
Apple-signed plugin bytes; stale sidecars are rejected. When input plugins carry
sidecars, provide `--final-plugin-sig-dir`, `--plugin-trust-bundle` and
`--runtime-plugin-trust-bundle`. The helper invokes Yuzu's shared CMS verifier on
the final plugin bytes and the generated LaunchDaemon enforces that runtime trust
bundle with `--plugin-require-signature`. During an upgrade, existing server/TLS
arguments and supported `YUZU_*` environment settings are retained. A generated
sidecar policy deliberately replaces existing plugin-signing arguments and
environment settings; bundle-owned paths and `--no-auto-update` are forced.

## Authorized test-rig lifecycle

Do not run these commands on a development workstation without explicit
authorization for the target rig. They install and start the root LaunchDaemon.
For an authorized disposable rig, record the package hash first, then perform a
non-interactive install with:

```sh
sudo /usr/sbin/installer -pkg YuzuAgent-<version>-macos-<arch>.pkg -target /
```

The same command performs loose-to-bundle, bundle-to-bundle, and bundle-to-loose
transitions. It stages the new payload under incoming names while the old daemon
continues to run, validates the bundle, then stops and replaces the selected lane.
The postinstall script restores the saved plist and package-owned files if that
promotion or its bounded launchd health observation fails. It leaves data, logs,
certificates, and third-party plugins alone. The recovery snapshot records a
durable `prepared` or `promoting` phase; a later package invocation discards an
unused prepared snapshot or restores an interrupted promotion before taking a
new snapshot.

For an authorized silent uninstall, run:

```sh
sudo /usr/local/lib/yuzu/uninstall.sh
```

It removes only Yuzu's manifest-listed plugin files and both package-owned code
lanes; it retains operational data, logs, configuration, trust anchors, and
third-party plugins. If an installation reports an error, retain
`/var/db/yuzu-agent/install-recovery.*` and the Installer log for diagnosis;
do not delete them before comparing the restored plist and package manifest.
