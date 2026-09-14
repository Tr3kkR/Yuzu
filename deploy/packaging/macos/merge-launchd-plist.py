#!/usr/bin/env python3
"""Preserve safe existing LaunchDaemon options during a bundle transition."""

from __future__ import annotations

import argparse
import os
import plistlib
import tempfile
from pathlib import Path


_FIXED_WITH_VALUE = {"--plugin-dir", "--data-dir", "--log-file", "--log-max-size", "--log-max-files"}
_SIGNING_OPTIONS = {"--plugin-trust-bundle", "--plugin-require-signature"}
_PRESERVED_ENVIRONMENT = {
    "YUZU_SERVER", "YUZU_CA_CERT", "YUZU_TLS_SYSTEM_ROOTS", "YUZU_CLIENT_CERT", "YUZU_CLIENT_KEY",
    "YUZU_CERT_STORE", "YUZU_CERT_SUBJECT", "YUZU_CERT_THUMBPRINT", "YUZU_PLUGIN_ALLOWLIST",
    "YUZU_PLUGIN_TRUST_BUNDLE", "YUZU_PLUGIN_REQUIRE_SIGNATURE",
}


def merge(previous: Path, destination: Path, *, force_no_auto_update: bool = False) -> None:
    with previous.open("rb") as source:
        prior = plistlib.load(source)
    with destination.open("rb") as source:
        generated = plistlib.load(source)
    old_args = prior.get("ProgramArguments")
    new_args = generated.get("ProgramArguments")
    if not isinstance(old_args, list) or not all(isinstance(arg, str) for arg in old_args):
        raise ValueError("previous plist has invalid ProgramArguments")
    if not isinstance(new_args, list) or not new_args or not all(isinstance(arg, str) for arg in new_args):
        raise ValueError("generated plist has invalid ProgramArguments")

    generated_signing = "--plugin-trust-bundle" in new_args
    preserved: list[str] = []
    index = 1  # executable path is always replaced by the generated bundle path.
    while index < len(old_args):
        argument = old_args[index]
        name, separator, _value = argument.partition("=")
        if name in _FIXED_WITH_VALUE:
            index += 2 if not separator else 1
            continue
        if name == "--no-auto-update" and force_no_auto_update:
            index += 1
            continue
        if generated_signing and name in _SIGNING_OPTIONS:
            index += 2 if name == "--plugin-trust-bundle" and not separator else 1
            continue
        preserved.append(argument)
        index += 1

    generated["ProgramArguments"] = [*new_args, *preserved]
    old_environment = prior.get("EnvironmentVariables", {})
    if not isinstance(old_environment, dict) or not all(isinstance(key, str) and isinstance(value, str)
                                                         for key, value in old_environment.items()):
        raise ValueError("previous plist has invalid EnvironmentVariables")
    retained_environment = {
        key: value for key, value in old_environment.items() if key in _PRESERVED_ENVIRONMENT
    }
    if generated_signing:
        retained_environment.pop("YUZU_PLUGIN_TRUST_BUNDLE", None)
        retained_environment.pop("YUZU_PLUGIN_REQUIRE_SIGNATURE", None)
    if retained_environment:
        generated["EnvironmentVariables"] = retained_environment
    else:
        generated.pop("EnvironmentVariables", None)
    fd, temporary = tempfile.mkstemp(prefix="yuzu-plist-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            plistlib.dump(generated, output, sort_keys=False)
        os.replace(temporary, destination)
    except Exception:
        os.unlink(temporary)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--force-no-auto-update", action="store_true")
    args = parser.parse_args()
    merge(args.previous, args.destination, force_no_auto_update=args.force_no_auto_update)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
