#!/usr/bin/env bash
# linux-start-UAT.sh — backward-compatibility shim.
#
# The canonical script is now scripts/start-UAT.sh, which works on both
# Linux and macOS. This shim is kept so docs, muscle memory, and external
# automation that still call the linux- name keep working. New work should
# call scripts/start-UAT.sh directly.

exec bash "$(dirname "$0")/start-UAT.sh" "$@"
