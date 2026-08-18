# ADR 0001: isolate keepass-rs behind KdbxEngine

- Status: accepted for compatibility harness
- Dependency: `keepass` 0.13.x
- License: MIT

The Rust `keepass` crate supports KDBX 3/4 parsing and marks KDBX 4.1 writing as
experimental. It is therefore isolated behind the `KdbxEngine` interface. No
Flutter or synchronization type may depend directly on its public types.

Acceptance requires read-modify-write fixtures opened by both KeePass and
KeePassXC, preservation of unknown fields and history, and malformed-input
tests. If these gates fail, the repository will pin and patch a reviewed fork
without changing callers.
