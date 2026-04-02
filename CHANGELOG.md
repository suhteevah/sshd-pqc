# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-02

### Added

- Initial release
- SSH-2 transport layer (RFC 4253): version exchange, binary packet framing, sequence numbers
- Hybrid post-quantum key exchange: `mlkem768x25519-sha256@openssh.com` (ML-KEM-768 + X25519)
- Classical key exchange fallback: `curve25519-sha256`
- Hybrid host keys: ML-DSA-65 + Ed25519 dual signatures (`mlkem768-ed25519@openssh.com`)
- Classical host keys: `ssh-ed25519`
- User authentication (RFC 4252): publickey (Ed25519, ML-DSA-65) and password methods
- Channel multiplexing (RFC 4254): session channels, PTY, shell, exec, window-change
- ChaCha20-Poly1305 AEAD cipher state management (`chacha20-poly1305@openssh.com`)
- Key derivation per RFC 4253 section 7.2
- SSH wire format reader/writer with all SSH data types (byte, boolean, uint32, uint64, string, mpint, name-list)
- `PaneCallback` trait for integrating with host application terminals
- `SshServer` for managing host keys, authorized users, and connection lifecycle
- `SshSession` per-connection state machine
- `#![no_std]` with `alloc` -- no POSIX or libc dependency
