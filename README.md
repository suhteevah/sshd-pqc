# sshd-pqc

A `#![no_std]` post-quantum SSH daemon written in Rust.

## Highlights

- **Post-quantum hybrid key exchange**: `mlkem768x25519-sha256@openssh.com` combines ML-KEM-768 (FIPS 203) with X25519, providing quantum resistance without sacrificing classical security
- **Post-quantum host keys**: ML-DSA-65 (FIPS 204, CRYSTALS-Dilithium) + Ed25519 dual signatures for server authentication
- **Classical fallback**: `curve25519-sha256` for clients that do not yet support post-quantum algorithms
- **`#![no_std]` + `alloc`**: Runs on bare metal, embedded systems, or any environment with a heap allocator -- no POSIX, no libc, no Linux kernel required
- **Full SSH-2 protocol**: version exchange, KEXINIT negotiation, user authentication (publickey + password), channel multiplexing, PTY, shell, exec
- **ChaCha20-Poly1305**: AEAD transport encryption (`chacha20-poly1305@openssh.com`)

## Protocol Stack

```
+----------------------------------+
|         Channel Layer            |  RFC 4254: sessions, exec, pty
+----------------------------------+
|       Authentication Layer       |  RFC 4252: publickey, password
+----------------------------------+
|        Transport Layer           |  RFC 4253: packets, encryption
+----------------------------------+
|    Key Exchange (Hybrid PQ)      |  ML-KEM-768 + X25519
+----------------------------------+
|        Wire Format               |  SSH binary encoding
+----------------------------------+
```

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
sshd-pqc = "0.1"
```

Basic server setup:

```rust,no_run
use sshd_pqc::{SshServer, SshConfig};

fn my_rng(buf: &mut [u8]) {
    // Fill buf with random bytes from your platform's RNG
    # todo!()
}

let config = SshConfig::default();
let mut server = SshServer::new(config, my_rng);

// Add an authorized Ed25519 public key
let pubkey = [0u8; 32]; // your user's Ed25519 public key
server.add_ed25519_key("admin", &pubkey, "admin key");

// When a TCP connection arrives:
if let Some(mut session) = server.accept_connection() {
    // Send version string
    let version = session.version_bytes();
    // ... send `version` over TCP ...

    // Feed received TCP data into the session
    // let actions = session.on_data_received(&tcp_data).unwrap();

    // Drain outgoing packets and send over TCP
    // for packet in session.drain_outgoing() { ... }
}
```

## Status

This crate implements the full SSH-2 protocol state machine. Cryptographic operations (ML-KEM-768 encapsulation/decapsulation, Ed25519 signing/verification, ML-DSA-65, ChaCha20-Poly1305 packet encryption) use placeholder implementations that validate the protocol flow. Wire up the real crypto crate APIs (ml-kem, ed25519-dalek, ml-dsa, chacha20poly1305) for production use.

## Algorithms

| Category | Algorithm | Status |
|----------|-----------|--------|
| KEX | `mlkem768x25519-sha256@openssh.com` | Protocol complete, ML-KEM placeholder |
| KEX | `curve25519-sha256` | Protocol complete, X25519 placeholder |
| Host key | `mlkem768-ed25519@openssh.com` (hybrid) | Protocol complete, placeholder sigs |
| Host key | `ssh-ed25519` | Protocol complete, placeholder sigs |
| Encryption | `chacha20-poly1305@openssh.com` | Key derivation complete, AEAD placeholder |
| MAC | `hmac-sha2-256` | Advertised, integrated in AEAD |
| Auth | publickey (Ed25519, ML-DSA-65) | Framework complete |
| Auth | password (SHA-256 hash) | Complete |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/suhteevah/sshd-pqc).

---

---

---

---

---

---

---

---

---

---

---

## Support This Project

If you find this project useful, consider buying me a coffee! Your support helps me keep building and sharing open-source tools.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?logo=paypal)](https://www.paypal.me/baal_hosting)

**PayPal:** [baal_hosting@live.com](https://paypal.me/baal_hosting)

Every donation, no matter how small, is greatly appreciated and motivates continued development. Thank you!
