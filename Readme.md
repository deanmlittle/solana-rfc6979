# Solana NoStd RFC 6979

[![CI](https://github.com/blueshift-gg/solana-rfc6979/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-rfc6979/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-rfc6979.svg)](https://crates.io/crates/solana-rfc6979)
[![docs.rs](https://docs.rs/solana-rfc6979/badge.svg)](https://docs.rs/solana-rfc6979)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-rfc6979/blob/master/LICENSE)

A more efficient, `no_std` implementation of [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) deterministic ECDSA nonce generation for the Solana SVM. Built on [`solana-hmac-drbg`](https://crates.io/crates/solana-hmac-drbg) and [`solana-hmac-sha256`](https://crates.io/crates/solana-hmac-sha256), so every internal HMAC routes through the `sol_sha256` syscall on-chain and falls through to the `sha2` crate off-chain — the same API works in host code (tests, off-chain tooling).

Given a private scalar `x`, a curve subgroup order `n`, and a message hash `h`, this returns the unique nonce `k` in the range `1 ≤ k < n` derived from HMAC-DRBG seeded with `(x, h)`. Works with any 256-bit curve (secp256k1, NIST P-256, …).

## Quick start

```toml
[dependencies]
solana-rfc6979 = "0.3.0"
```

```rust
use solana_rfc6979::rfc6979_generate;

let private_key:  [u8; 32] = [/* signer scalar  */];
let curve_order:  [u8; 32] = [/* subgroup order */];
let message_hash: [u8; 32] = [/* sha256(msg)    */];

let k = rfc6979_generate(&private_key, &curve_order, &message_hash);
```

The library is `#![no_std]`-clean for SBPF; no allocator setup required.

## Static syscalls

If your target supports the Upstream BPF / sBPFv3 static-syscall ABI, enable the `static-syscalls` feature. It transparently forwards through [`solana-hmac-drbg/static-syscalls`](https://crates.io/crates/solana-hmac-drbg) to [`solana-hmac-sha256/static-syscalls`](https://crates.io/crates/solana-hmac-sha256), so the SBPF program calls `sol_sha256` directly instead of going through an `extern "C"` PLT relocation.

```toml
[dependencies]
solana-rfc6979 = { version = "0.3.0", features = ["static-syscalls"] }
```

## Benchmarks

To reproduce the on-chain compute unit cost, install `cargo build-sbf` (Solana CLI) and run:

```sh
cargo test --test sbpf --jobs 1
```

The benchmark compiles the function into its own SBPF program and runs it through [Mollusk](https://github.com/anza-xyz/mollusk) via [`svm-unit-test`](https://crates.io/crates/svm-unit-test).

## License

Licensed under the [MIT License](https://github.com/blueshift-gg/solana-rfc6979/blob/master/LICENSE). The license includes the standard "as-is" warranty disclaimer — use at your own risk.
