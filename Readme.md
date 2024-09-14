# solana-rfc6979
A simple implementation of [RFC6979](https://datatracker.ietf.org/doc/html/rfc6979) for solana.

Uses `solana-hmac-drbg`, `solana-hmac-sha256` and `solana-nostd-sha256` under the hood.

### Usage

```rs
let k = rfc6979_generate(&private_key, &curve_order, &message_hash); // -> [u8;32]
```