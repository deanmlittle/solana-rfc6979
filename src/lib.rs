//! A more efficient, no_std implementation of RFC 6979 deterministic
//! nonce generation for the Solana SVM.
//!
//! Built on top of [`solana_hmac_drbg`], so on `target_os = "solana"`
//! every internal HMAC routes through the `sol_sha256` syscall. Off-Solana
//! it falls through to the `sha2` crate, so the same API works in host
//! code (tests, off-chain tooling).
//!
//! See [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) §3.2 for
//! the deterministic nonce construction this implements. Given a private
//! scalar `x`, a curve subgroup order `n`, and a message hash `h`, this
//! returns the unique nonce `k` in the range `1 ≤ k < n` derived from
//! HMAC-DRBG seeded with `(x, h)`.
#![no_std]

use core::cmp::Ordering;
use solana_hmac_drbg::HmacDrbg;

const HASH_LENGTH: usize = 32;

/// Deterministically derive an ECDSA nonce per RFC 6979 §3.2.
///
/// `private_key` is the signer's scalar, `curve_order` is the subgroup
/// order `n` of the target curve (e.g. secp256k1, secp256r1), and
/// `message_hash` is the SHA-256 hash of the message to sign. The returned
/// 32-byte value is a valid nonce in `1 ≤ k < n`.
pub fn rfc6979_generate(
    private_key: &[u8; HASH_LENGTH],
    curve_order: &[u8; HASH_LENGTH],
    message_hash: &[u8; HASH_LENGTH],
) -> [u8; HASH_LENGTH] {
    let mut drbg = HmacDrbg::new(private_key, message_hash);
    let mut k = [0u8; HASH_LENGTH];
    loop {
        drbg.fill_bytes(&mut k);
        if k != [0u8; HASH_LENGTH] && matches!(k.cmp(curve_order), Ordering::Less) {
            return k;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rfc6979_generate;

    // P-256 / secp256k1 test vectors from the `rfc6979` crate; the low-modulus
    // vector exercises the rejection-sampling loop across multiple DRBG rounds.

    // NIST P-256 subgroup order
    const NIST_P256_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    // secp256k1 subgroup order
    const SECP256K1_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    // Arbitrary small modulus to force multiple DRBG rounds via rejection.
    const LOW_ORDER: [u8; 32] = [0x10; 32];

    // RFC 6979 NIST P-256 / SHA-256 sample private key
    const RFC6979_KEY: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];

    // sha256("sample") — the RFC 6979 sample message hash
    const RFC6979_MSG_HASH: [u8; 32] = [
        0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f,
        0xc7, 0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad,
        0xd1, 0xbf,
    ];

    // Expected k for both secp256k1 and NIST P-256 with the sample inputs above.
    const RFC6979_EXPECTED_K: [u8; 32] = [
        0xa6, 0xe3, 0xc5, 0x7d, 0xd0, 0x1a, 0xbe, 0x90, 0x08, 0x65, 0x38, 0x39, 0x83, 0x55, 0xdd,
        0x4c, 0x3b, 0x17, 0xaa, 0x87, 0x33, 0x82, 0xb0, 0xf2, 0x4d, 0x61, 0x29, 0x49, 0x3d, 0x8a,
        0xad, 0x60,
    ];

    // Expected k for the low-modulus rejection-sampling case.
    const RFC6979_EXPECTED_K_LOW: [u8; 32] = [
        0x0c, 0x21, 0x61, 0x73, 0x0a, 0x70, 0x22, 0x7d, 0xa5, 0x5c, 0x7d, 0x16, 0xdf, 0x1b, 0x6e,
        0x13, 0x02, 0xe7, 0x51, 0xba, 0xb0, 0xca, 0xf7, 0x23, 0xff, 0x83, 0x0f, 0x7b, 0xa6, 0x0a,
        0x30, 0xad,
    ];

    #[test]
    fn rfc6979_secp256r1_test() {
        let k = rfc6979_generate(&RFC6979_KEY, &NIST_P256_ORDER, &RFC6979_MSG_HASH);
        assert_eq!(k, RFC6979_EXPECTED_K);
    }

    #[test]
    fn rfc6979_secp256k1_test() {
        let k = rfc6979_generate(&RFC6979_KEY, &SECP256K1_ORDER, &RFC6979_MSG_HASH);
        assert_eq!(k, RFC6979_EXPECTED_K);
    }

    #[test]
    fn rfc6979_low_order_test() {
        let k = rfc6979_generate(&RFC6979_KEY, &LOW_ORDER, &RFC6979_MSG_HASH);
        assert_eq!(k, RFC6979_EXPECTED_K_LOW);
    }
}
