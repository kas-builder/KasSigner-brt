// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// KasSigner — Schnorr Signatures (secp256k1)
// 100% Rust, no-std, no-alloc
//
// Schnorr signature implementation compatible with Kaspa:
//   - secp256k1 curve (via crate k256, pure Rust)
//   - Public keys: x-only 32 bytes (BIP-340 style)
//   - Signatures: 64 bytes (R.x || s)
//   - BIP340 tagged hashes and nonce derivation via k256's audited implementation
//
// Kaspa uses Schnorr over secp256k1 similar to Bitcoin BIP340.
// The main difference is in the sighash hash (Blake2b vs SHA256),
// but that is handled in the KSPT module, not here.
//
// This implementation signs a 32-byte message (the pre-computed sighash).
//
// Security:
//   - BIP340 deterministic signing with an all-zero auxiliary-randomness input
//   - k256's SigningKey zeroizes private key material on drop
//   - No heap/alloc used


use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    schnorr::{Signature as K256SchnorrSignature, SigningKey, VerifyingKey},
    SecretKey,
};

// ─── Types ────────────────────────────────────────────────────────────

/// Schnorr signature: 64 bytes (R.x: 32 bytes || s: 32 bytes)
#[derive(Debug, Clone)]
/// A 64-byte Schnorr signature (R || s) compatible with Kaspa.
pub struct SchnorrSignature {
    pub bytes: [u8; 64],
}

impl SchnorrSignature {
    /// R component (x-coordinate of the nonce point, first 32 bytes)
    pub fn r_bytes(&self) -> &[u8; 32] {
        // SAFETY: self.bytes is [u8; 64], slicing [..32] always yields exactly 32 bytes
        self.bytes[..32].try_into().expect("r_bytes: 32-byte slice from 64-byte array")
    }

    /// s component (scalar, last 32 bytes)
    pub fn s_bytes(&self) -> &[u8; 32] {
        // SAFETY: self.bytes is [u8; 64], slicing [32..] always yields exactly 32 bytes
        self.bytes[32..].try_into().expect("s_bytes: 32-byte slice from 64-byte array")
    }
}

/// Schnorr signature errors
#[derive(Debug, PartialEq)]
/// Errors that can occur during Schnorr signing or verification.
pub enum SchnorrError {
    /// Invalid private key (zero or >= curve order)
    InvalidPrivateKey,
    /// Derived nonce is zero (should not happen with RFC6979)
    InvalidNonce,
    /// Elliptic curve operation error
    CurveError,
    /// Invalid signature (verification failed)
    InvalidSignature,
}

// ─── Sign ────────────────────────────────────────────────────────────

/// Sign a 32-byte precomputed Kaspa sighash with standard BIP340 Schnorr.
///
/// `message` must be the 32-byte sighash (pre-computed by the KSPT module).
/// `private_key` is the 32-byte BIP32 private key.
pub fn schnorr_sign(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<SchnorrSignature, SchnorrError> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|_| SchnorrError::InvalidPrivateKey)?;
    let signature = signing_key
        .sign_raw(message, &[0u8; 32])
        .map_err(|_| SchnorrError::InvalidNonce)?;
    Ok(SchnorrSignature {
        bytes: signature.to_bytes(),
    })
}

// ─── Verification ─────────────────────────────────────────────────────

/// Verifies a Schnorr signature against an x-only public key (32 bytes).
///
/// Algorithm:
///   1. Parse R.x and s from the signature
///   2. e = SHA256(R.x || P.x || message) mod n
///   3. Compute R' = s*G - e*P
///   4. Verify that R'.x == R.x and R'.y is even
pub fn schnorr_verify(
    pubkey_x: &[u8; 32],
    message: &[u8; 32],
    signature: &SchnorrSignature,
) -> Result<(), SchnorrError> {
    let verifying_key = VerifyingKey::from_bytes(pubkey_x)
        .map_err(|_| SchnorrError::InvalidSignature)?;
    let parsed_signature = K256SchnorrSignature::try_from(signature.bytes.as_slice())
        .map_err(|_| SchnorrError::InvalidSignature)?;
    verifying_key
        .verify_raw(message, &parsed_signature)
        .map_err(|_| SchnorrError::InvalidSignature)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
fn decode_hex<const N: usize>(hex: &[u8]) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    for i in 0..N {
        out[i] = (nibble(hex[i * 2])? << 4) | nibble(hex[i * 2 + 1])?;
    }
    Some(out)
}

/// Official BIP340 vector 0, also exercised by the k256 implementation.
/// Kaspa consensus uses this exact Schnorr signature scheme over its own
/// precomputed Blake2b transaction sighash.
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_official_bip340_vector_0() -> bool {
    let private_key = match decode_hex::<32>(
        b"0000000000000000000000000000000000000000000000000000000000000003",
    ) {
        Some(value) => value,
        None => return false,
    };
    let message = [0u8; 32];
    let expected_public_key = match decode_hex::<32>(
        b"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    ) {
        Some(value) => value,
        None => return false,
    };
    let expected_signature = match decode_hex::<64>(
        b"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ) {
        Some(value) => value,
        None => return false,
    };

    let signing_key = match SigningKey::from_bytes(&private_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if signing_key.verifying_key().to_bytes().as_slice() != expected_public_key {
        return false;
    }

    match schnorr_sign(&private_key, &message) {
        Ok(signature) => {
            signature.bytes == expected_signature
                && schnorr_verify(&expected_public_key, &message, &signature).is_ok()
        }
        Err(_) => false,
    }
}

/// Test: sign and verify roundtrip
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: sign then verify succeeds.
pub fn test_sign_verify_roundtrip() -> bool {
    // Test private key (DO NOT use in production)
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // Test message (32 bytes)
    let message: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    ];

    // Sign
    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify that the signature is 64 bytes
    if sig.bytes.len() != 64 {
        return false;
    }

    // Get x-only public key
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verify signature
    schnorr_verify(&pubkey_x, &message, &sig).is_ok()
}

/// Test: deterministic signing (same key + message = same signature)
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: deterministic signing (same key + message = same signature).
pub fn test_deterministic_signature() -> bool {
    let privkey: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    let message = [0x42u8; 32];

    let sig1 = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let sig2 = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Must be identical (deterministic nonce)
    sig1.bytes == sig2.bytes
}

/// Test: invalid signature must fail verification
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: invalid signature must fail verification.
pub fn test_invalid_signature_fails() -> bool {
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let message = [0x55u8; 32];
    let wrong_message = [0x66u8; 32];

    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Get pubkey
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verify with correct message → OK
    if schnorr_verify(&pubkey_x, &message, &sig).is_err() {
        return false;
    }

    // Verify with incorrect message → must fail
    schnorr_verify(&pubkey_x, &wrong_message, &sig).is_err()
}

/// Test: sign with BIP32-derived key
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_sign_with_bip32_key() -> bool {
    use super::bip39;
    use super::bip32;

    // Generate seed from known mnemonic
    let entropy = [0u8; 16]; // "abandon...about"
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");

    // Derive Kaspa key
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // x-only pubkey
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Sign a dummy sighash
    let sighash = [0xABu8; 32];
    let sig = match schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify
    schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

/// Runs all Schnorr tests.
/// Returns (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_schnorr_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_official_bip340_vector_0() { passed += 1; }
    if test_sign_verify_roundtrip() { passed += 1; }
    if test_deterministic_signature() { passed += 1; }
    if test_invalid_signature_fails() { passed += 1; }
    if test_sign_with_bip32_key() { passed += 1; }

    (passed, total)
}
