//! # Merkle Proof Verification
//!
//! Reusable utilities for verifying Merkle proofs against stored root hashes.
//! Optimized for Soroban on-chain costs.

use soroban_sdk::{Bytes, BytesN, Env, Vec};

/// Verify a Merkle proof against a root and leaf.
///
/// The proof is a vector of sister node hashes. At each level, the current hash
/// and the sister hash are concatenated in sorted order and hashed to produce
/// the parent hash. Sorting makes the proof order-independent at each level
/// and helps prevent second-preimage attacks on unbalanced trees.
///
/// # Arguments
/// * `env` - The Soroban environment.
/// * `root` - The expected Merkle root.
/// * `leaf` - The leaf node hash to verify.
/// * `proof` - Vector of sister node hashes (bottom to top).
///
/// # Returns
/// * `true` if the proof is valid, `false` otherwise.
pub fn verify_merkle_proof(
    env: &Env,
    root: &BytesN<32>,
    leaf: &BytesN<32>,
    proof: &Vec<BytesN<32>>,
) -> bool {
    let mut current_hash = leaf.clone();

    for i in 0..proof.len() {
        let proof_element = proof.get(i).unwrap();

        let mut combined = Bytes::new(env);
        // Canonical ordering: smaller hash first
        if current_hash < proof_element {
            combined.append(&current_hash.clone().into());
            combined.append(&proof_element.clone().into());
        } else {
            combined.append(&proof_element.clone().into());
            combined.append(&current_hash.clone().into());
        }

        current_hash = env.crypto().sha256(&combined).into();
    }

    current_hash == *root
}

/// Computes the hash of a data leaf using SHA-256.
///
/// This provides a consistent way to hash leaves before verification.
pub fn hash_leaf(env: &Env, data: &Bytes) -> BytesN<32> {
    env.crypto().sha256(data).into()
}
