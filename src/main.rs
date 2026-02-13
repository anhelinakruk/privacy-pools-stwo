mod poseidon_hash;

use poseidon_hash::*;
use stwo_prover::core::fields::m31::BaseField;

/// Hash two elements using Poseidon2 (returns first element of state - 31 bits)
fn poseidon_hash_two(a: u32, b: u32) -> u32 {
    let state = poseidon_permute(a, b);
    state[0].0
}

/// Hash two elements using Poseidon2 (returns 8 elements - 248 bits)
fn poseidon_hash_two_wide(a: u32, b: u32) -> [u32; 8] {
    let state = poseidon_permute(a, b);
    [
        state[0].0, state[1].0, state[2].0, state[3].0, state[4].0, state[5].0, state[6].0,
        state[7].0,
    ]
}

/// Combine 8 M31 elements into uint256 (248 bits)
fn combine_to_uint256(elements: [u32; 8]) -> String {
    let mut result: u128 = 0;
    let mut result_hi: u128 = 0;

    // Lower 128 bits: elements[4..8]
    for i in 0..4 {
        result |= (elements[4 + i] as u128) << (i * 31);
    }

    // Upper 120 bits (of 248 total): elements[0..4]
    for i in 0..4 {
        result_hi |= (elements[i] as u128) << (i * 31);
    }

    format!("0x{:031x}{:032x}", result_hi, result)
}

/// Poseidon2 permutation (internal function)
fn poseidon_permute(a: u32, b: u32) -> [BaseField; N_STATE] {
    // 🔒 SECURITY: Validate inputs are within M31 field modulus
    // M31 prime: 2^31 - 1 = 2147483647
    const M31_MODULUS: u32 = (1u32 << 31) - 1;
    assert!(
        a <= M31_MODULUS,
        "Input 'a' ({}) exceeds M31 field modulus ({})",
        a,
        M31_MODULUS
    );
    assert!(
        b <= M31_MODULUS,
        "Input 'b' ({}) exceeds M31 field modulus ({})",
        b,
        M31_MODULUS
    );

    // Initialize state with [a, b, 0, 0, ..., 0] (16 elements)
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = BaseField::from_u32_unchecked(a);
    state[1] = BaseField::from_u32_unchecked(b);

    // Apply Poseidon2 permutation
    apply_external_round_matrix(&mut state);

    // First 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round][i];
        }
        state = std::array::from_fn(|i| pow5(state[i]));
        apply_external_round_matrix(&mut state);
    }

    // 14 partial rounds
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] = state[0] + INTERNAL_ROUND_CONSTS[round];
        state[0] = pow5(state[0]);
        apply_internal_round_matrix(&mut state);
    }

    // Last 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
        }
        state = std::array::from_fn(|i| pow5(state[i]));
        apply_external_round_matrix(&mut state);
    }

    state
}

/// Compute precomputed hashes for sparse Merkle tree (32 levels) - 248 bit version
fn compute_precomputed_hashes_wide() -> Vec<[u32; 8]> {
    let mut precomputed = Vec::new();

    // Level 0: hash of empty leaf (0, 0)
    precomputed.push(poseidon_hash_two_wide(0, 0));

    // Level i: hash of two nodes from level i-1
    // For simplicity, we hash the first element of each node
    for i in 1..32 {
        let prev = precomputed[i - 1][0];
        precomputed.push(poseidon_hash_two_wide(prev, prev));
    }

    precomputed
}

fn main() {
    println!("=== 31-bit hashes (single element) ===");
    let hash = poseidon_hash_two(1, 2);
    println!("Poseidon hash of (1, 2) = {:#x}", hash);

    let hash2 = poseidon_hash_two(0, 0);
    println!("Poseidon hash of (0, 0) = {:#x}", hash2);

    let hash3 = poseidon_hash_two(5, 10);
    println!("Poseidon hash of (5, 10) = {:#x}", hash3);

    println!("\n=== 248-bit hashes (8 elements) ===");
    let hash_wide = poseidon_hash_two_wide(1, 2);
    println!(
        "Poseidon hash of (1, 2) = {}",
        combine_to_uint256(hash_wide)
    );

    let hash_wide2 = poseidon_hash_two_wide(0, 0);
    println!(
        "Poseidon hash of (0, 0) = {}",
        combine_to_uint256(hash_wide2)
    );

    let hash_wide3 = poseidon_hash_two_wide(5, 10);
    println!(
        "Poseidon hash of (5, 10) = {}",
        combine_to_uint256(hash_wide3)
    );

    println!("\n=== Precomputed hashes for Sparse Merkle Tree (248-bit) ===");
    let precomputed = compute_precomputed_hashes_wide();
    for (i, hash) in precomputed.iter().enumerate() {
        println!("self.precomputed[{}] = {};", i, combine_to_uint256(*hash));
    }
    println!(
        "\nRoot of empty tree: {}",
        combine_to_uint256(precomputed[31])
    );
}

#[cfg(test)]
mod input_validation_tests {
    use super::*;

    #[test]
    #[should_panic(expected = "exceeds M31 field modulus")]
    fn test_poseidon_hash_rejects_invalid_input_a() {
        // M31 modulus = 2^31 - 1 = 2147483647
        // Try with value above modulus
        let invalid = 1u32 << 31; // 2147483648
        poseidon_hash_two(invalid, 100);
    }

    #[test]
    #[should_panic(expected = "exceeds M31 field modulus")]
    fn test_poseidon_hash_rejects_invalid_input_b() {
        let invalid = (1u32 << 31) + 1000; // Way above modulus
        poseidon_hash_two(100, invalid);
    }

    #[test]
    fn test_poseidon_hash_accepts_valid_input() {
        // M31 modulus = 2^31 - 1 = 2147483647
        let valid_max = (1u32 << 31) - 1;
        let result = poseidon_hash_two(valid_max, valid_max);
        assert!(result > 0); // Just check it doesn't panic
    }
}
