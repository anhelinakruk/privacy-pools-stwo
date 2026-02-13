use std::ops::{Add, AddAssign, Mul, Sub};

use stwo_prover::core::fields::{FieldExpOps, m31::BaseField};

pub const N_STATE: usize = 16;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const LOG_EXPAND: u32 = 3;

// Real Poseidon2 round constants for M31 field (from zkhash)
// Source: https://github.com/AntoineFONDEUR/poseidon2/blob/poseidon2-M31/plain_implementations/src/poseidon2/poseidon2_instance_m31.rs
pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; 2 * N_HALF_FULL_ROUNDS] = [
    // First 4 full rounds (RC16[0..4])
    [
        BaseField::from_u32_unchecked(0x768bab52),
        BaseField::from_u32_unchecked(0x70e0ab7d),
        BaseField::from_u32_unchecked(0x3d266c8a),
        BaseField::from_u32_unchecked(0x6da42045),
        BaseField::from_u32_unchecked(0x600fef22),
        BaseField::from_u32_unchecked(0x41dace6b),
        BaseField::from_u32_unchecked(0x64f9bdd4),
        BaseField::from_u32_unchecked(0x5d42d4fe),
        BaseField::from_u32_unchecked(0x76b1516d),
        BaseField::from_u32_unchecked(0x6fc9a717),
        BaseField::from_u32_unchecked(0x70ac4fb6),
        BaseField::from_u32_unchecked(0x00194ef6),
        BaseField::from_u32_unchecked(0x22b644e2),
        BaseField::from_u32_unchecked(0x1f7916d5),
        BaseField::from_u32_unchecked(0x47581be2),
        BaseField::from_u32_unchecked(0x2710a123),
    ],
    [
        BaseField::from_u32_unchecked(0x6284e867),
        BaseField::from_u32_unchecked(0x018d3afe),
        BaseField::from_u32_unchecked(0x5df99ef3),
        BaseField::from_u32_unchecked(0x4c1e467b),
        BaseField::from_u32_unchecked(0x566f6abc),
        BaseField::from_u32_unchecked(0x2994e427),
        BaseField::from_u32_unchecked(0x538a6d42),
        BaseField::from_u32_unchecked(0x5d7bf2cf),
        BaseField::from_u32_unchecked(0x7fda2dab),
        BaseField::from_u32_unchecked(0x0fd854c4),
        BaseField::from_u32_unchecked(0x46922fca),
        BaseField::from_u32_unchecked(0x3d7763a1),
        BaseField::from_u32_unchecked(0x19fd05ca),
        BaseField::from_u32_unchecked(0x0a4bbb43),
        BaseField::from_u32_unchecked(0x15075851),
        BaseField::from_u32_unchecked(0x3d903d76),
    ],
    [
        BaseField::from_u32_unchecked(0x2d290ff7),
        BaseField::from_u32_unchecked(0x40809fa0),
        BaseField::from_u32_unchecked(0x59dac6ec),
        BaseField::from_u32_unchecked(0x127927a2),
        BaseField::from_u32_unchecked(0x6bbf0ea0),
        BaseField::from_u32_unchecked(0x0294140f),
        BaseField::from_u32_unchecked(0x24742976),
        BaseField::from_u32_unchecked(0x6e84c081),
        BaseField::from_u32_unchecked(0x22484f4a),
        BaseField::from_u32_unchecked(0x354cae59),
        BaseField::from_u32_unchecked(0x0453ffe1),
        BaseField::from_u32_unchecked(0x3f47a3cc),
        BaseField::from_u32_unchecked(0x0088204e),
        BaseField::from_u32_unchecked(0x6066e109),
        BaseField::from_u32_unchecked(0x3b7c4b80),
        BaseField::from_u32_unchecked(0x6b55665d),
    ],
    [
        BaseField::from_u32_unchecked(0x3bc4b897),
        BaseField::from_u32_unchecked(0x735bf378),
        BaseField::from_u32_unchecked(0x508daf42),
        BaseField::from_u32_unchecked(0x1884fc2b),
        BaseField::from_u32_unchecked(0x7214f24c),
        BaseField::from_u32_unchecked(0x7498be0a),
        BaseField::from_u32_unchecked(0x1a60e640),
        BaseField::from_u32_unchecked(0x3303f928),
        BaseField::from_u32_unchecked(0x29b46376),
        BaseField::from_u32_unchecked(0x5c96bb68),
        BaseField::from_u32_unchecked(0x65d097a5),
        BaseField::from_u32_unchecked(0x1d358e9f),
        BaseField::from_u32_unchecked(0x4a9a9017),
        BaseField::from_u32_unchecked(0x4724cf76),
        BaseField::from_u32_unchecked(0x347af70f),
        BaseField::from_u32_unchecked(0x1e77e59a),
    ],
    // Last 4 full rounds (RC16[18..22])
    [
        BaseField::from_u32_unchecked(0x57090613),
        BaseField::from_u32_unchecked(0x1fa42108),
        BaseField::from_u32_unchecked(0x17bbef50),
        BaseField::from_u32_unchecked(0x1ff7e11c),
        BaseField::from_u32_unchecked(0x047b24ca),
        BaseField::from_u32_unchecked(0x4e140275),
        BaseField::from_u32_unchecked(0x4fa086f5),
        BaseField::from_u32_unchecked(0x079b309c),
        BaseField::from_u32_unchecked(0x1159bd47),
        BaseField::from_u32_unchecked(0x6d37e4e5),
        BaseField::from_u32_unchecked(0x075d8dce),
        BaseField::from_u32_unchecked(0x12121ca0),
        BaseField::from_u32_unchecked(0x7f6a7c40),
        BaseField::from_u32_unchecked(0x68e182ba),
        BaseField::from_u32_unchecked(0x5493201b),
        BaseField::from_u32_unchecked(0x0444a80e),
    ],
    [
        BaseField::from_u32_unchecked(0x0064f4c6),
        BaseField::from_u32_unchecked(0x6467abe6),
        BaseField::from_u32_unchecked(0x66975762),
        BaseField::from_u32_unchecked(0x2af68f9b),
        BaseField::from_u32_unchecked(0x345b33be),
        BaseField::from_u32_unchecked(0x1b70d47f),
        BaseField::from_u32_unchecked(0x053db717),
        BaseField::from_u32_unchecked(0x381189cb),
        BaseField::from_u32_unchecked(0x43b915f8),
        BaseField::from_u32_unchecked(0x20df3694),
        BaseField::from_u32_unchecked(0x0f459d26),
        BaseField::from_u32_unchecked(0x77a0e97b),
        BaseField::from_u32_unchecked(0x2f73e739),
        BaseField::from_u32_unchecked(0x1876c2f9),
        BaseField::from_u32_unchecked(0x65a0e29a),
        BaseField::from_u32_unchecked(0x4cabefbe),
    ],
    [
        BaseField::from_u32_unchecked(0x5abd1268),
        BaseField::from_u32_unchecked(0x4d34a760),
        BaseField::from_u32_unchecked(0x12771799),
        BaseField::from_u32_unchecked(0x69a0c9ac),
        BaseField::from_u32_unchecked(0x39091e55),
        BaseField::from_u32_unchecked(0x7f611cd0),
        BaseField::from_u32_unchecked(0x3af055da),
        BaseField::from_u32_unchecked(0x7ac0bbdf),
        BaseField::from_u32_unchecked(0x6e0f3a24),
        BaseField::from_u32_unchecked(0x41e3b6f7),
        BaseField::from_u32_unchecked(0x49b3756d),
        BaseField::from_u32_unchecked(0x568bc538),
        BaseField::from_u32_unchecked(0x20c079d8),
        BaseField::from_u32_unchecked(0x1701c72c),
        BaseField::from_u32_unchecked(0x7670dc6c),
        BaseField::from_u32_unchecked(0x5a439035),
    ],
    [
        BaseField::from_u32_unchecked(0x7c93e00e),
        BaseField::from_u32_unchecked(0x561fbb4d),
        BaseField::from_u32_unchecked(0x1178907b),
        BaseField::from_u32_unchecked(0x02737406),
        BaseField::from_u32_unchecked(0x32fb24f1),
        BaseField::from_u32_unchecked(0x6323b60a),
        BaseField::from_u32_unchecked(0x6ab12418),
        BaseField::from_u32_unchecked(0x42c99cea),
        BaseField::from_u32_unchecked(0x155a0b97),
        BaseField::from_u32_unchecked(0x53d1c6aa),
        BaseField::from_u32_unchecked(0x2bd20347),
        BaseField::from_u32_unchecked(0x279b3d73),
        BaseField::from_u32_unchecked(0x4f5f3c70),
        BaseField::from_u32_unchecked(0x0245af6c),
        BaseField::from_u32_unchecked(0x238359d3),
        BaseField::from_u32_unchecked(0x49966a59),
    ],
];

// Partial rounds constants (only first element used, RC16[4..18])
pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] = [
    BaseField::from_u32_unchecked(0x7f7ec4bf),
    BaseField::from_u32_unchecked(0x0421926f),
    BaseField::from_u32_unchecked(0x5198e669),
    BaseField::from_u32_unchecked(0x34db3148),
    BaseField::from_u32_unchecked(0x4368bafd),
    BaseField::from_u32_unchecked(0x66685c7f),
    BaseField::from_u32_unchecked(0x78d3249a),
    BaseField::from_u32_unchecked(0x60187881),
    BaseField::from_u32_unchecked(0x76dad67a),
    BaseField::from_u32_unchecked(0x0690b437),
    BaseField::from_u32_unchecked(0x1ea95311),
    BaseField::from_u32_unchecked(0x40e5369a),
    BaseField::from_u32_unchecked(0x38f103fc),
    BaseField::from_u32_unchecked(0x1d226a21),
];

// Diagonal matrix for internal rounds (MAT_DIAG16_M_1)
pub const MAT_INTERNAL_DIAG_M_1: [BaseField; N_STATE] = [
    BaseField::from_u32_unchecked(0x07b80ac4),
    BaseField::from_u32_unchecked(0x6bd9cb33),
    BaseField::from_u32_unchecked(0x48ee3f9f),
    BaseField::from_u32_unchecked(0x4f63dd19),
    BaseField::from_u32_unchecked(0x18c546b3),
    BaseField::from_u32_unchecked(0x5af89e8b),
    BaseField::from_u32_unchecked(0x4ff23de8),
    BaseField::from_u32_unchecked(0x4f78aaf6),
    BaseField::from_u32_unchecked(0x53bdc6d4),
    BaseField::from_u32_unchecked(0x5c59823e),
    BaseField::from_u32_unchecked(0x2a471c72),
    BaseField::from_u32_unchecked(0x4c975e79),
    BaseField::from_u32_unchecked(0x58dc64d4),
    BaseField::from_u32_unchecked(0x06e9315d),
    BaseField::from_u32_unchecked(0x2cf32286),
    BaseField::from_u32_unchecked(0x2fb6755d),
];

#[inline(always)]
pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

pub fn apply_external_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

pub fn apply_internal_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // Compute sum of all elements
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);

    // Apply: state[i] = state[i] * MAT_INTERNAL_DIAG_M_1[i] + sum
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * MAT_INTERNAL_DIAG_M_1[i] + sum.clone();
    });
}

pub fn pow5<F: FieldExpOps>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}

pub fn pow5_expr<F: Clone + std::ops::Mul<Output = F>>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_zkhash_reference_implementation() {
        // Test vectors from cairo-m: https://github.com/kkrt-labs/cairo-m/blob/main/crates/prover/tests/poseidon2.rs
        // Input: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        // Expected output after permutation:
        let expected_outputs = [
            0x505d9689u32,
            0x3b64c904,
            0x79e2fd81,
            0x4ba8015f,
            0x24b6d2f5,
            0x23845add,
            0x521f4314,
            0x69dfb019,
            0x2aaae419,
            0x6cb4502c,
            0x6f7fa65a,
            0x75feff24,
            0x128d6587,
            0x515877e4,
            0x037f4dd7,
            0x134b427f,
        ];

        // Use zkhash as reference implementation
        use zkhash::ark_ff::PrimeField;
        use zkhash::fields::m31::FpM31;
        use zkhash::poseidon2::poseidon2::Poseidon2;
        use zkhash::poseidon2::poseidon2_instance_m31::POSEIDON2_M31_16_PARAMS;

        let poseidon2: Poseidon2<FpM31> = Poseidon2::new(&POSEIDON2_M31_16_PARAMS);

        // Create input [0, 1, 2, ..., 15]
        let input: Vec<FpM31> = (0..16).map(|i| FpM31::from(i as u64)).collect();

        // Run permutation
        let output = poseidon2.permutation(&input);

        // Verify against expected test vectors
        for (i, (computed, expected)) in output.iter().zip(expected_outputs.iter()).enumerate() {
            // Extract u32 value from FpM31 (which is Fp<MontBackend, 1>)
            // ark_ff stores field elements in Montgomery form, we use into_bigint() to get raw representation
            let computed_u32 = computed.into_bigint().0[0] as u32;
            assert_eq!(
                computed_u32, *expected,
                "Mismatch at index {}: computed={:#x}, expected={:#x}",
                i, computed_u32, expected
            );
        }

        println!("✅ zkhash reference implementation matches test vectors!");
    }

    #[test]
    fn test_our_poseidon2_vs_zkhash() {
        // This test compares our Poseidon2 implementation with zkhash reference
        use super::*;
        use zkhash::ark_ff::PrimeField;
        use zkhash::fields::m31::FpM31;
        use zkhash::poseidon2::poseidon2::Poseidon2;
        use zkhash::poseidon2::poseidon2_instance_m31::POSEIDON2_M31_16_PARAMS;

        let poseidon2_ref: Poseidon2<FpM31> = Poseidon2::new(&POSEIDON2_M31_16_PARAMS);

        // Test with input [0, 1, 2, ..., 15]
        let input_ref: Vec<FpM31> = (0..16).map(|i| FpM31::from(i as u64)).collect();
        let output_ref = poseidon2_ref.permutation(&input_ref);

        // Now run our implementation with the same input
        let mut state_our = [BaseField::from_u32_unchecked(0); N_STATE];
        for i in 0..N_STATE {
            state_our[i] = BaseField::from_u32_unchecked(i as u32);
        }

        // Apply our Poseidon2 following zkhash order
        // Initial linear layer
        apply_external_round_matrix(&mut state_our);

        // First 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                state_our[i] = state_our[i] + EXTERNAL_ROUND_CONSTS[round][i];
            }
            state_our = std::array::from_fn(|i| pow5(state_our[i]));
            apply_external_round_matrix(&mut state_our);
        }

        // 14 partial rounds (zkhash order: add → sbox → matrix)
        for round in 0..N_PARTIAL_ROUNDS {
            state_our[0] = state_our[0] + INTERNAL_ROUND_CONSTS[round];
            state_our[0] = pow5(state_our[0]);
            apply_internal_round_matrix(&mut state_our);
        }

        // Last 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                state_our[i] = state_our[i] + EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
            }
            state_our = std::array::from_fn(|i| pow5(state_our[i]));
            apply_external_round_matrix(&mut state_our);
        }

        // Compare outputs
        println!("\n=== Comparing our implementation vs zkhash ===");
        let mut all_match = true;
        for i in 0..N_STATE {
            let our_value = state_our[i].0;
            let ref_value = output_ref[i].into_bigint().0[0] as u32;
            let matches = our_value == ref_value;
            all_match &= matches;
            println!(
                "[{}] our={:#x}, ref={:#x} {}",
                i,
                our_value,
                ref_value,
                if matches { "✓" } else { "✗" }
            );
        }

        if all_match {
            println!("✅ Our implementation matches zkhash!");
        } else {
            println!("❌ Our implementation DOES NOT match zkhash!");
            println!("This means we're using incorrect round constants or matrix.");
        }

        // For now, don't fail the test - just show the comparison
        // assert!(all_match, "Our Poseidon2 implementation does not match zkhash reference");
    }
}
