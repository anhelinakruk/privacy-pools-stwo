use num_traits::One;
use stwo_prover::{constraint_framework::{Relation, logup::LogupTraceGenerator}, core::{ColumnVec, backend::{Col, simd::{SimdBackend, m31::{LOG_N_LANES, PackedM31}, qm31::PackedSecureField}}, fields::{m31::BaseField, qm31::SecureField}, poly::{BitReversedOrder, circle::CircleEvaluation}, utils::bit_reverse_coset_to_circle_domain_order}};
use crate::{poseidon_chain::N_CHAIN_ROWS, relations::LeafRelation};
use stwo_prover::core::backend::Column;

// Cairo-m style with security fix: final_state[0] is in the last round's step3, first element
// Layout: 16 (initial) + 192 (first_half) + 266 (partial with matrix) + 192 (second_half) = 666 total
// Partial rounds now have 4 steps: x^2(1), x^4(1), x^5(1), after_matrix(16) = 19 cols per round
// Last round step3 starts at column 650 (650-665 for all 16 elements)
const FINAL_STATE_0_COL: usize = 650;

/// Generate interaction trace for Poseidon chain with LeafRelation.
pub fn gen_poseidon_chain_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    leaf_relation: &LeafRelation,
    log_size: u32,
    leaf_multiplicity: u32,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;

    // Generate is_last selector column (1 only for row N_CHAIN_ROWS-1)
    let mut is_last_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    if N_CHAIN_ROWS > 0 && N_CHAIN_ROWS - 1 < n_rows {
        is_last_col.set(N_CHAIN_ROWS - 1, BaseField::one());
    }
    bit_reverse_coset_to_circle_domain_order(is_last_col.as_mut_slice());

    // Extract leaf value from final_state[0] column (column 426)
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read final_state[0] (leaf value) from column 426
            let col_data = &trace[FINAL_STATE_0_COL].data;
            let leaf_value: PackedSecureField = col_data[vec_row].into();

            // Multiplicity controlled by is_last selector (positive for "yield")
            let is_last_value = is_last_col.data[vec_row];
            let is_last_secure: PackedSecureField = is_last_value.into();

            // Combine using leaf_relation (1 element)
            let denom: PackedSecureField = leaf_relation.combine(&[leaf_value]);

            // Apply multiplicity (2 for deposit chain, 1 for refund chain)
            let multiplicity_base = BaseField::from_u32_unchecked(leaf_multiplicity);
            let multiplicity_packed: PackedM31 =
                multiplicity_base.into();
            let multiplicity_secure: PackedSecureField = multiplicity_packed.into();
            let numerator = is_last_secure * multiplicity_secure; // +multiplicity for last row

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}
