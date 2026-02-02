use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{LogupTraceGenerator, Relation};
use num_traits::One;

use crate::{LeafRelation, RootRelation};

use super::trace::ColumnVec;

const CURRENT_NODE_INPUT_COL: usize = 0;

const FINAL_STATE_0_COL: usize = 159;

pub fn gen_merkle_membership_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    leaf_relation: &LeafRelation,
    root_relation: &RootRelation,
    log_size: u32,
    depth: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;

    // Generate is_first selector column (1 only for row 0)
    let mut is_first_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    if n_rows > 0 {
        is_first_col.set(0, BaseField::one());
    }
    bit_reverse_coset_to_circle_domain_order(is_first_col.as_mut_slice());

    // Generate is_last selector column (1 only for row depth-1)
    let mut is_last_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    if depth > 0 && depth - 1 < n_rows {
        is_last_col.set(depth - 1, BaseField::one());
    }
    bit_reverse_coset_to_circle_domain_order(is_last_col.as_mut_slice());

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read leaf value from current_node_input column (column 0)
            // This is always the correct input value, regardless of index_bit
            let leaf_value: PackedSecureField = trace[CURRENT_NODE_INPUT_COL].data[vec_row].into();
            let leaf_denom: PackedSecureField = leaf_relation.combine(&[leaf_value]);

            // Read root value (final_state[0])
            let root_value: PackedSecureField = trace[FINAL_STATE_0_COL].data[vec_row].into();
            let root_denom: PackedSecureField = root_relation.combine(&[root_value]);

            // Get selectors
            let is_first_value = is_first_col.data[vec_row];
            let is_last_value = is_last_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let is_last_secure: PackedSecureField = is_last_value.into();

            // Combine TWO fractions: -is_first/leaf_denom + is_last/root_denom
            // = (is_last * leaf_denom - is_first * root_denom) / (leaf_denom * root_denom)
            let numerator = is_last_secure * leaf_denom - is_first_secure * root_denom;
            let denominator = leaf_denom * root_denom;

            col_gen.write_frac(vec_row, numerator, denominator);
        }

        col_gen.finalize_col();
    }

    // Finalize and return single interaction trace
    logup_gen.finalize_last()
}
