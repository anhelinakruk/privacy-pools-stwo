use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{LogupTraceGenerator, Relation};
use num_traits::One;

use crate::relations::{LeafRelation, RootRelation, RefundLeafRelation};

pub fn gen_scheduler_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    leaf_relation: &LeafRelation,
    root_relation: &RootRelation,
    refund_leaf_relation: &RefundLeafRelation,
    log_size: u32,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;

    let mut is_first_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    is_first_col.set(0, BaseField::one());
    bit_reverse_coset_to_circle_domain_order(is_first_col.as_mut_slice());

    // Columns: [computed_root, expected_root, commitment_amount, refund_amount, deposit_leaf, refund_leaf]

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    // Relation 1: consume deposit_leaf (MUST match eval.rs order!)
    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let col_data = &trace[4].data;  // deposit_leaf column (index 4)
            let deposit_leaf_value: PackedSecureField = col_data[vec_row].into();

            let denom: PackedSecureField = leaf_relation.combine(&[deposit_leaf_value]);

            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure;

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    // Relation 2: consume root (MUST match eval.rs order!)
    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let col_data = &trace[0].data;  // computed_root column
            let computed_root_value: PackedSecureField = col_data[vec_row].into();

            let denom: PackedSecureField = root_relation.combine(&[computed_root_value]);

            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure;

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    // Relation 3: consume refund_leaf (MUST match eval.rs order!)
    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let col_data = &trace[5].data;  // refund_leaf column (index 5)
            let refund_leaf_value: PackedSecureField = col_data[vec_row].into();

            let denom: PackedSecureField = refund_leaf_relation.combine(&[refund_leaf_value]);

            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure;

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}
