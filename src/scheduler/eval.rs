use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX,
};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::relations::{LeafRelation, RootRelation, RefundLeafRelation};

#[derive(Clone)]
pub struct PrivacyPoolSchedulerEval {
    pub log_n_rows: u32,
    pub is_first_id: PreProcessedColumnId,
    pub leaf_relation: LeafRelation,
    pub root_relation: RootRelation,
    pub refund_leaf_relation: RefundLeafRelation,
    pub amount: BaseField,
    pub refund_commitment_hash: BaseField,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for PrivacyPoolSchedulerEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 3 // LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(self.is_first_id.clone());

        // Read 6 trace columns
        let computed_root = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let expected_root = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let commitment_amount = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let refund_amount = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let deposit_leaf = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let refund_leaf = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();

        // Constraint 1: computed_root == expected_root (only for first row)
        eval.add_constraint(is_first.clone() * (computed_root.clone() - expected_root));

        // Constraint 2: amount == commitment_amount - refund_amount (only for first row)
        eval.add_constraint(
            is_first.clone() * (E::F::from(self.amount) - (commitment_amount - refund_amount))
        );

        // Constraint 3: refund_commitment_hash == refund_leaf (only for first row)
        eval.add_constraint(is_first.clone() * (E::F::from(self.refund_commitment_hash) - refund_leaf.clone()));

        // LogUp: consume deposit_leaf from deposit chain
        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            (-is_first.clone()).into(),
            &[deposit_leaf],
        ));

        // LogUp: consume computed_root from merkle
        eval.add_to_relation(RelationEntry::new(
            &self.root_relation,
            (-is_first.clone()).into(),
            &[computed_root],
        ));

        // LogUp: consume refund_leaf from refund chain
        eval.add_to_relation(RelationEntry::new(
            &self.refund_leaf_relation,
            (-is_first).into(),
            &[refund_leaf],
        ));

        eval.finalize_logup();
        eval
    }
}

pub type PrivacyPoolSchedulerComponent = FrameworkComponent<PrivacyPoolSchedulerEval>;

pub fn gen_is_first_column(log_size: u32) -> stwo::prover::poly::circle::CircleEvaluation<
    stwo::prover::backend::simd::SimdBackend,
    BaseField,
    stwo::prover::poly::BitReversedOrder,
> {
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::backend::{Col, Column};
    use num_traits::One;

    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    if n_rows > 0 {
        col.set(0, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    let domain = CanonicCoset::new(log_size).circle_domain();
    stwo::prover::poly::circle::CircleEvaluation::new(domain, col)
}

pub fn is_first_column_id(log_size: u32) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("scheduler_is_first_{}", log_size),
    }
}
