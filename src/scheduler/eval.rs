use stwo_prover::{constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, RelationEntry, preprocessed_columns::PreProcessedColumnId}, core::{backend::{Col, simd::SimdBackend}, fields::{m31::BaseField, qm31::SecureField}, poly::{BitReversedOrder, circle::{CanonicCoset, CircleEvaluation}}, utils::bit_reverse_coset_to_circle_domain_order}};
use stwo_prover::core::backend::Column;

use crate::relations::{LeafRelation, RefundLeafRelation, RootRelation};

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

        let computed_root = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let expected_root = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let commitment_amount = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let refund_amount = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let deposit_leaf = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();
        let refund_leaf = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone();

        eval.add_constraint(is_first.clone() * (computed_root.clone() - expected_root));

        // 🔒 SECURITY WARNING: Amount underflow vulnerability (PARTIALLY MITIGATED)
        //
        // This constraint verifies: amount == commitment_amount - refund_amount
        //
        // VULNERABILITY: In M31 field arithmetic, if refund_amount > commitment_amount,
        // the subtraction wraps around modulo (2^31-1). For example:
        //   commitment_amount = 100
        //   refund_amount = 200
        //   Result = 100 - 200 mod (2^31-1) = 2147483547
        //
        // If amount = 2147483547, this constraint would PASS, allowing an attacker
        // to withdraw more funds than deposited!
        //
        // MITIGATIONS IN PLACE:
        // 1. ✅ Runtime check in trace generation (scheduler/trace.rs:30-35)
        //    - Prevents honest prover from generating invalid proofs
        //    - But doesn't protect against malicious prover who modifies the code
        //
        // 2. ⚠️  Smart contract MUST verify commitment_amount >= refund_amount
        //    - This is the primary security boundary
        //    - Circuit cannot fully protect against this without range checks
        //
        // TODO: Add proper range check constraint to verify:
        //   - commitment_amount - refund_amount is in range [0, MAX_SAFE_AMOUNT]
        //   - This requires additional columns and lookup tables
        //   - See: https://github.com/privacy-pools/issues/range-check
        //
        // DEPLOYMENT CHECKLIST:
        // [ ] Smart contract verifies commitment_amount >= refund_amount
        // [ ] Smart contract verifies amounts are reasonable (< MAX_DEPOSIT)
        // [ ] Add integration tests for underflow scenarios
        eval.add_constraint(
            is_first.clone() * (E::F::from(self.amount) - (commitment_amount - refund_amount)),
        );

        eval.add_constraint(
            is_first.clone() * (E::F::from(self.refund_commitment_hash) - refund_leaf.clone()),
        );

        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            (-is_first.clone()).into(),
            &[deposit_leaf],
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.root_relation,
            (-is_first.clone()).into(),
            &[computed_root],
        ));

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

pub fn gen_is_first_column(
    log_size: u32,
) -> CircleEvaluation<
    SimdBackend,
    BaseField,
    BitReversedOrder,
> {
    use num_traits::One;

    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    if n_rows > 0 {
        col.set(0, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    let domain = CanonicCoset::new(log_size).circle_domain();
    CircleEvaluation::new(domain, col)
}

pub fn is_first_column_id(log_size: u32) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("scheduler_is_first_{}", log_size),
    }
}
