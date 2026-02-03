//! Constraint evaluator for Poseidon hash chain computation

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX,
};

use crate::poseidon_hash::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5_expr, EXTERNAL_ROUND_CONSTS,
    INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
};

use super::trace::N_CHAIN_ROWS;
use crate::relations::LeafRelation;

#[derive(Clone)]
pub struct PoseidonChainEval {
    pub log_n_rows: u32,
    pub is_active_id: PreProcessedColumnId,
    pub is_step_id: PreProcessedColumnId,
    pub is_last_id: PreProcessedColumnId,
    pub leaf_relation: LeafRelation,
    pub leaf_multiplicity: u32,
    pub claimed_sum: stwo::core::fields::qm31::SecureField,
}

impl FrameworkEval for PoseidonChainEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 3 // LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_active_val = eval.get_preprocessed_column(self.is_active_id.clone());
        let is_step_val = eval.get_preprocessed_column(self.is_step_id.clone());
        let is_last_val = eval.get_preprocessed_column(self.is_last_id.clone());

        // Read initial state (16 elements)
        let [initial_state_first_curr, initial_state_first_next] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);

        // Read the rest of initial_state (cols 1-15) normally with offset [0]
        let initial_state_curr: [E::F; N_STATE] = std::array::from_fn(|i| {
            if i == 0 {
                initial_state_first_curr.clone()
            } else {
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone()
            }
        });

        // Constraint: state[2..16] must be zero (capacity)
        for i in 2..N_STATE {
            eval.add_constraint(is_active_val.clone() * initial_state_curr[i].clone());
        }

        // Read intermediate states
        let intermediate_full1: [[E::F; N_STATE]; N_HALF_FULL_ROUNDS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone())
        });

        let intermediate_partial: [E::F; N_PARTIAL_ROUNDS] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone());

        let intermediate_full2: [[E::F; N_STATE]; N_HALF_FULL_ROUNDS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone())
        });

        let final_state_curr: [E::F; N_STATE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone());

        // Poseidon2 permutation constraints
        let mut state = initial_state_curr.clone();

        // First 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                state[i] = state[i].clone() + E::F::from(EXTERNAL_ROUND_CONSTS[round][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5_expr(state[i].clone()));

            for i in 0..N_STATE {
                eval.add_constraint(
                    is_active_val.clone()
                        * (state[i].clone() - intermediate_full1[round][i].clone()),
                );
            }
            state = intermediate_full1[round].clone();
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            state[0] = state[0].clone() + E::F::from(INTERNAL_ROUND_CONSTS[round]);
            apply_internal_round_matrix(&mut state);
            state[0] = pow5_expr(state[0].clone());

            eval.add_constraint(
                is_active_val.clone() * (state[0].clone() - intermediate_partial[round].clone()),
            );
            state[0] = intermediate_partial[round].clone();
        }

        // Last 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                state[i] = state[i].clone()
                    + E::F::from(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5_expr(state[i].clone()));

            for i in 0..N_STATE {
                eval.add_constraint(
                    is_active_val.clone()
                        * (state[i].clone() - intermediate_full2[round][i].clone()),
                );
            }
            state = intermediate_full2[round].clone();
        }

        // Verify final state
        for i in 0..N_STATE {
            eval.add_constraint(
                is_active_val.clone() * (state[i].clone() - final_state_curr[i].clone()),
            );
        }

        eval.add_constraint(is_step_val * (final_state_curr[0].clone() - initial_state_first_next));

        let leaf_value = final_state_curr[0].clone();

        // LogUp: yield leaf with configurable multiplicity
        // For deposit chain: multiplicity=2 (consumed by Merkle + Scheduler)
        // For refund chain: multiplicity=1 (consumed by Scheduler only)
        let multiplicity =
            is_last_val * E::F::from(BaseField::from_u32_unchecked(self.leaf_multiplicity));
        eval.add_to_relation(RelationEntry::new(
            &self.leaf_relation,
            multiplicity.into(),
            &[leaf_value],
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type PoseidonChainComponent = FrameworkComponent<PoseidonChainEval>;

pub fn gen_is_active_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..N_CHAIN_ROWS.min(n_rows) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_active_column_id(log_size: u32, component_name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_active_{}_{}", component_name, log_size),
    }
}

pub fn gen_is_step_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    for row in 0..(N_CHAIN_ROWS.saturating_sub(1)).min(n_rows) {
        col.set(row, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_step_column_id(log_size: u32, component_name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_step_{}_{}", component_name, log_size),
    }
}

pub fn is_first_column_id(log_size: u32) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_first_{}", log_size),
    }
}

pub fn gen_is_last_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    if N_CHAIN_ROWS > 0 && N_CHAIN_ROWS - 1 < n_rows {
        col.set(N_CHAIN_ROWS - 1, BaseField::one());
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_last_column_id(log_size: u32, component_name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_last_{}_{}", component_name, log_size),
    }
}
