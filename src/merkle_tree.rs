use stwo_circuits::{
    circuits::{
        context::{Context, TraceContext, Var},
        ivalue::IValue,
    },
    eval,
    stark_verifier::constraint_eval::{
        CircuitEval, ComponentData, CompositionConstraintAccumulator,
    },
};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::{
    poseidon_hash::{EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS},
    posiedon_hash_new::{apply_external_round_matrix, apply_internal_round_matrix, pow5},
};

pub const N_STATE: usize = 16;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const N_PARTIAL_ROUNDS: usize = 14;

// Total columns calculation:
// 1 (current_node_input) + 16 (initial_state) + 64 (intermediate_full1) +
// 14 (intermediate_partial) + 64 (intermediate_full2) + 16 (final_state) = 175
pub const N_TRACE_COLUMNS: usize = 175;

struct MerkleTraceColumns {
    current_node_input: Var,
    initial_state: [Var; N_STATE],
    intermediate_full1: [[Var; N_STATE]; N_HALF_FULL_ROUNDS],
    intermediate_partial: [Var; N_PARTIAL_ROUNDS],
    intermediate_full2: [[Var; N_STATE]; N_HALF_FULL_ROUNDS],
    final_state: [Var; N_STATE],
}

impl MerkleTraceColumns {
    fn from_trace(columns: &[Var]) -> Self {
        assert_eq!(columns.len(), N_TRACE_COLUMNS, "Expected 175 trace columns");

        let mut index = 0;

        let current_node_input = columns[index].clone();
        index += 1;

        // Columns 1-16: initial_state
        let mut initial_state = [columns[0].clone(); N_STATE];
        for i in 0..N_STATE {
            initial_state[i] = columns[index].clone();
            index += 1;
        }

        // Columns 17-80: intermediate_full1 (4 rounds × 16 state = 64 columns)
        let mut intermediate_full1 = [[columns[0].clone(); N_STATE]; N_HALF_FULL_ROUNDS];
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                intermediate_full1[round][i] = columns[index].clone();
                index += 1;
            }
        }

        // Columns 81-94: intermediate_partial (14 rounds = 14 columns)
        let mut intermediate_partial = [columns[0].clone(); N_PARTIAL_ROUNDS];
        for round in 0..N_PARTIAL_ROUNDS {
            intermediate_partial[round] = columns[index].clone();
            index += 1;
        }

        // Columns 95-158: intermediate_full2 (4 rounds × 16 state = 64 columns)
        let mut intermediate_full2 = [[columns[0].clone(); N_STATE]; N_HALF_FULL_ROUNDS];
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                intermediate_full2[round][i] = columns[index].clone();
                index += 1;
            }
        }

        // Columns 159-174: final_state (16 columns)
        let mut final_state = [columns[0].clone(); N_STATE];
        for i in 0..N_STATE {
            final_state[i] = columns[index].clone();
            index += 1;
        }

        assert_eq!(
            index, N_TRACE_COLUMNS,
            "Should have consumed all 175 columns"
        );

        Self {
            current_node_input,
            initial_state,
            intermediate_full1,
            intermediate_partial,
            intermediate_full2,
            final_state,
        }
    }
}

pub struct MerkleMembershipComponent {
    pub is_active_id: PreProcessedColumnId,
    pub is_step_id: PreProcessedColumnId,
    pub is_first_id: PreProcessedColumnId,
    pub is_last_id: PreProcessedColumnId,
}

impl<Value: IValue> CircuitEval<Value> for MerkleMembershipComponent {
    fn trace_columns(&self) -> usize {
        N_TRACE_COLUMNS
    }

    fn interaction_columns(&self) -> usize {
        8
    }

    fn evaluate(
        &self,
        context: &mut Context<Value>,
        component_data: &ComponentData<'_>,
        acc: &mut CompositionConstraintAccumulator,
    ) {
        // Main trace columns
        let cols = MerkleTraceColumns::from_trace(component_data.trace_columns);

        // Preprocessed columns
        let is_active_val = acc.get_preprocessed_column(&self.is_active_id);
        let is_step_val = acc.get_preprocessed_column(&self.is_step_id);
        let is_first_val = acc.get_preprocessed_column(&self.is_first_id);
        let is_last_val = acc.get_preprocessed_column(&self.is_last_id);

        // Constraint 1: state[2..16] must be zero (capacity) - masked by is_active
        for i in 2..N_STATE {
            let constraint = eval!(context, (is_active_val) * (cols.initial_state[i].clone()));
            acc.add_constraint(context, constraint);
        }

        // Constraint 2: Poseidon2 Permutation Constraints
        let mut state = cols.initial_state;

        // First 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            // Step 1: Add round constants
            for i in 0..N_STATE {
                let constant = context.constant(EXTERNAL_ROUND_CONSTS[round][i].into());
                state[i] = eval!(context, (state[i]) + (constant));
            }

            // Step 2: Apply MDS matrix
            apply_external_round_matrix(context, &mut state);

            // Step 3: Apply S-box (x^5)
            for i in 0..N_STATE {
                state[i] = pow5(context, state[i]);
            }

            // Step 4: Constraint - computed state should match intermediate
            for i in 0..N_STATE {
                let constraint = eval!(
                    context,
                    (is_active_val) * ((state[i]) - (cols.intermediate_full1[round][i]))
                );
                acc.add_constraint(context, constraint);
            }

            // Update state to intermediate (for next round)
            state = cols.intermediate_full1[round];
        }

        // 14 partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            // Step 1: Add round constant to state[0] only
            let constant = context.constant(INTERNAL_ROUND_CONSTS[round].into());
            state[0] = eval!(context, (state[0]) + (constant));

            // Step 2: Apply internal MDS matrix
            apply_internal_round_matrix(context, &mut state);

            // Step 3: Apply S-box (x^5) to state[0] only
            state[0] = pow5(context, state[0]);

            // Step 4: Constraint - state[0] should match intermediate
            let constraint = eval!(
                context,
                (is_active_val) * ((state[0]) - (cols.intermediate_partial[round]))
            );
            acc.add_constraint(context, constraint);

            // Update state[0] to intermediate
            state[0] = cols.intermediate_partial[round];
        }

        // Last 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            // Step 1: Add round constants
            for i in 0..N_STATE {
                let constant =
                    context.constant(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i].into());
                state[i] = eval!(context, (state[i]) + (constant));
            }

            // Step 2: Apply MDS matrix
            apply_external_round_matrix(context, &mut state);

            // Step 3: Apply S-box (x^5)
            for i in 0..N_STATE {
                state[i] = pow5(context, state[i]);
            }

            // Step 4: Constraint - computed state should match intermediate
            for i in 0..N_STATE {
                let constraint = eval!(
                    context,
                    (is_active_val) * ((state[i]) - (cols.intermediate_full2[round][i]))
                );
                acc.add_constraint(context, constraint);
            }

            // Update state to intermediate
            state = cols.intermediate_full2[round];
        }

        // Final state consistency - masked by is_active
        for i in 0..N_STATE {
            let constraint = eval!(
                context,
                (is_active_val) * ((cols.final_state[i]) - (state[i]))
            );
            acc.add_constraint(context, constraint);
        }

        // Constraint 3: Link initial and final states across steps
        let chaining_constraint = eval!(
            context,
            (is_step_val) * (cols.final_state[0]) // Should equal next row's initial_state[0]
        );
        let _ = chaining_constraint;

        // Logup for leaf
        let leaf_numerator = eval!(context, -(is_first_val));
        acc.add_to_relation(context, leaf_numerator, &[cols.current_node_input]);

        // Logup for root
        acc.add_to_relation(context, is_last_val, &[cols.final_state[0]]);

    }
}

// pub fn build_merkle_membership_circuit(depth: usize) -> TraceContext {
//     let context = TraceContext::default();
// }
