use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

use crate::poseidon_hash::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5, EXTERNAL_ROUND_CONSTS,
    INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
};

use super::types::{ChainInputs, ChainOutputs};

pub type ColumnVec<T> = Vec<T>;

pub const N_CHAIN_ROWS: usize = 3;

pub const N_COLUMNS: usize = N_STATE
    + (N_HALF_FULL_ROUNDS * N_STATE)
    + N_PARTIAL_ROUNDS
    + (N_HALF_FULL_ROUNDS * N_STATE)
    + N_STATE;

pub fn gen_poseidon_chain_trace(
    log_size: u32,
    inputs: ChainInputs,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ChainOutputs,
) {
    let n_rows = 1 << log_size;
    assert!(n_rows >= N_CHAIN_ROWS, "log_size too small for chain");

    let mut trace = (0..N_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect::<Vec<_>>();

    let hash1 = fill_poseidon_row(&mut trace, 0, inputs.input1_a, inputs.input1_b);
    let hash2 = fill_poseidon_row(&mut trace, 1, hash1, inputs.input2);
    let leaf = fill_poseidon_row(&mut trace, 2, hash2, inputs.input3);

    for row in N_CHAIN_ROWS..n_rows {
        for col_index in 0..N_COLUMNS {
            trace[col_index].set(row, BaseField::from_u32_unchecked(0));
        }
    }

    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    let trace_cols = trace
        .into_iter()
        .map(|col| CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col))
        .collect::<Vec<_>>();

    (trace_cols, ChainOutputs { leaf })
}

pub fn fill_poseidon_row(
    trace: &mut Vec<Col<SimdBackend, BaseField>>,
    row: usize,
    input1: BaseField,
    input2: BaseField,
) -> BaseField {
    let mut col_index = 0;
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = input1;
    state[1] = input2;

    // Write initial_state
    for i in 0..N_STATE {
        trace[col_index].set(row, state[i]);
        col_index += 1;
    }

    // First 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round][i];
        }
        apply_external_round_matrix(&mut state);
        state = std::array::from_fn(|i| pow5(state[i]));

        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }
    }

    // Partial rounds
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] = state[0] + INTERNAL_ROUND_CONSTS[round];
        apply_internal_round_matrix(&mut state);
        state[0] = pow5(state[0]);

        trace[col_index].set(row, state[0]);
        col_index += 1;
    }

    // Last 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
        }
        apply_external_round_matrix(&mut state);
        state = std::array::from_fn(|i| pow5(state[i]));

        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }
    }

    // Write final_state
    for i in 0..N_STATE {
        trace[col_index].set(row, state[i]);
        col_index += 1;
    }

    state[0]
}
