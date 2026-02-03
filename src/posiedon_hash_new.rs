use stwo_circuits::{
    circuits::{
        context::{Context, Var},
        ivalue::IValue,
    },
    eval,
};

use crate::merkle_tree::N_STATE;

pub fn apply_m4<Value: IValue>(context: &mut Context<Value>, x: [Var; 4]) -> [Var; 4] {
    let t0 = eval!(context, (x[0]) + (x[1]));
    let t02 = eval!(context, (t0) + (t0));
    let t1 = eval!(context, (x[2]) + (x[3]));
    let t12 = eval!(context, (t1) + (t1));

    let t2_temp = eval!(context, (x[1]) + (x[1]));
    let t2 = eval!(context, (t2_temp) + (t1));

    let t3_temp = eval!(context, (x[3]) + (x[3]));
    let t3 = eval!(context, (t3_temp) + (t0));

    let t4_temp = eval!(context, (t12) + (t12));
    let t4 = eval!(context, (t4_temp) + (t3));

    let t5_temp = eval!(context, (t02) + (t02));
    let t5 = eval!(context, (t5_temp) + (t2));

    let t6 = eval!(context, (t3) + (t5));
    let t7 = eval!(context, (t2) + (t4));

    [t6, t5, t7, t4]
}

pub fn pow5<Value: IValue>(context: &mut Context<Value>, x: Var) -> Var {
    let x2 = eval!(context, (x) * (x));
    let x4 = eval!(context, (x2) * (x2));
    eval!(context, (x4) * (x))
}

pub fn apply_external_round_matrix<Value: IValue>(
    context: &mut Context<Value>,
    state: &mut [Var; N_STATE],
) {
    // First: apply M4 to each group of 4
    for i in 0..4 {
        let idx = 4 * i;
        let input = [state[idx], state[idx + 1], state[idx + 2], state[idx + 3]];
        let output = apply_m4(context, input);
        state[idx] = output[0];
        state[idx + 1] = output[1];
        state[idx + 2] = output[2];
        state[idx + 3] = output[3];
    }

    // Second: add column sums to each column
    for j in 0..4 {
        let s = eval!(context, (state[j]) + (state[j + 4]));
        let s = eval!(context, (s) + (state[j + 8]));
        let s = eval!(context, (s) + (state[j + 12]));

        for i in 0..4 {
            state[4 * i + j] = eval!(context, (state[4 * i + j]) + (s));
        }
    }
}

/// Apply internal round matrix
/// Adapted from apply_internal_round_matrix
pub fn apply_internal_round_matrix<Value: IValue>(
    context: &mut Context<Value>,
    state: &mut [Var; N_STATE],
) {
    // Compute sum of all elements
    let mut sum = state[0];
    for i in 1..N_STATE {
        sum = eval!(context, (sum) + (state[i]));
    }

    // Update each state element: state[i] = state[i] * (2^(i+1)) + sum
    for i in 0..N_STATE {
        let coeff = context.constant((1u32 << (i + 1)).into());
        let scaled = eval!(context, (state[i]) * (coeff));
        state[i] = eval!(context, (scaled) + (sum));
    }
}
