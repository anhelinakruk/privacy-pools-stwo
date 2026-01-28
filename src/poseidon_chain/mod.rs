pub mod types;
pub mod trace;
pub mod eval;
pub mod logup;

#[cfg(test)]
mod tests;

pub use types::{ChainInputs, ChainOutputs, ChainStatement0, ChainStatement1};
pub use trace::{gen_poseidon_chain_trace, fill_poseidon_row, ColumnVec, N_COLUMNS, N_CHAIN_ROWS};
pub use eval::{
    PoseidonChainEval, PoseidonChainComponent,
    gen_is_active_column, gen_is_step_column, gen_is_last_column,
    is_active_column_id, is_step_column_id, is_first_column_id, is_last_column_id,
};
pub use logup::gen_poseidon_chain_interaction_trace;
