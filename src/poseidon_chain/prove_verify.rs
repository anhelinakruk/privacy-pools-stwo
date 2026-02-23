
use stwo::core::air::{Component, Components};
use stwo::core::channel::KeccakChannel;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::keccak_hash::KeccakHash;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{PolyOps, SecureCirclePoly};
use stwo::prover::CommitmentSchemeProver;
use stwo_constraint_framework::{FrameworkComponent, PREPROCESSED_TRACE_IDX, TraceLocationAllocator};
use stwo_polynomial::prove::prove;
use stwo::core::vcs::keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher};

use crate::poseidon_chain::{
    eval::{
        gen_is_active_column, gen_is_last_column, gen_is_step_column, is_active_column_id,
        is_last_column_id, is_step_column_id, PoseidonChainComponent, PoseidonChainEval,
    },
    logup::gen_poseidon_chain_interaction_trace,
    trace::gen_poseidon_chain_trace,
    types::{ChainInputs, ChainStatement0},
};
use crate::relations::LeafRelation;

pub struct PoseidonChainProofData {
    pub proof: StarkProof<KeccakMerkleHasher>,
    pub claimed_sum: stwo::core::fields::qm31::QM31,
    pub composition_polynomial: SecureCirclePoly<SimdBackend>,
    pub config: PcsConfig,
}

pub fn prove_poseidon_chain(
    log_size: u32,
    inputs: ChainInputs,
    leaf_multiplicity: u32,
) -> Result<PoseidonChainProofData, Box<dyn std::error::Error>> {
    // Generate trace
    let (trace, _outputs) = gen_poseidon_chain_trace(log_size, inputs.clone());

    // Generate preprocessed columns
    let is_active_col = gen_is_active_column(log_size);
    let is_step_col = gen_is_step_column(log_size);
    let is_last_col = gen_is_last_column(log_size);

    // Setup prover
    let config = PcsConfig::default();
    let log_max_rows = log_size + 3;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut KeccakChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

    // Draw leaf relation from channel
    let leaf_relation = LeafRelation::draw(prover_channel);

    // Commit preprocessed columns
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals([
        is_active_col.clone(),
        is_step_col.clone(),
        is_last_col.clone(),
    ]);
    tree_builder.commit(prover_channel);

    // Commit base trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.clone());
    tree_builder.commit(prover_channel);

    // Generate interaction trace for LogUp
    let (interaction_trace, claimed_sum) = gen_poseidon_chain_interaction_trace(
        &trace,
        &leaf_relation,
        log_size,
        leaf_multiplicity,
    );
    println!("  ✓ Generated interaction trace with {} columns", interaction_trace.len());
    println!("  ✓ Claimed sum: {:?}", claimed_sum);

    // Commit interaction trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace.clone());
    tree_builder.commit(prover_channel);
    println!("  ✓ Committed interaction trace");

    // Create component
    let mut tree_span_provider = TraceLocationAllocator::new_with_preprocessed_columns(&[
        is_active_column_id(log_size, "test"),
        is_step_column_id(log_size, "test"),
        is_last_column_id(log_size, "test"),
    ]);

    let component = PoseidonChainComponent::new(
        &mut tree_span_provider,
        PoseidonChainEval {
            log_n_rows: log_size,
            is_active_id: is_active_column_id(log_size, "test"),
            is_step_id: is_step_column_id(log_size, "test"),
            is_last_id: is_last_column_id(log_size, "test"),
            leaf_relation: leaf_relation.clone(),
            leaf_multiplicity,
            claimed_sum,
        },
        claimed_sum,
    );

    // Generate proof
    let (proof, composition_polynomial) = prove(
        &[&component],
        prover_channel,
        commitment_scheme,
    )?;

    println!("✅ Proof generated successfully!\n");

    Ok(PoseidonChainProofData {
        proof,
        claimed_sum,
        composition_polynomial,
        config,
    })
}

pub fn verify_poseidon_chain(
    proof_data: PoseidonChainProofData,
    log_size: u32,
    leaf_multiplicity: u32,
) -> Result<(KeccakHash, FrameworkComponent<PoseidonChainEval> , Vec<KeccakHash>, Vec<Vec<u32>>, u32), Box<dyn std::error::Error>> {
    let verifier_channel = &mut KeccakChannel::default();
    let mut commitment_scheme_verifier =
        CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.config);
    let statement0 = ChainStatement0 { log_size };
    let log_sizes = statement0.log_sizes();

    // Draw leaf relation again (verifier side)
    let leaf_relation_v = LeafRelation::draw(verifier_channel);

    // Commit preprocessed (3 columns: is_active, is_step, is_last)
    commitment_scheme_verifier.commit(
        proof_data.proof.commitments[0],
        &log_sizes[0],
        verifier_channel,
    );

    // Commit base trace
    commitment_scheme_verifier.commit(
        proof_data.proof.commitments[1],
        &log_sizes[1],
        verifier_channel,
    );

    // Commit interaction trace
    // finalize_logup_in_pairs() creates 4 columns per relation pair
    commitment_scheme_verifier.commit(
        proof_data.proof.commitments[2],
        &log_sizes[2],
        verifier_channel,
    );

    let extended_log_sizes: Vec<Vec<u32>> = log_sizes
        .iter()
        .map(|tree_log_sizes| {
            tree_log_sizes
                .iter()
                .map(|&ls| ls + proof_data.proof.config.fri_config.log_blowup_factor)
                .collect()
        })
        .collect();
    println!("Extended log sizes for FRI: {:?}", extended_log_sizes);

    // Create verifier component
    let mut tree_span_provider_verifier = TraceLocationAllocator::new_with_preprocessed_columns(&[
        is_active_column_id(log_size, "test"),
        is_step_column_id(log_size, "test"),
        is_last_column_id(log_size, "test"),
    ]);

    let verifier_component = PoseidonChainComponent::new(
        &mut tree_span_provider_verifier,
        PoseidonChainEval {
            log_n_rows: log_size,
            is_active_id: is_active_column_id(log_size, "test"),
            is_step_id: is_step_column_id(log_size, "test"),
            is_last_id: is_last_column_id(log_size, "test"),
            leaf_relation: leaf_relation_v.clone(),
            leaf_multiplicity,
            claimed_sum: proof_data.claimed_sum,
        },
        proof_data.claimed_sum,
    );

    let digest = verifier_channel.digest();

    // Verify
    stwo_polynomial::verify::verify(
        &[&verifier_component],
        verifier_channel,
        &mut commitment_scheme_verifier,
        proof_data.proof.clone(),
        proof_data.composition_polynomial
    )?;
    println!("✅ Proof verified successfully!");

    let n_preprocessed_columns = commitment_scheme_verifier.trees[PREPROCESSED_TRACE_IDX]
        .column_log_sizes
        .len();
    let components_vec: Vec<&dyn Component> = vec![
        &verifier_component as &dyn Component,
    ];  

    let components = Components {
        components: components_vec,
        n_preprocessed_columns,
    };

    let components_log_degree_bound = components.composition_log_degree_bound();

    Ok((digest, verifier_component, vec![proof_data.proof.commitments[0], proof_data.proof.commitments[1], proof_data.proof.commitments[2]], extended_log_sizes, components_log_degree_bound))
}
