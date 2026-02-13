#[cfg(test)]
mod tests {
    use stwo_prover::{constraint_framework::TraceLocationAllocator, core::{backend::{Col, simd::SimdBackend}, channel::Blake2sChannel, fields::m31::BaseField, pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig}, poly::circle::{CanonicCoset, PolyOps}, prover::{prove, verify}, vcs::blake2_merkle::Blake2sMerkleChannel}};
    use stwo_prover::core::backend::Column;
    use crate::poseidon_chain::{
        eval::{
            gen_is_active_column, gen_is_last_column, gen_is_step_column, is_active_column_id,
            is_last_column_id, is_step_column_id, PoseidonChainComponent, PoseidonChainEval,
        },
        logup::gen_poseidon_chain_interaction_trace,
        trace::{fill_poseidon_row, gen_poseidon_chain_trace, N_COLUMNS},
        types::ChainInputs,
    };
    use crate::relations::LeafRelation;

    #[test]
    fn test_poseidon_chain_trace_generation() {
        const LOG_SIZE: u32 = 5;

        let inputs = ChainInputs::for_deposit(
            BaseField::from_u32_unchecked(12345),
            BaseField::from_u32_unchecked(67890),
            BaseField::from_u32_unchecked(100),
            BaseField::from_u32_unchecked(0xABCD),
        );

        println!("Inputs:");
        println!("  input1_a: {}", inputs.input1_a.0);
        println!("  input1_b: {}", inputs.input1_b.0);
        println!("  input2: {}", inputs.input2.0);
        println!("  input3: {}\n", inputs.input3.0);

        // Generate trace
        println!("Generating trace...");
        let (trace, outputs) = gen_poseidon_chain_trace(LOG_SIZE, inputs.clone());
        println!("  ✓ Trace generated!");
        println!("  Trace has {} columns", trace.len());
        println!("  Computed leaf: {}\n", outputs.leaf.0);

        // Manually verify the hash chain using a temporary trace
        println!("Verifying hash chain manually...");
        let n_rows = 1 << LOG_SIZE;
        let mut temp_trace = (0..N_COLUMNS)
            .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
            .collect::<Vec<_>>();

        let hash1 = fill_poseidon_row(&mut temp_trace, 0, inputs.input1_a, inputs.input1_b);
        println!("  hash1 = hash(input1_a, input1_b) = {}", hash1.0);

        let hash2 = fill_poseidon_row(&mut temp_trace, 1, hash1, inputs.input2);
        println!("  hash2 = hash(hash1, input2) = {}", hash2.0);

        let leaf_manual = fill_poseidon_row(&mut temp_trace, 2, hash2, inputs.input3);
        println!("  leaf = hash(hash2, input3) = {}\n", leaf_manual.0);

        // Verify outputs match
        assert_eq!(outputs.leaf, leaf_manual, "Leaf mismatch!");
        println!("✓✓✓ Hash chain verified! ✓✓✓");
        println!("\nFinal leaf hash: {}", outputs.leaf.0);
    }

    #[test]
    fn test_poseidon_chain_prove_and_verify() {
        // use stwo::prover::{prove, CommitmentSchemeProver};

        const LOG_SIZE: u32 = 5;

        let inputs = ChainInputs::for_deposit(
            BaseField::from_u32_unchecked(12345),
            BaseField::from_u32_unchecked(67890),
            BaseField::from_u32_unchecked(100),
            BaseField::from_u32_unchecked(0xABCD),
        );

        println!("Inputs:");
        println!("  input1_a: {}", inputs.input1_a.0);
        println!("  input1_b: {}", inputs.input1_b.0);
        println!("  input2: {}", inputs.input2.0);
        println!("  input3: {}\n", inputs.input3.0);

        // Generate trace
        let (trace, outputs) = gen_poseidon_chain_trace(LOG_SIZE, inputs.clone());

        // Generate preprocessed columns
        let is_active_col = gen_is_active_column(LOG_SIZE);
        let is_step_col = gen_is_step_column(LOG_SIZE);
        let is_last_col = gen_is_last_column(LOG_SIZE);

        // Setup prover
        let config = PcsConfig::default();
        let log_max_rows = LOG_SIZE + 3;
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let prover_channel = &mut Blake2sChannel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // Draw leaf relation from channel
        let leaf_relation = LeafRelation::draw(prover_channel);

        // Commit preprocessed columns
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(
            [
                is_active_col.clone(),
                is_step_col.clone(),
                is_last_col.clone(),
            ]
            .to_vec(),
        );
        tree_builder.commit(prover_channel);

        // Commit base trace
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace.clone());
        tree_builder.commit(prover_channel);

        // Generate interaction trace for LogUp
        let (interaction_trace, claimed_sum) = gen_poseidon_chain_interaction_trace(
            &trace,
            &leaf_relation,
            LOG_SIZE,
            1, // multiplicity=1 for test
        );

        println!("Interaction trace columns: {}", interaction_trace.len());
        println!("Claimed sum: {:?}", claimed_sum);

        // Commit interaction trace
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(interaction_trace.clone());
        tree_builder.commit(prover_channel);

        // Create component
        let mut tree_span_provider = TraceLocationAllocator::new_with_preproccessed_columns(&[
            is_active_column_id(LOG_SIZE, "test"),
            is_step_column_id(LOG_SIZE, "test"),
            is_last_column_id(LOG_SIZE, "test"),
        ]);

        let component = PoseidonChainComponent::new(
            &mut tree_span_provider,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE, "test"),
                is_step_id: is_step_column_id(LOG_SIZE, "test"),
                is_last_id: is_last_column_id(LOG_SIZE, "test"),
                leaf_relation: leaf_relation.clone(),
                leaf_multiplicity: 1,
                claimed_sum, // Use actual claimed sum from interaction trace
            },
            claimed_sum, // Total claimed sum for component
        );

        let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
            &[&component],
            prover_channel,
            commitment_scheme,
        )
        .expect("Failed to generate proof");

        let verifier_channel = &mut Blake2sChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

        // Draw leaf relation again (verifier side)
        let leaf_relation_v = LeafRelation::draw(verifier_channel);

        // Commit preprocessed (3 columns: is_active, is_step, is_last)
        commitment_scheme_verifier.commit(
            proof.commitments[0],
            &[LOG_SIZE, LOG_SIZE, LOG_SIZE],
            verifier_channel,
        );

        // Commit base trace (666 columns with security fix, all at LOG_SIZE)
        // 16 initial + 192 first_half + 266 partial (with matrix) + 192 second_half
        let base_trace_bounds: Vec<u32> = vec![LOG_SIZE; 666];
        commitment_scheme_verifier.commit(
            proof.commitments[1],
            &base_trace_bounds,
            verifier_channel,
        );

        // Commit interaction trace
        // finalize_logup_in_pairs() creates 4 columns per relation pair
        commitment_scheme_verifier.commit(
            proof.commitments[2],
            &[LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE],
            verifier_channel,
        );

        // Create verifier component
        let mut tree_span_provider_verifier =
            TraceLocationAllocator::new_with_preproccessed_columns(&[
                is_active_column_id(LOG_SIZE, "test"),
                is_step_column_id(LOG_SIZE, "test"),
                is_last_column_id(LOG_SIZE, "test"),
            ]);

        let verifier_component = PoseidonChainComponent::new(
            &mut tree_span_provider_verifier,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE, "test"),
                is_step_id: is_step_column_id(LOG_SIZE, "test"),
                is_last_id: is_last_column_id(LOG_SIZE, "test"),
                leaf_relation: leaf_relation_v.clone(),
                leaf_multiplicity: 1,
                claimed_sum, // Use same claimed sum
            },
            claimed_sum, // Total claimed sum for component
        );

        // Verify (verify() will handle interaction column commitments internally)
        let result = verify(
            &[&verifier_component],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof,
        );

        match result {
            Ok(_) => {
                println!("\n✓✓✓ VERIFICATION SUCCESSFUL! ✓✓✓");
                println!("\nChain leaf hash: {}", outputs.leaf.0);
            }
            Err(e) => {
                panic!("Verification failed: {:?}", e);
            }
        }
    }
}
