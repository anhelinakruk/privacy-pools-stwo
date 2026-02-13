#[cfg(test)]
mod tests {
    use stwo_prover::constraint_framework::TraceLocationAllocator;
    use stwo_prover::core::backend::simd::SimdBackend;
    use stwo_prover::core::channel::Blake2sChannel;
    use stwo_prover::core::fields::m31::BaseField;
    use stwo_prover::core::pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig};
    use stwo_prover::core::poly::circle::{CanonicCoset, PolyOps};
    use stwo_prover::core::prover::{prove, verify};
    use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel;

    use crate::merkle_membership::{
        gen_merkle_is_active_column, gen_merkle_is_first_column, gen_merkle_is_last_column,
        gen_merkle_is_step_column, gen_merkle_membership_interaction_trace, gen_merkle_trace,
        merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
        merkle_is_step_column_id, MerkleInputs, MerkleMembershipComponent, MerkleMembershipEval,
    };
    use crate::relations::{LeafRelation, RootRelation};

    #[test]
    fn test_merkle_prove_and_verify() {

        let leaf = BaseField::from_u32_unchecked(12345);
        // Use depth=5 for better testing (more rows)
        let siblings = vec![
            BaseField::from_u32_unchecked(11111),
            BaseField::from_u32_unchecked(22222),
            BaseField::from_u32_unchecked(33333),
            BaseField::from_u32_unchecked(44444),
            BaseField::from_u32_unchecked(55555),
        ];
        let index = 1;
        let expected_root = BaseField::from_u32_unchecked(0);

        let inputs = MerkleInputs::new(leaf, siblings.clone(), index, expected_root);
        const LOG_SIZE: u32 = 5; // 32 rows

        println!("Input:");
        println!("  Leaf: {}", leaf.0);
        println!("  Index: {} (binary: {:03b})", index, index);
        println!(
            "  Siblings: {:?}",
            siblings.iter().map(|s| s.0).collect::<Vec<_>>()
        );
        println!("  Depth: {}", inputs.depth());

        let (trace, computed_root) = gen_merkle_trace(LOG_SIZE, &inputs);
        println!("  Computed root: {}", computed_root.0);

        let is_active_col = gen_merkle_is_active_column(LOG_SIZE, inputs.depth());
        let is_step_col = gen_merkle_is_step_column(LOG_SIZE, inputs.depth());
        let is_first_col = gen_merkle_is_first_column(LOG_SIZE, inputs.depth());
        let is_last_col = gen_merkle_is_last_column(LOG_SIZE, inputs.depth());

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

        // Draw relations from channel
        let leaf_relation = LeafRelation::draw(prover_channel);
        let root_relation = RootRelation::draw(prover_channel);

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(
            [
                is_active_col.clone(),
                is_step_col.clone(),
                is_first_col.clone(),
                is_last_col.clone(),
            ]
            .to_vec(),
        );
        tree_builder.commit(prover_channel);

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace.clone());
        tree_builder.commit(prover_channel);

        // Generate interaction traces for LogUp (leaf consumption + root yielding combined)
        let (interaction_trace, claimed_sum) = gen_merkle_membership_interaction_trace(
            &trace,
            &leaf_relation,
            &root_relation,
            LOG_SIZE,
            inputs.depth(),
        );

        println!("Interaction trace columns: {}", interaction_trace.len());
        println!("Claimed sum: {:?}", claimed_sum);

        // Commit interaction traces
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(interaction_trace.clone());
        tree_builder.commit(prover_channel);

        let mut tree_span_provider = TraceLocationAllocator::new_with_preproccessed_columns(&[
            merkle_is_active_column_id(LOG_SIZE, inputs.depth()),
            merkle_is_step_column_id(LOG_SIZE, inputs.depth()),
            merkle_is_first_column_id(LOG_SIZE, inputs.depth()),
            merkle_is_last_column_id(LOG_SIZE, inputs.depth()),
        ]);
        let component = MerkleMembershipComponent::new(
            &mut tree_span_provider,
            MerkleMembershipEval {
                log_n_rows: LOG_SIZE,
                depth: inputs.depth(),
                is_active_id: merkle_is_active_column_id(LOG_SIZE, inputs.depth()),
                is_step_id: merkle_is_step_column_id(LOG_SIZE, inputs.depth()),
                is_first_id: merkle_is_first_column_id(LOG_SIZE, inputs.depth()),
                is_last_id: merkle_is_last_column_id(LOG_SIZE, inputs.depth()),
                leaf_relation: leaf_relation.clone(),
                root_relation: root_relation.clone(),
                claimed_sum, // Use combined claimed sum
            },
            claimed_sum, // Total claimed sum for component
        );

        let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
            &[&component],
            prover_channel,
            commitment_scheme,
        )
        .expect("Failed to generate proof");

        println!("Proof generated");

        let verifier_channel = &mut Blake2sChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

        // Draw relations again (verifier side)
        let leaf_relation_v = LeafRelation::draw(verifier_channel);
        let root_relation_v = RootRelation::draw(verifier_channel);

        // Commit preprocessed (4 columns: is_active, is_step, is_first, is_last)
        commitment_scheme_verifier.commit(
            proof.commitments[0],
            &[LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE],
            verifier_channel,
        );

        // 667 columns with security fix: 1 (index_bit) + 666 (Poseidon Cairo-m style)
        // 16 initial + 192 first_half + 266 partial (with matrix) + 192 second_half
        let base_trace_bounds: Vec<u32> = vec![LOG_SIZE; 667];
        commitment_scheme_verifier.commit(
            proof.commitments[1],
            &base_trace_bounds,
            verifier_channel,
        );

        // Commit interaction traces
        // finalize_logup_in_pairs() creates 4 columns
        // Both relations are combined into a single column generator
        commitment_scheme_verifier.commit(
            proof.commitments[2],
            &[LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE],
            verifier_channel,
        );

        let mut tree_span_provider_verifier =
            TraceLocationAllocator::new_with_preproccessed_columns(&[
                merkle_is_active_column_id(LOG_SIZE, inputs.depth()),
                merkle_is_step_column_id(LOG_SIZE, inputs.depth()),
                merkle_is_first_column_id(LOG_SIZE, inputs.depth()),
                merkle_is_last_column_id(LOG_SIZE, inputs.depth()),
            ]);
        let verifier_component = MerkleMembershipComponent::new(
            &mut tree_span_provider_verifier,
            MerkleMembershipEval {
                log_n_rows: LOG_SIZE,
                depth: inputs.depth(),
                is_active_id: merkle_is_active_column_id(LOG_SIZE, inputs.depth()),
                is_step_id: merkle_is_step_column_id(LOG_SIZE, inputs.depth()),
                is_first_id: merkle_is_first_column_id(LOG_SIZE, inputs.depth()),
                is_last_id: merkle_is_last_column_id(LOG_SIZE, inputs.depth()),
                leaf_relation: leaf_relation_v.clone(),
                root_relation: root_relation_v.clone(),
                claimed_sum, // Use same claimed sum
            },
            claimed_sum, // Total claimed sum for component
        );

        let result = verify(
            &[&verifier_component],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof,
        );

        match result {
            Ok(_) => {
                println!("Verification succeeded!");
                println!("Computed root: {}", computed_root.0);
            }
            Err(e) => {
                panic!("Verification failed: {:?}", e);
            }
        }
    }
}
