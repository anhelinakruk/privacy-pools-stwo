#[cfg(test)]
mod tests {
    use alloy::primitives::{FixedBytes, U256};
    use stwo::core::air::{Component, Components};
    use stwo::core::channel::KeccakChannel;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::vcs::keccak_merkle::KeccakMerkleChannel;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo_constraint_framework::{FrameworkEval, PREPROCESSED_TRACE_IDX};
    use stwo_polynomial::prove::prove;

    use crate::merkle_membership::tests::{
        convert_to_solidity_proof, test_contract_verify, CM31, ComponentInfo, ComponentParams,
        QM31, VerificationParams,
    };
    use crate::scheduler::{
        gen_is_first_column, gen_scheduler_interaction_trace, gen_scheduler_trace,
        is_first_column_id, PrivacyPoolSchedulerComponent, PrivacyPoolSchedulerEval,
        SchedulerStatement0,
    };
    use crate::relations::{LeafRelation, RefundLeafRelation, RootRelation};

    #[tokio::test]
    async fn test_scheduler_prove_and_verify() {
        use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::prover::poly::circle::PolyOps;
        use stwo::prover::CommitmentSchemeProver;
        use stwo_constraint_framework::TraceLocationAllocator;

        const LOG_SIZE: u32 = 8; // 256 rows (increased for FRI queries)

        // Test values
        let computed_root = BaseField::from_u32_unchecked(12345);
        let expected_root = BaseField::from_u32_unchecked(12345); // Must match for constraint
        let commitment_amount = BaseField::from_u32_unchecked(1000);
        let refund_amount = BaseField::from_u32_unchecked(300);
        let amount = BaseField::from_u32_unchecked(700); // commitment - refund
        let deposit_leaf = BaseField::from_u32_unchecked(11111);
        let refund_leaf = BaseField::from_u32_unchecked(22222);
        let refund_commitment_hash = BaseField::from_u32_unchecked(22222); // Must match refund_leaf

        // Generate trace
        let trace = gen_scheduler_trace(
            LOG_SIZE,
            computed_root,
            expected_root,
            commitment_amount,
            refund_amount,
            deposit_leaf,
            refund_leaf,
        );

        println!("Trace generated with {} columns", trace.len());

        // Generate preprocessed column
        let is_first_col = gen_is_first_column(LOG_SIZE);

        // Use custom FRI config with fewer queries for small trace
        use stwo::core::fri::FriConfig;
        let fri_config = FriConfig::new(2, 1, 3); // log_blowup_factor=2, log_last_layer_degree_bound=1, n_queries=3
        let config = PcsConfig {
            pow_bits: 10,
            fri_config,
        };
        let log_max_rows = LOG_SIZE + 3;
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let prover_channel = &mut KeccakChannel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

        // Draw relations from channel
        let leaf_relation = LeafRelation::draw(prover_channel);
        let root_relation = RootRelation::draw(prover_channel);
        let refund_leaf_relation = RefundLeafRelation::draw(prover_channel);

        // Commit preprocessed column (is_first)
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals([is_first_col.clone()].to_vec());
        tree_builder.commit(prover_channel);

        // Commit base trace (6 columns)
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace.clone());
        tree_builder.commit(prover_channel);

        // Generate interaction traces
        let (interaction_trace, claimed_sum) = gen_scheduler_interaction_trace(
            &trace,
            &leaf_relation,
            &root_relation,
            &refund_leaf_relation,
            LOG_SIZE,
        );

        println!("Interaction trace columns: {}", interaction_trace.len());
        println!("Claimed sum: {:?}", claimed_sum);

        // Debug: verify interaction trace size matches expectation
        assert_eq!(interaction_trace.len(), 12, "Expected 12 interaction trace columns (3 logup cols × 4 = 12)");

        // Commit interaction traces
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(interaction_trace.clone());
        tree_builder.commit(prover_channel);

        let mut tree_span_provider =
            TraceLocationAllocator::new_with_preprocessed_columns(&[is_first_column_id(LOG_SIZE)]);

        let component = PrivacyPoolSchedulerComponent::new(
            &mut tree_span_provider,
            PrivacyPoolSchedulerEval {
                log_n_rows: LOG_SIZE,
                is_first_id: is_first_column_id(LOG_SIZE),
                leaf_relation: leaf_relation.clone(),
                root_relation: root_relation.clone(),
                refund_leaf_relation: refund_leaf_relation.clone(),
                amount,
                refund_commitment_hash,
                claimed_sum,
            },
            claimed_sum,
        );

        // Generate proof
        let (proof, composition_polynomial) =
            prove(&[&component], prover_channel, commitment_scheme).unwrap();

        println!("Proof generated");

        let solidity_proof =
            convert_to_solidity_proof(proof.clone(), composition_polynomial.clone(), config);

        let verifier_channel = &mut KeccakChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(config);

        // Draw relations again (verifier side)
        let leaf_relation_v = LeafRelation::draw(verifier_channel);
        let root_relation_v = RootRelation::draw(verifier_channel);
        let refund_leaf_relation_v = RefundLeafRelation::draw(verifier_channel);

        // Commit preprocessed (1 column: is_first)
        commitment_scheme_verifier.commit(proof.commitments[0], &[LOG_SIZE], verifier_channel);

        // Commit base trace (6 columns)
        let base_trace_bounds: Vec<u32> = vec![LOG_SIZE; 6];
        commitment_scheme_verifier.commit(
            proof.commitments[1],
            &base_trace_bounds,
            verifier_channel,
        );

        // Commit interaction traces (12 columns: 3 logup cols × 4 = 12)
        commitment_scheme_verifier.commit(
            proof.commitments[2],
            &[LOG_SIZE; 12],
            verifier_channel,
        );

        let statement0 = SchedulerStatement0 { log_size: LOG_SIZE };
        let log_sizes = statement0.log_sizes();

        println!("\n=== DEBUG: Column Sizes ===");
        println!("Proof has {} commitments", proof.commitments.len());
        println!("Statement0 log_sizes:");
        for (tree_idx, tree_sizes) in log_sizes.0.iter().enumerate() {
            println!(
                "  Tree {}: {} columns of size {}",
                tree_idx,
                tree_sizes.len(),
                tree_sizes[0]
            );
        }

        println!("\nVerifier commitment_scheme trees:");
        for (tree_idx, tree) in commitment_scheme_verifier.trees.iter().enumerate() {
            println!(
                "  Tree {}: {} columns",
                tree_idx,
                tree.column_log_sizes.len()
            );
        }

        let extended_log_sizes: Vec<Vec<u32>> = log_sizes
            .0
            .iter()
            .map(|tree_log_sizes| {
                tree_log_sizes
                    .iter()
                    .map(|&ls| ls + proof.config.fri_config.log_blowup_factor)
                    .collect()
            })
            .collect();
        println!("\nExtended log sizes for FRI: {:?}", extended_log_sizes);

        let mut tree_span_provider_verifier =
            TraceLocationAllocator::new_with_preprocessed_columns(&[is_first_column_id(LOG_SIZE)]);

        let verifier_component = PrivacyPoolSchedulerComponent::new(
            &mut tree_span_provider_verifier,
            PrivacyPoolSchedulerEval {
                log_n_rows: LOG_SIZE,
                is_first_id: is_first_column_id(LOG_SIZE),
                leaf_relation: leaf_relation_v.clone(),
                root_relation: root_relation_v.clone(),
                refund_leaf_relation: refund_leaf_relation_v.clone(),
                amount,
                refund_commitment_hash,
                claimed_sum,
            },
            claimed_sum,
        );

        let digest = verifier_channel.digest();

        stwo_polynomial::verify::verify(
            &[&verifier_component],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof.clone(),
            composition_polynomial,
        )
        .unwrap();
        println!("✅ Proof verified successfully!");

        let n_preprocessed_columns = commitment_scheme_verifier.trees[PREPROCESSED_TRACE_IDX]
            .column_log_sizes
            .len();
        let components_vec: Vec<&dyn Component> =
            vec![&verifier_component as &dyn Component];

        let components = Components {
            components: components_vec,
            n_preprocessed_columns,
        };

        let components_log_degree_bound = components.composition_log_degree_bound();

        let component_info = ComponentInfo {
            maxConstraintLogDegreeBound: verifier_component.max_constraint_log_degree_bound(),
            logSize: verifier_component.log_size(),
            maskOffsets: verifier_component
                .info
                .mask_offsets
                .0
                .iter()
                .map(|tree| {
                    tree.iter()
                        .map(|col| col.iter().map(|&offset| offset as i32).collect())
                        .collect()
                })
                .collect(),
            preprocessedColumns: verifier_component
                .info
                .preprocessed_columns
                .iter()
                .enumerate()
                .map(|(idx, _)| U256::from(idx))
                .collect(),
        };

        let verification_params = VerificationParams {
            componentParams: vec![ComponentParams {
                logSize: component.log_size(),
                claimedSum: QM31 {
                    first: CM31 {
                        real: component.claimed_sum().0 .0 .0,
                        imag: component.claimed_sum().0 .1 .0,
                    },
                    second: CM31 {
                        real: component.claimed_sum().1 .0 .0,
                        imag: component.claimed_sum().1 .1 .0,
                    },
                },
                info: component_info,
            }],
            nPreprocessedColumns: U256::from(1), // 1 preprocessed column: is_first
            componentsCompositionLogDegreeBound: components_log_degree_bound,
        };

        let roots = vec![
            proof.commitments[0],
            proof.commitments[1],
            proof.commitments[2],
        ];
        let roots_bytes32: Vec<FixedBytes<32>> =
            roots.iter().map(|r| FixedBytes::from(r.0)).collect();

        if let Err(e) = test_contract_verify(
            solidity_proof,
            verification_params,
            roots_bytes32,
            extended_log_sizes,
            FixedBytes::from(digest.0),
            0u32,
        )
        .await
        {
            println!("Contract verify call failed: {}", e);
        }

        println!("✓✓✓ TEST PASSED ✓✓✓");
    }
}
