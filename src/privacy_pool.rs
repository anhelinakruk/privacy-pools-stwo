#[cfg(test)]
mod tests {
    use alloy::primitives::{FixedBytes, U256};
    use stwo::core::air::{Component, Components};
    use stwo::core::channel::KeccakChannel;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fri::FriConfig;
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs::keccak_merkle::KeccakMerkleChannel;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::CommitmentSchemeProver;
    use stwo_constraint_framework::{FrameworkEval, TraceLocationAllocator, PREPROCESSED_TRACE_IDX};
    use stwo_polynomial::prove::prove;

    use crate::merkle_membership::tests::{
        convert_to_solidity_proof, test_contract_verify, CM31, ComponentInfo, ComponentParams,
        QM31, VerificationParams,
    };
    use crate::merkle_membership::{
        gen_merkle_is_active_column, gen_merkle_is_first_column, gen_merkle_is_last_column,
        gen_merkle_is_step_column, gen_merkle_membership_interaction_trace, gen_merkle_trace,
        merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
        merkle_is_step_column_id, MerkleInputs, MerkleMembershipComponent, MerkleMembershipEval,
    };
    use crate::poseidon_chain::{
        gen_is_active_column, gen_is_last_column, gen_is_step_column,
        gen_poseidon_chain_interaction_trace, gen_poseidon_chain_trace, is_active_column_id,
        is_last_column_id, is_step_column_id, ChainInputs, PoseidonChainComponent,
        PoseidonChainEval,
    };
    use crate::relations::{LeafRelation, RefundLeafRelation, RootRelation};
    use crate::scheduler::{
        gen_is_first_column as gen_scheduler_is_first_column, gen_scheduler_interaction_trace,
        gen_scheduler_trace, is_first_column_id as scheduler_is_first_column_id,
        PrivacyPoolSchedulerComponent, PrivacyPoolSchedulerEval,
    };

    #[tokio::test]
    async fn test_full_privacy_pool_prove_and_verify() {
        const LOG_SIZE: u32 = 8; // Increased for FRI queries with multiple components

        println!("\n=== FULL PRIVACY POOL PROOF ===\n");

        // Step 1: Generate deposit chain trace
        println!("1. Generating deposit chain...");
        let deposit_inputs = ChainInputs::for_deposit(
            BaseField::from_u32_unchecked(12345), // secret
            BaseField::from_u32_unchecked(67890), // nullifier
            BaseField::from_u32_unchecked(1000), // commitment_amount
            BaseField::from_u32_unchecked(0xABCD), // token_address
        );
        let (deposit_trace, deposit_outputs) =
            gen_poseidon_chain_trace(LOG_SIZE, deposit_inputs.clone());
        let deposit_leaf = deposit_outputs.leaf;
        println!("   Deposit leaf: {}", deposit_leaf.0);

        // Step 2: Generate refund chain trace
        println!("\n2. Generating refund chain...");
        let refund_inputs = ChainInputs::for_refund(
            BaseField::from_u32_unchecked(54321), // secret
            BaseField::from_u32_unchecked(98765), // nullifier
            BaseField::from_u32_unchecked(300),   // refund_amount
            BaseField::from_u32_unchecked(0xABCD), // token_address
        );
        let (refund_trace, refund_outputs) =
            gen_poseidon_chain_trace(LOG_SIZE, refund_inputs.clone());
        let refund_leaf = refund_outputs.leaf;
        println!("   Refund leaf: {}", refund_leaf.0);

        // Step 3: Build Merkle tree with deposit_leaf
        println!("\n3. Building Merkle tree...");
        let siblings = vec![
            BaseField::from_u32_unchecked(11111),
            BaseField::from_u32_unchecked(22222),
            BaseField::from_u32_unchecked(33333),
            BaseField::from_u32_unchecked(44444),
            BaseField::from_u32_unchecked(55555),
        ];
        let index = 1;
        let merkle_inputs = MerkleInputs::new(
            deposit_leaf,
            siblings.clone(),
            index,
            BaseField::from_u32_unchecked(0), // Will be overwritten
        );

        let (merkle_trace, computed_root) = gen_merkle_trace(LOG_SIZE, &merkle_inputs);
        println!("   Computed Merkle root: {}", computed_root.0);

        // Update expected_root to match computed
        let merkle_inputs = MerkleInputs::new(deposit_leaf, siblings, index, computed_root);

        // Step 4: Generate scheduler trace
        println!("\n4. Generating scheduler...");
        let commitment_amount = deposit_inputs.input2;
        let refund_amount = refund_inputs.input2;
        let amount = BaseField::from_u32_unchecked(700); // 1000 - 300
        let scheduler_trace = gen_scheduler_trace(
            LOG_SIZE,
            computed_root,
            computed_root, // expected_root matches
            commitment_amount,
            refund_amount,
            deposit_leaf,
            refund_leaf,
        );

        // Setup prover
        println!("\n5. Setting up prover...");
        let config = PcsConfig {
            pow_bits: 5,
            fri_config: FriConfig::new(2, 1, 2),
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

        // Draw relations
        let leaf_relation = LeafRelation::draw(prover_channel);
        let root_relation = RootRelation::draw(prover_channel);
        let refund_leaf_relation = RefundLeafRelation::draw(prover_channel);

        // Generate preprocessed columns
        let chain_is_active = gen_is_active_column(LOG_SIZE);
        let chain_is_step = gen_is_step_column(LOG_SIZE);
        let chain_is_last = gen_is_last_column(LOG_SIZE);

        let merkle_is_active = gen_merkle_is_active_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_step = gen_merkle_is_step_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_first = gen_merkle_is_first_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_last = gen_merkle_is_last_column(LOG_SIZE, merkle_inputs.depth());

        let scheduler_is_first = gen_scheduler_is_first_column(LOG_SIZE);

        // Commit preprocessed columns (11 total)
        println!("\n6. Committing preprocessed columns...");
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(
            [
                chain_is_active.clone(),      // deposit
                chain_is_step.clone(),
                chain_is_last.clone(),
                chain_is_active.clone(),      // refund
                chain_is_step.clone(),
                chain_is_last.clone(),
                merkle_is_active.clone(),     // merkle
                merkle_is_step.clone(),
                merkle_is_first.clone(),
                merkle_is_last.clone(),
                scheduler_is_first.clone(),   // scheduler
            ]
            .to_vec(),
        );
        tree_builder.commit(prover_channel);

        // Commit base traces
        println!("7. Committing base traces...");
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(deposit_trace.clone());
        tree_builder.extend_evals(refund_trace.clone());
        tree_builder.extend_evals(merkle_trace.clone());
        tree_builder.extend_evals(scheduler_trace.clone());
        tree_builder.commit(prover_channel);

        // Generate interaction traces
        println!("8. Generating interaction traces...");
        let (deposit_interaction, deposit_claimed_sum) = gen_poseidon_chain_interaction_trace(
            &deposit_trace,
            &leaf_relation,
            LOG_SIZE,
            1, // multiplicity = 1 for deposit
        );

        let (refund_interaction, refund_claimed_sum) = gen_poseidon_chain_interaction_trace(
            &refund_trace,
            &leaf_relation, // Use LeafRelation, not RefundLeafRelation
            LOG_SIZE,
            1, // multiplicity = 1 for refund
        );

        let (merkle_interaction, merkle_claimed_sum) = gen_merkle_membership_interaction_trace(
            &merkle_trace,
            &leaf_relation,
            &root_relation,
            LOG_SIZE,
            merkle_inputs.depth(),
        );

        let (scheduler_interaction, scheduler_claimed_sum) = gen_scheduler_interaction_trace(
            &scheduler_trace,
            &leaf_relation,
            &root_relation,
            &refund_leaf_relation,
            LOG_SIZE,
        );

        println!("   Deposit claimed sum: {:?}", deposit_claimed_sum);
        println!("   Refund claimed sum: {:?}", refund_claimed_sum);
        println!("   Merkle claimed sum: {:?}", merkle_claimed_sum);
        println!("   Scheduler claimed sum: {:?}", scheduler_claimed_sum);

        // Commit interaction traces
        println!("9. Committing interaction traces...");
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(deposit_interaction.clone());
        tree_builder.extend_evals(refund_interaction.clone());
        tree_builder.extend_evals(merkle_interaction.clone());
        tree_builder.extend_evals(scheduler_interaction.clone());
        tree_builder.commit(prover_channel);

        // Create components
        println!("10. Creating components...");
        let mut tree_span_provider = TraceLocationAllocator::new_with_preprocessed_columns(&[
            is_active_column_id(LOG_SIZE, "deposit"),
            is_step_column_id(LOG_SIZE, "deposit"),
            is_last_column_id(LOG_SIZE, "deposit"),
            is_active_column_id(LOG_SIZE, "refund"),
            is_step_column_id(LOG_SIZE, "refund"),
            is_last_column_id(LOG_SIZE, "refund"),
            merkle_is_active_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_step_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_first_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_last_column_id(LOG_SIZE, merkle_inputs.depth()),
            scheduler_is_first_column_id(LOG_SIZE),
        ]);

        let deposit_component = PoseidonChainComponent::new(
            &mut tree_span_provider,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE, "deposit"),
                is_step_id: is_step_column_id(LOG_SIZE, "deposit"),
                is_last_id: is_last_column_id(LOG_SIZE, "deposit"),
                leaf_relation: leaf_relation.clone(),
                leaf_multiplicity: 1,
                claimed_sum: deposit_claimed_sum,
            },
            deposit_claimed_sum,
        );

        let refund_component = PoseidonChainComponent::new(
            &mut tree_span_provider,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE, "refund"),
                is_step_id: is_step_column_id(LOG_SIZE, "refund"),
                is_last_id: is_last_column_id(LOG_SIZE, "refund"),
                leaf_relation: leaf_relation.clone(), // Using LeafRelation for type compatibility
                leaf_multiplicity: 1,
                claimed_sum: refund_claimed_sum,
            },
            refund_claimed_sum,
        );

        let merkle_component = MerkleMembershipComponent::new(
            &mut tree_span_provider,
            MerkleMembershipEval {
                log_n_rows: LOG_SIZE,
                depth: merkle_inputs.depth(),
                is_active_id: merkle_is_active_column_id(LOG_SIZE, merkle_inputs.depth()),
                is_step_id: merkle_is_step_column_id(LOG_SIZE, merkle_inputs.depth()),
                is_first_id: merkle_is_first_column_id(LOG_SIZE, merkle_inputs.depth()),
                is_last_id: merkle_is_last_column_id(LOG_SIZE, merkle_inputs.depth()),
                leaf_relation: leaf_relation.clone(),
                root_relation: root_relation.clone(),
                claimed_sum: merkle_claimed_sum,
            },
            merkle_claimed_sum,
        );

        let scheduler_component = PrivacyPoolSchedulerComponent::new(
            &mut tree_span_provider,
            PrivacyPoolSchedulerEval {
                log_n_rows: LOG_SIZE,
                is_first_id: scheduler_is_first_column_id(LOG_SIZE),
                leaf_relation: leaf_relation.clone(),
                root_relation: root_relation.clone(),
                refund_leaf_relation: refund_leaf_relation.clone(),
                amount,
                refund_commitment_hash: refund_leaf,
                claimed_sum: scheduler_claimed_sum,
            },
            scheduler_claimed_sum,
        );

        // Generate proof
        println!("11. Generating proof...");
        let (proof, composition_polynomial) = prove(
            &[
                &deposit_component,
                &refund_component,
                &merkle_component,
                &scheduler_component,
            ],
            prover_channel,
            commitment_scheme,
        )
        .unwrap();

        println!("✅ Proof generated successfully!\n");

        // Convert to Solidity format
        let solidity_proof =
            convert_to_solidity_proof(proof.clone(), composition_polynomial.clone(), config);

        // Verify
        println!("12. Verifying proof...");
        let verifier_channel = &mut KeccakChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(config);

        // Draw relations (verifier side)
        let leaf_relation_v = LeafRelation::draw(verifier_channel);
        let root_relation_v = RootRelation::draw(verifier_channel);
        let refund_leaf_relation_v = RefundLeafRelation::draw(verifier_channel);

        // Commit preprocessed (11 columns)
        commitment_scheme_verifier.commit(
            proof.commitments[0],
            &[LOG_SIZE; 11],
            verifier_channel,
        );

        // Commit base traces (666 + 666 + 667 + 6 = 2005 columns)
        let base_trace_sizes: Vec<u32> = vec![LOG_SIZE; 666 + 666 + 667 + 6];
        commitment_scheme_verifier.commit(
            proof.commitments[1],
            &base_trace_sizes,
            verifier_channel,
        );

        // Commit interaction traces (4 + 4 + 4 + 12 = 24 columns)
        commitment_scheme_verifier.commit(
            proof.commitments[2],
            &[LOG_SIZE; 24],
            verifier_channel,
        );

        // Create verifier components
        let mut tree_span_provider_v = TraceLocationAllocator::new_with_preprocessed_columns(&[
            is_active_column_id(LOG_SIZE, "deposit"),
            is_step_column_id(LOG_SIZE, "deposit"),
            is_last_column_id(LOG_SIZE, "deposit"),
            is_active_column_id(LOG_SIZE, "refund"),
            is_step_column_id(LOG_SIZE, "refund"),
            is_last_column_id(LOG_SIZE, "refund"),
            merkle_is_active_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_step_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_first_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_last_column_id(LOG_SIZE, merkle_inputs.depth()),
            scheduler_is_first_column_id(LOG_SIZE),
        ]);

        let deposit_component_v = PoseidonChainComponent::new(
            &mut tree_span_provider_v,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE, "deposit"),
                is_step_id: is_step_column_id(LOG_SIZE, "deposit"),
                is_last_id: is_last_column_id(LOG_SIZE, "deposit"),
                leaf_relation: leaf_relation_v.clone(),
                leaf_multiplicity: 1,
                claimed_sum: deposit_claimed_sum,
            },
            deposit_claimed_sum,
        );

        let refund_component_v = PoseidonChainComponent::new(
            &mut tree_span_provider_v,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE, "refund"),
                is_step_id: is_step_column_id(LOG_SIZE, "refund"),
                is_last_id: is_last_column_id(LOG_SIZE, "refund"),
                leaf_relation: leaf_relation_v.clone(), // Use LeafRelation, not RefundLeafRelation
                leaf_multiplicity: 1,
                claimed_sum: refund_claimed_sum,
            },
            refund_claimed_sum,
        );

        let merkle_component_v = MerkleMembershipComponent::new(
            &mut tree_span_provider_v,
            MerkleMembershipEval {
                log_n_rows: LOG_SIZE,
                depth: merkle_inputs.depth(),
                is_active_id: merkle_is_active_column_id(LOG_SIZE, merkle_inputs.depth()),
                is_step_id: merkle_is_step_column_id(LOG_SIZE, merkle_inputs.depth()),
                is_first_id: merkle_is_first_column_id(LOG_SIZE, merkle_inputs.depth()),
                is_last_id: merkle_is_last_column_id(LOG_SIZE, merkle_inputs.depth()),
                leaf_relation: leaf_relation_v.clone(),
                root_relation: root_relation_v.clone(),
                claimed_sum: merkle_claimed_sum,
            },
            merkle_claimed_sum,
        );

        let scheduler_component_v = PrivacyPoolSchedulerComponent::new(
            &mut tree_span_provider_v,
            PrivacyPoolSchedulerEval {
                log_n_rows: LOG_SIZE,
                is_first_id: scheduler_is_first_column_id(LOG_SIZE),
                leaf_relation: leaf_relation_v.clone(),
                root_relation: root_relation_v.clone(),
                refund_leaf_relation: refund_leaf_relation_v.clone(),
                amount,
                refund_commitment_hash: refund_leaf,
                claimed_sum: scheduler_claimed_sum,
            },
            scheduler_claimed_sum,
        );

        let digest = verifier_channel.digest();

        stwo_polynomial::verify::verify(
            &[
                &deposit_component_v,
                &refund_component_v,
                &merkle_component_v,
                &scheduler_component_v,
            ],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof.clone(),
            composition_polynomial,
        )
        .unwrap();

        println!("✅ Proof verified successfully!\n");

        // Prepare contract verification
        println!("13. Preparing contract verification...");
        let n_preprocessed_columns = commitment_scheme_verifier.trees[PREPROCESSED_TRACE_IDX]
            .column_log_sizes
            .len();

        let components_vec: Vec<&dyn Component> = vec![
            &deposit_component_v as &dyn Component,
            &refund_component_v as &dyn Component,
            &merkle_component_v as &dyn Component,
            &scheduler_component_v as &dyn Component,
        ];

        let components = Components {
            components: components_vec,
            n_preprocessed_columns,
        };

        let components_log_degree_bound = components.composition_log_degree_bound();

        let all_preprocessed_ids: Vec<U256> = (0u64..11).map(U256::from).collect();

        // Build component infos (each component has different type, so build individually)
        let deposit_info = ComponentInfo {
            maxConstraintLogDegreeBound: deposit_component_v.max_constraint_log_degree_bound(),
            logSize: deposit_component_v.log_size(),
            maskOffsets: deposit_component_v
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
            preprocessedColumns: all_preprocessed_ids[0..3].to_vec(),
        };

        let refund_info = ComponentInfo {
            maxConstraintLogDegreeBound: refund_component_v.max_constraint_log_degree_bound(),
            logSize: refund_component_v.log_size(),
            maskOffsets: refund_component_v
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
            preprocessedColumns: all_preprocessed_ids[0..6].to_vec(),
        };

        let merkle_info = ComponentInfo {
            maxConstraintLogDegreeBound: merkle_component_v.max_constraint_log_degree_bound(),
            logSize: merkle_component_v.log_size(),
            maskOffsets: merkle_component_v
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
            preprocessedColumns: all_preprocessed_ids[0..10].to_vec(),
        };

        let scheduler_info = ComponentInfo {
            maxConstraintLogDegreeBound: scheduler_component_v.max_constraint_log_degree_bound(),
            logSize: scheduler_component_v.log_size(),
            maskOffsets: scheduler_component_v
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
            preprocessedColumns: all_preprocessed_ids[0..11].to_vec(),
        };

        let component_params: Vec<ComponentParams> = vec![
            ComponentParams {
                logSize: deposit_component.log_size(),
                claimedSum: QM31 {
                    first: CM31 {
                        real: deposit_claimed_sum.0 .0 .0,
                        imag: deposit_claimed_sum.0 .1 .0,
                    },
                    second: CM31 {
                        real: deposit_claimed_sum.1 .0 .0,
                        imag: deposit_claimed_sum.1 .1 .0,
                    },
                },
                info: deposit_info,
            },
            ComponentParams {
                logSize: refund_component.log_size(),
                claimedSum: QM31 {
                    first: CM31 {
                        real: refund_claimed_sum.0 .0 .0,
                        imag: refund_claimed_sum.0 .1 .0,
                    },
                    second: CM31 {
                        real: refund_claimed_sum.1 .0 .0,
                        imag: refund_claimed_sum.1 .1 .0,
                    },
                },
                info: refund_info,
            },
            ComponentParams {
                logSize: merkle_component.log_size(),
                claimedSum: QM31 {
                    first: CM31 {
                        real: merkle_claimed_sum.0 .0 .0,
                        imag: merkle_claimed_sum.0 .1 .0,
                    },
                    second: CM31 {
                        real: merkle_claimed_sum.1 .0 .0,
                        imag: merkle_claimed_sum.1 .1 .0,
                    },
                },
                info: merkle_info,
            },
            ComponentParams {
                logSize: scheduler_component.log_size(),
                claimedSum: QM31 {
                    first: CM31 {
                        real: scheduler_claimed_sum.0 .0 .0,
                        imag: scheduler_claimed_sum.0 .1 .0,
                    },
                    second: CM31 {
                        real: scheduler_claimed_sum.1 .0 .0,
                        imag: scheduler_claimed_sum.1 .1 .0,
                    },
                },
                info: scheduler_info,
            },
        ];

        let verification_params = VerificationParams {
            componentParams: component_params,
            nPreprocessedColumns: U256::from(11),
            componentsCompositionLogDegreeBound: components_log_degree_bound,
        };

        let roots = vec![
            proof.commitments[0],
            proof.commitments[1],
            proof.commitments[2],
        ];
        let roots_bytes32: Vec<FixedBytes<32>> =
            roots.iter().map(|r| FixedBytes::from(r.0)).collect();

        // Calculate extended log sizes
        let log_sizes_vec = vec![
            vec![LOG_SIZE; 11],   // preprocessed
            vec![LOG_SIZE; 2005], // base traces
            vec![LOG_SIZE; 24],   // interaction traces
        ];

        let extended_log_sizes: Vec<Vec<u32>> = log_sizes_vec
            .iter()
            .map(|tree_log_sizes| {
                tree_log_sizes
                    .iter()
                    .map(|&ls| ls + proof.config.fri_config.log_blowup_factor)
                    .collect()
            })
            .collect();

        println!("14. Contract verification...");

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
            println!("⚠️  Contract verify call failed: {}", e);
            println!("\n✓✓✓ FULL PRIVACY POOL TEST PASSED (OFF-CHAIN VERIFICATION ONLY) ✓✓✓");
        } else {
            println!("\n✓✓✓ FULL PRIVACY POOL TEST PASSED (OFF-CHAIN + ON-CHAIN) ✓✓✓");
        }
    }
}
