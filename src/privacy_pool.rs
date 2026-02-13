#[cfg(test)]
mod tests {
    use stwo_polynomial::prove::prove;
    use stwo_polynomial::verify::verify_with_queries;
    use stwo_prover::constraint_framework::TraceLocationAllocator;
    use stwo_prover::core::backend::simd::SimdBackend;
    use stwo_prover::core::channel::Blake2sChannel;
    use stwo_prover::core::fields::m31::BaseField;
    use stwo_prover::core::pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, PcsConfig};
    use stwo_prover::core::poly::circle::{CanonicCoset, PolyOps};
    use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel;

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
        PrivacyPoolSchedulerComponent, PrivacyPoolSchedulerEval, SchedulerStatement,
    };

    #[test]
    fn test_privacy_pool_combined() {
        const LOG_SIZE: u32 = 5;

        let deposit_inputs = ChainInputs::for_deposit(
            BaseField::from_u32_unchecked(12345),
            BaseField::from_u32_unchecked(67890),
            BaseField::from_u32_unchecked(100),
            BaseField::from_u32_unchecked(0xABCD),
        );
        let (deposit_trace, deposit_outputs) =
            gen_poseidon_chain_trace(LOG_SIZE, deposit_inputs.clone());
        println!("Deposit leaf: {}\n", deposit_outputs.leaf.0);

        let refund_inputs = ChainInputs::for_refund(
            BaseField::from_u32_unchecked(54321),
            BaseField::from_u32_unchecked(98765),
            BaseField::from_u32_unchecked(40),
            BaseField::from_u32_unchecked(0xABCD),
        );
        let (refund_trace, refund_outputs) =
            gen_poseidon_chain_trace(LOG_SIZE, refund_inputs.clone());
        println!("Refund leaf: {}\n", refund_outputs.leaf.0);

        // Public inputs
        let nullifier = BaseField::from_u32_unchecked(67890);
        let token_address = BaseField::from_u32_unchecked(0xABCD);
        let amount = BaseField::from_u32_unchecked(60); // withdrawal amount = 100 - 40
        let refund_commitment_hash = refund_outputs.leaf;
        let recipient = BaseField::from_u32_unchecked(0xDEADBEEF);

        // First, compute the Merkle root
        let merkle_inputs_temp = MerkleInputs {
            leaf: deposit_outputs.leaf,
            index: 1,
            siblings: vec![
                BaseField::from_u32_unchecked(11111),
                BaseField::from_u32_unchecked(22222),
                BaseField::from_u32_unchecked(33333),
                BaseField::from_u32_unchecked(44444),
                BaseField::from_u32_unchecked(55555),
            ],
            expected_root: BaseField::from_u32_unchecked(0), // Placeholder
        };
        let (merkle_trace, computed_root) = gen_merkle_trace(LOG_SIZE, &merkle_inputs_temp);
        println!(" Computed root: {}\n", computed_root.0);

        let merkle_inputs = MerkleInputs {
            expected_root: computed_root,
            ..merkle_inputs_temp
        };

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
        // commitment_scheme.set_store_polynomials_coefficients();

        // Mix public statement into Fiat-Shamir channel BEFORE drawing relations
        let scheduler_statement = SchedulerStatement::new(
            merkle_inputs.expected_root,
            merkle_inputs.depth() as u32,
            nullifier,
            token_address,
            amount,
            refund_commitment_hash,
            recipient,
        );
        scheduler_statement.mix_into(prover_channel);

        let leaf_relation = LeafRelation::draw(prover_channel);
        let root_relation = RootRelation::draw(prover_channel);
        let refund_leaf_relation = crate::relations::RefundLeafRelation::draw(prover_channel);

        let chain_is_active = gen_is_active_column(LOG_SIZE);
        let chain_is_step = gen_is_step_column(LOG_SIZE);
        let chain_is_last = gen_is_last_column(LOG_SIZE);

        let merkle_is_active = gen_merkle_is_active_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_step = gen_merkle_is_step_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_first = gen_merkle_is_first_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_last = gen_merkle_is_last_column(LOG_SIZE, merkle_inputs.depth());

        let scheduler_is_first = gen_scheduler_is_first_column(LOG_SIZE);

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(
            [
                chain_is_active.clone(),
                chain_is_step.clone(),
                chain_is_last.clone(),
                chain_is_active.clone(),
                chain_is_step.clone(),
                chain_is_last.clone(),
                merkle_is_active.clone(),
                merkle_is_step.clone(),
                merkle_is_first.clone(),
                merkle_is_last.clone(),
                scheduler_is_first.clone(),
            ]
            .to_vec(),
        );
        tree_builder.commit(prover_channel);

        let expected_root = merkle_inputs.expected_root;
        let commitment_amount = deposit_inputs.input2;
        let refund_amount = refund_inputs.input2;
        let scheduler_trace = gen_scheduler_trace(
            LOG_SIZE,
            computed_root,
            expected_root,
            commitment_amount,
            refund_amount,
            deposit_outputs.leaf,
            refund_outputs.leaf,
        );

        // Commit base traces (deposit + refund + merkle + scheduler)
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(deposit_trace.clone());
        tree_builder.extend_evals(refund_trace.clone());
        tree_builder.extend_evals(merkle_trace.clone());
        tree_builder.extend_evals(scheduler_trace.clone());
        tree_builder.commit(prover_channel);

        let (deposit_interaction_trace, deposit_claimed_sum) =
            gen_poseidon_chain_interaction_trace(&deposit_trace, &leaf_relation, LOG_SIZE, 2);

        let (refund_interaction_trace, refund_claimed_sum) =
            gen_poseidon_chain_interaction_trace(&refund_trace, &leaf_relation, LOG_SIZE, 1);

        let (merkle_interaction_trace, merkle_claimed_sum) =
            gen_merkle_membership_interaction_trace(
                &merkle_trace,
                &leaf_relation,
                &root_relation,
                LOG_SIZE,
                merkle_inputs.depth(),
            );

        let (scheduler_interaction_trace, scheduler_claimed_sum) = gen_scheduler_interaction_trace(
            &scheduler_trace,
            &leaf_relation,
            &root_relation,
            &refund_leaf_relation,
            LOG_SIZE,
        );

        // Commit interaction traces (deposit + refund + merkle + scheduler)
        use itertools::chain;

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(
            chain![
                deposit_interaction_trace,
                refund_interaction_trace,
                merkle_interaction_trace,
                scheduler_interaction_trace
            ]
            .collect::<Vec<_>>(),
        );
        tree_builder.commit(prover_channel);

        let mut tree_span_provider = TraceLocationAllocator::new_with_preproccessed_columns(&[
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
                leaf_multiplicity: 2,
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
                leaf_relation: leaf_relation.clone(),
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
            merkle_claimed_sum, // Total claimed sum for merkle component
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
                refund_commitment_hash,
                claimed_sum: scheduler_claimed_sum,
            },
            scheduler_claimed_sum, // Total claimed sum for scheduler component
        );

        let (proof, composition_poly) = prove::<SimdBackend, Blake2sMerkleChannel>(
            &[
                &deposit_component,
                &refund_component,
                &merkle_component,
                &scheduler_component,
            ],
            prover_channel,
            commitment_scheme,
        )
        .expect("Failed to generate proof");
        println!("Proof generated\n");

        let verifier_channel = &mut Blake2sChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

        // Verifier receives PUBLIC INPUTS (outside the proof)
        // In this test, we use the same values as prover, but in real system
        // verifier would receive these from external source
        let scheduler_statement_v = SchedulerStatement::new(
            merkle_inputs.expected_root,
            merkle_inputs.depth() as u32,
            nullifier,
            token_address,
            amount,
            refund_commitment_hash,
            recipient,
        );
        scheduler_statement_v.mix_into(verifier_channel);

        let leaf_relation_v = LeafRelation::draw(verifier_channel);
        let root_relation_v = RootRelation::draw(verifier_channel);
        let refund_leaf_relation_v = RefundLeafRelation::draw(verifier_channel);

        // Commit preprocessed (3 deposit + 3 refund + 4 merkle + 1 scheduler = 11 columns)
        commitment_scheme_verifier.commit(
            proof.commitments[0],
            &[
                LOG_SIZE, LOG_SIZE, LOG_SIZE, // deposit: is_active, is_step, is_last
                LOG_SIZE, LOG_SIZE, LOG_SIZE, // refund: is_active, is_step, is_last
                LOG_SIZE, LOG_SIZE, LOG_SIZE,
                LOG_SIZE, // merkle: is_active, is_step, is_first, is_last
                LOG_SIZE, // scheduler: is_first
            ],
            verifier_channel,
        );

        // Commit base traces (666 deposit + 666 refund + 667 merkle + 6 scheduler = 2005 columns)
        // Security fix: partial rounds now include internal matrix verification (19 cols per round)
        let mut base_trace_bounds = vec![LOG_SIZE; 666]; // Deposit chain (Cairo-m with security fix)
        base_trace_bounds.extend(vec![LOG_SIZE; 666]); // Refund chain (Cairo-m with security fix)
        base_trace_bounds.extend(vec![LOG_SIZE; 667]); // MerkleMembership (1 index_bit + 666 Poseidon)
        base_trace_bounds.extend(vec![LOG_SIZE; 6]); // Scheduler (6 columns: computed_root, expected_root, commitment_amount, refund_amount, deposit_leaf, refund_leaf)
        commitment_scheme_verifier.commit(
            proof.commitments[1],
            &base_trace_bounds,
            verifier_channel,
        );

        commitment_scheme_verifier.commit(
            proof.commitments[2],
            &[
                LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, // Deposit
                LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, // Refund
                LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, // Merkle
                LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, // Scheduler rel 1
                LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, // Scheduler rel 2
                LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE,
            ], // Scheduler rel 3
            verifier_channel,
        );

        let mut tree_span_provider_v = TraceLocationAllocator::new_with_preproccessed_columns(&[
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
                leaf_multiplicity: 2,
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
                leaf_relation: leaf_relation_v.clone(),
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
                refund_commitment_hash,
                claimed_sum: scheduler_claimed_sum,
            },
            scheduler_claimed_sum,
        );

        let result = verify_with_queries(
            &[
                &deposit_component_v,
                &refund_component_v,
                &merkle_component_v,
                &scheduler_component_v,
            ],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof,
            composition_poly
        );

        match result {
            Ok(_) => {
                println!("Verification succeeded!");
            }
            Err(e) => {
                panic!("Verification failed: {:?}", e);
            }
        }
    }
}
