#[cfg(test)]
mod tests {
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    use crate::poseidon_chain::{
        ChainInputs, PoseidonChainComponent, PoseidonChainEval,
        gen_poseidon_chain_trace, gen_is_active_column, gen_is_step_column, gen_is_last_column,
        is_active_column_id, is_step_column_id, is_last_column_id,
        gen_poseidon_chain_interaction_trace,
    };
    use crate::merkle_membership::{
        MerkleInputs, MerkleMembershipComponent, MerkleMembershipEval,
        gen_merkle_trace, gen_merkle_is_active_column, gen_merkle_is_step_column,
        gen_merkle_is_first_column, gen_merkle_is_last_column,
        merkle_is_active_column_id, merkle_is_step_column_id,
        merkle_is_first_column_id, merkle_is_last_column_id,
        gen_merkle_membership_interaction_trace,
    };
    use crate::relations::{LeafRelation, RootRelation};

    #[test]
    fn test_privacy_pool_combined() {
        const LOG_SIZE: u32 = 5;

        let chain_inputs = ChainInputs::for_deposit(
            BaseField::from_u32_unchecked(12345),
            BaseField::from_u32_unchecked(67890),
            BaseField::from_u32_unchecked(100),
            BaseField::from_u32_unchecked(0xABCD),
        );
        let (chain_trace, chain_outputs) = gen_poseidon_chain_trace(LOG_SIZE, chain_inputs.clone());
        println!(" Computed leaf: {}\n", chain_outputs.leaf.0);

        let merkle_inputs = MerkleInputs {
            leaf: chain_outputs.leaf,
            index: 1,
            siblings: vec![
                BaseField::from_u32_unchecked(11111),
                BaseField::from_u32_unchecked(22222),
                BaseField::from_u32_unchecked(33333),
                BaseField::from_u32_unchecked(44444),
                BaseField::from_u32_unchecked(55555),
            ],
            expected_root: BaseField::from_u32_unchecked(999999), 
        };
        let (merkle_trace, computed_root) = gen_merkle_trace(LOG_SIZE, &merkle_inputs);
        println!(" Computed root: {}\n", computed_root.0);

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

        let leaf_relation = LeafRelation::draw(prover_channel);
        let root_relation = RootRelation::draw(prover_channel);
  
        let chain_is_active = gen_is_active_column(LOG_SIZE);
        let chain_is_step = gen_is_step_column(LOG_SIZE);
        let chain_is_last = gen_is_last_column(LOG_SIZE);

        let merkle_is_active = gen_merkle_is_active_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_step = gen_merkle_is_step_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_first = gen_merkle_is_first_column(LOG_SIZE, merkle_inputs.depth());
        let merkle_is_last = gen_merkle_is_last_column(LOG_SIZE, merkle_inputs.depth());

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals([
            chain_is_active.clone(),
            chain_is_step.clone(),
            chain_is_last.clone(),
            merkle_is_active.clone(),
            merkle_is_step.clone(),
            merkle_is_first.clone(),
            merkle_is_last.clone(),
        ]);
        tree_builder.commit(prover_channel);

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(chain_trace.clone());
        tree_builder.extend_evals(merkle_trace.clone());
        tree_builder.commit(prover_channel);

        let (chain_interaction_trace, chain_claimed_sum) = gen_poseidon_chain_interaction_trace(
            &chain_trace,
            &leaf_relation,
            LOG_SIZE,
        );

        let (merkle_interaction_trace, merkle_claimed_sum) =
            gen_merkle_membership_interaction_trace(
                &merkle_trace,
                &leaf_relation,
                &root_relation,
                LOG_SIZE,
                merkle_inputs.depth(),
            );

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(chain_interaction_trace.clone());
        tree_builder.extend_evals(merkle_interaction_trace.clone());
        tree_builder.commit(prover_channel);

        let mut tree_span_provider = TraceLocationAllocator::new_with_preprocessed_columns(&[
            is_active_column_id(LOG_SIZE),
            is_step_column_id(LOG_SIZE),
            is_last_column_id(LOG_SIZE),
            merkle_is_active_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_step_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_first_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_last_column_id(LOG_SIZE, merkle_inputs.depth()),
        ]);

        let chain_component = PoseidonChainComponent::new(
            &mut tree_span_provider,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE),
                is_step_id: is_step_column_id(LOG_SIZE),
                is_last_id: is_last_column_id(LOG_SIZE),
                leaf_relation: leaf_relation.clone(),
                claimed_sum: chain_claimed_sum,
            },
            chain_claimed_sum,  // Total claimed sum for chain component
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
            merkle_claimed_sum,  // Total claimed sum for merkle component
        );

        let proof = prove::<SimdBackend, Blake2sMerkleChannel>(
            &[&chain_component, &merkle_component],
            prover_channel,
            commitment_scheme,
        )
        .expect("Failed to generate proof");
        println!("Proof generated\n");

        let verifier_channel = &mut Blake2sChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

        let leaf_relation_v = LeafRelation::draw(verifier_channel);
        let root_relation_v = RootRelation::draw(verifier_channel);

        commitment_scheme_verifier.commit(
            proof.commitments[0],
            &[LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE],
            verifier_channel,
        );

        let mut base_trace_bounds = vec![LOG_SIZE; 174]; // PoseidonChain
        base_trace_bounds.extend(vec![LOG_SIZE; 174]); // MerkleMembership
        commitment_scheme_verifier.commit(
            proof.commitments[1],
            &base_trace_bounds,
            verifier_channel,
        );

        commitment_scheme_verifier.commit(
            proof.commitments[2],
            &[LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE,  
              LOG_SIZE, LOG_SIZE, LOG_SIZE, LOG_SIZE], 
            verifier_channel,
        );

        let mut tree_span_provider_v = TraceLocationAllocator::new_with_preprocessed_columns(&[
            is_active_column_id(LOG_SIZE),
            is_step_column_id(LOG_SIZE),
            is_last_column_id(LOG_SIZE),
            merkle_is_active_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_step_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_first_column_id(LOG_SIZE, merkle_inputs.depth()),
            merkle_is_last_column_id(LOG_SIZE, merkle_inputs.depth()),
        ]);

        let chain_component_v = PoseidonChainComponent::new(
            &mut tree_span_provider_v,
            PoseidonChainEval {
                log_n_rows: LOG_SIZE,
                is_active_id: is_active_column_id(LOG_SIZE),
                is_step_id: is_step_column_id(LOG_SIZE),
                is_last_id: is_last_column_id(LOG_SIZE),
                leaf_relation: leaf_relation_v.clone(),
                claimed_sum: chain_claimed_sum,
            },
            chain_claimed_sum, 
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

        let result = stwo::core::verifier::verify(
            &[&chain_component_v, &merkle_component_v],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof,
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
