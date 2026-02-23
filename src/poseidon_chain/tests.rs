#[cfg(test)]
mod tests {
    use alloy::primitives::{FixedBytes, U256};
    use stwo::core::air::Component;
    use stwo::core::fields::m31::BaseField;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::backend::{Col, Column};
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::{FrameworkEval, TraceLocationAllocator};

    use crate::merkle_membership::tests::{
        convert_to_solidity_proof, test_contract_verify, CM31, ComponentInfo, ComponentParams,
        QM31, VerificationParams,
    };
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

    #[tokio::test]
    async fn test_poseidon_chain_prove_and_verify() {
        use stwo::core::fields::m31::BaseField;
        use crate::poseidon_chain::prove_verify::{prove_poseidon_chain, verify_poseidon_chain};

        const LOG_SIZE: u32 = 5;

        let inputs = ChainInputs::for_deposit(
            BaseField::from_u32_unchecked(1),
            BaseField::from_u32_unchecked(2),
            BaseField::from_u32_unchecked(3),
            BaseField::from_u32_unchecked(4),
        );

        // Generate proof
        let proof_data = prove_poseidon_chain(LOG_SIZE, inputs.clone(), 1)
            .expect("Failed to generate proof");

        let solidity_proof =
        convert_to_solidity_proof(proof_data.proof.clone(), proof_data.composition_polynomial.clone(), proof_data.config);

        let (digest, component, roots, log_sizes, composition_log_degree_bound) = verify_poseidon_chain(
            proof_data,
            LOG_SIZE,
            1,
        )
        .expect("Failed to verify proof");

        let component_info = ComponentInfo {
            maxConstraintLogDegreeBound: component.max_constraint_log_degree_bound(),
            logSize: component.log_size(),
            maskOffsets: component.info.mask_offsets.0
                .iter()
                .map(|tree| tree.iter().map(|col| col.iter().map(|&offset| offset as i32).collect()).collect())
                .collect(), // Mask offsets: [tree][column][offset_values] from InfoEvaluator
            preprocessedColumns: component.info.preprocessed_columns
                .iter()
                .enumerate()
                .map(|(idx, _)| U256::from(idx))
                .collect(),
        };

        let verification_params = VerificationParams {
            componentParams: vec![
                ComponentParams {
                    logSize: component.log_size(),
                    claimedSum: QM31 {
                        first: CM31 { real: component.claimed_sum().0.0.0, imag: component.claimed_sum().0.1.0 },
                        second: CM31 { real: component.claimed_sum().1.0.0, imag: component.claimed_sum().1.1.0 },
                    },
                    info: component_info,
                },
            ],
            nPreprocessedColumns: U256::from(3),
            componentsCompositionLogDegreeBound: composition_log_degree_bound,
        };

        let roots_bytes32: Vec<FixedBytes<32>> = roots.iter().map(|r| FixedBytes::from(r.0)).collect();

        if let Err(e) = test_contract_verify(solidity_proof, verification_params,roots_bytes32, log_sizes, FixedBytes::from(digest.0), 0u32
        ).await {     println!("Contract verify call failed: {}", e);
        }

        println!("✓✓✓ TEST PASSED ✓✓✓");
    }
}
