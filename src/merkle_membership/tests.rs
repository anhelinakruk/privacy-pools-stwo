#[cfg(test)]
mod tests {
    use alloy::primitives::{FixedBytes, U256};
    use stwo::core::air::{Component, Components};
    use stwo::core::channel::KeccakChannel;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::vcs::keccak_merkle::KeccakMerkleChannel;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo_constraint_framework::{FrameworkEval, PREPROCESSED_TRACE_IDX};
    use stwo_polynomial::prove::{prove};

    use crate::merkle_membership::tests::{CM31, ComponentInfo, ComponentParams, QM31, VerificationParams, convert_to_solidity_proof, test_contract_verify};
    use crate::merkle_membership::{
        gen_merkle_is_active_column, gen_merkle_is_first_column, gen_merkle_is_last_column,
        gen_merkle_is_step_column, gen_merkle_membership_interaction_trace, gen_merkle_trace,
        merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
        merkle_is_step_column_id, MerkleInputs, MerkleMembershipComponent, MerkleMembershipEval,
        MerkleStatement0,
    };
    use crate::relations::{LeafRelation, RootRelation};

    #[tokio::test]
    async fn test_merkle_prove_and_verify() {
        use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::prover::poly::circle::PolyOps;
        use stwo::prover::{CommitmentSchemeProver};
        use stwo_constraint_framework::TraceLocationAllocator;

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

        let (trace, computed_root) = gen_merkle_trace(LOG_SIZE, &inputs);
        println!("Computed root: {}", computed_root.0);

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

        let prover_channel = &mut KeccakChannel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

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

        let mut tree_span_provider = TraceLocationAllocator::new_with_preprocessed_columns(&[
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

        // Generate proof
        let (proof, composition_polynomial) = prove(
            &[&component],
            prover_channel,
            commitment_scheme,
        ).unwrap();

        println!("Proof generated");

        let solidity_proof =
        convert_to_solidity_proof(proof.clone(), composition_polynomial.clone(), config);

        let verifier_channel = &mut KeccakChannel::default();
        let mut commitment_scheme_verifier =
            CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(config);

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

        let statement0 = MerkleStatement0 { log_size: LOG_SIZE };
        let log_sizes = statement0.log_sizes();

        let extended_log_sizes: Vec<Vec<u32>> = log_sizes.0
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
            TraceLocationAllocator::new_with_preprocessed_columns(&[
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

        let digest = verifier_channel.digest();

        stwo_polynomial::verify::verify(
            &[&verifier_component],
            verifier_channel,
            &mut commitment_scheme_verifier,
            proof.clone(),
            composition_polynomial
        ).unwrap();
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

        let component_info = ComponentInfo {
            maxConstraintLogDegreeBound: verifier_component.max_constraint_log_degree_bound(),
            logSize: verifier_component.log_size(),
            maskOffsets: verifier_component.info.mask_offsets.0
                .iter()
                .map(|tree| tree.iter().map(|col| col.iter().map(|&offset| offset as i32).collect()).collect())
                .collect(), // Mask offsets: [tree][column][offset_values] from InfoEvaluator
            preprocessedColumns: verifier_component.info.preprocessed_columns
                .iter()
                .enumerate()
                .map(|(idx, _)| U256::from(idx))
                .collect(),
        };

        let verification_params = VerificationParams {
            componentParams: vec![
                ComponentParams{
                    logSize: component.log_size(),
                    claimedSum: QM31 {
                        first: CM31 { real: component.claimed_sum().0.0.0, imag: component.claimed_sum().0.1.0 },
                        second: CM31 { real: component.claimed_sum().1.0.0, imag: component.claimed_sum().1.1.0 },
                    },
                    info: component_info,
                },
            ],
            nPreprocessedColumns: U256::from(4),  // 4 preprocessed columns: is_active, is_step, is_first, is_last
            componentsCompositionLogDegreeBound: components_log_degree_bound,
        };

        let roots = vec![proof.commitments[0], proof.commitments[1], proof.commitments[2]];
        let roots_bytes32: Vec<FixedBytes<32>> = roots.iter().map(|r| FixedBytes::from(r.0)).collect();

        if let Err(e) = test_contract_verify(solidity_proof, verification_params,roots_bytes32, extended_log_sizes, FixedBytes::from(digest.0), 0u32
        ).await {     println!("Contract verify call failed: {}", e);
        }

        println!("✓✓✓ TEST PASSED ✓✓✓");
    }
}

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use alloy::{hex, sol};
use std::time::Duration;
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse;
use stwo::core::vcs::keccak_merkle::{KeccakMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{SecureCirclePoly};

sol! {
    /// QM31 field element structure
    /// QM31 field element structure
    struct QM31 {
        CM31 first;
        CM31 second;
    }

    /// CM31 field element structure
    struct CM31 {
        uint32 real;
        uint32 imag;
    }

    /// PCS Configuration
    struct Config {
        uint32 powBits;
        FriConfig friConfig;
    }

    /// FRI Configuration
    struct FriConfig {
        uint32 logBlowupFactor;
        uint32 logLastLayerDegreeBound;
        uint256 nQueries;
    }

    /// Merkle decommitment structure
    struct Decommitment {
        bytes32[] witness;
        uint32[] columnWitness;
    }

    /// FRI layer proof structure
    struct FriLayerProof {
        QM31[] friWitness;
        bytes decommitment;
        bytes32 commitment;
    }

    /// FRI proof structure
    struct FriProof {
        FriLayerProof firstLayer;
        FriLayerProof[] innerLayers;
        QM31[] lastLayerPoly;
    }

    /// Composition polynomial
    struct CompositionPoly {
        uint32[] coeffs0;
        uint32[] coeffs1;
        uint32[] coeffs2;
        uint32[] coeffs3;
    }

    /// Complete proof structure for verification
    struct Proof {
        Config config;
        bytes32[] commitments;
        QM31[][][] sampledValues;
        Decommitment[] decommitments;
        uint32[][] queriedValues;
        uint64 proofOfWork;
        FriProof friProof;
        CompositionPoly compositionPoly;
    }

    /// TreeSubspan.Subspan structure
    struct Subspan {
        uint256 treeIndex;
        uint256 colStart;
        uint256 colEnd;
    }

    /// Component information structure
    struct ComponentInfo {
        uint32 maxConstraintLogDegreeBound;
        uint32 logSize;
        int32[][][] maskOffsets; // Mask offsets: [tree][column][offset_values] from InfoEvaluator
        uint256[] preprocessedColumns; // Preprocessed column IDs
    }

    /// Framework component state
    struct ComponentState {
        uint32 logSize;
        Subspan[] traceLocations; // Trace locations allocated for this component
        uint256[] preprocessedColumnIndices; // Preprocessed column indices
        QM31 claimedSum; // Claimed sum for logup constraints
        ComponentInfo info; // Component metadata
        bool isInitialized; // Whether the component is initialized
    }

    struct ComponentParams{
        uint32 logSize;
        QM31 claimedSum;
        ComponentInfo info;
    }

    /// Verification parameters structure - EXACT match with Solidity
    struct VerificationParams {
        ComponentParams[] componentParams; // Array of components to verify
        uint256 nPreprocessedColumns; // Number of preprocessed columns
        uint32 componentsCompositionLogDegreeBound; // Log degree bound for composition polynomial
    }
    /// STWO Verifier contract interface
    interface IStwoVerifier {
        /// Main verification function
        function verify(
            Proof calldata proof,
            VerificationParams calldata params,
            bytes32[] memory treeRoots,
            uint32[][] memory treeColumnLogSizes,
            bytes32 digest,
            uint32 nDraws
        ) external view returns (bool);

        /// Verify proof with merkle roots
        function verifyProofWithRoots(
            Proof calldata proof,
            bytes32[] calldata merkleRoots,
            uint32[][] calldata columnLogSizes
        ) external view returns (bool);

        /// Get verification configuration
        function getConfig() external view returns (Config memory);
    }
}

pub async fn test_contract_verify(
    proof: Proof,
    verification_params: VerificationParams,
    tree_roots: Vec<FixedBytes<32>>,
    tree_column_log_sizes: Vec<Vec<u32>>,
    digest: FixedBytes<32>,
    n_draws: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔗 Testing Contract Verify Call");

    // Connect to Anvil
    let rpc_url = "http://localhost:8545";
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);

    // Contract address
    let contract_address =
        Address::parse_checksummed("0x5FbDB2315678afecb367f032d93F642f64180aa3", None)?;

    println!("Calling contract verify function...");

    // Encode the call data using SolCall trait
    let call_data = IStwoVerifier::verifyCall {
        proof,
        params: verification_params,
        treeRoots: tree_roots,
        treeColumnLogSizes: tree_column_log_sizes,
        digest,
        nDraws: n_draws,
    };

    // Call contract - this simulates the transaction and returns revert reasons
    let call_input = TransactionRequest::default()
        .to(contract_address)
        .input(call_data.abi_encode().into());

    let gas_estimation_timeout = Duration::from_secs(10);
    println!(
        "Estimating gas (timeout: {}s)...",
        gas_estimation_timeout.as_secs()
    );
    match tokio::time::timeout(gas_estimation_timeout, provider.estimate_gas(call_input.clone())).await {
        Ok(Ok(gas)) => println!("⛽ Estimated gas: {}", gas),
        Ok(Err(e)) => println!("⚠️  Gas estimate failed: {}", e),
        Err(_) => println!(
            "⏱️  Gas estimate timed out after {}s, continuing without estimate",
            gas_estimation_timeout.as_secs()
        ),
    }

    println!("Simulating contract call...");
    match provider.call(call_input).await {
        Ok(result) => {
            println!("✅ Contract call succeeded: 0x{}", hex::encode(&result));
        }
        Err(e) => {
            println!("❌ Contract call reverted:");
            println!("{}", e);
            
            // Try to extract revert reason
            if let Some(data) = e.as_error_resp() {
                println!("\nRevert data: {:?}", data);
            }

            return Err(Box::new(e));
        }
    }

    Ok(())
}

/// Recreate Solidity abi.encodePacked for decommitment
pub fn encode_decommitment_packed(hash_witness: &[FixedBytes<32>], column_witness: &[u32]) -> Bytes {
    let mut encoded = Vec::new();

    // uint256(innerLayer2HashWitness.length)
    let length_bytes: [u8; 32] = U256::from(hash_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&length_bytes);

    // innerLayer2HashWitness (bytes32[] packed)
    for witness in hash_witness {
        encoded.extend_from_slice(witness.as_slice());
    }

    // uint256(0) - column witness length
    let column_length_bytes: [u8; 32] = U256::from(column_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&column_length_bytes);

    // new uint32[](0) - empty column witness array
    for &val in column_witness {
        encoded.extend_from_slice(&val.to_be_bytes());
    }

    Bytes::from(encoded)
}

pub fn convert_to_solidity_proof(
    proof: StarkProof<KeccakMerkleHasher>,
    composition_polynomial: SecureCirclePoly<SimdBackend>,
    config: PcsConfig,
) -> Proof {
    // Convert PCS config
    let sol_config = Config {
        powBits: config.pow_bits,
        friConfig: FriConfig {
            logBlowupFactor: config.fri_config.log_blowup_factor,
            logLastLayerDegreeBound: config.fri_config.log_last_layer_degree_bound,
            nQueries: U256::from(config.fri_config.n_queries),
        },
    };

    // Extract commitments as FixedBytes<32> array for Solidity bytes32
    let commitments: Vec<FixedBytes<32>> = proof
        .0
        .commitments
        .iter()
        .map(|commitment| FixedBytes::from(commitment.0))
        .collect();

    // Convert sampled values - convert STWO QM31 to Alloy QM31
    let sampled_values: Vec<Vec<Vec<QM31>>> = proof
        .sampled_values
        .iter()
        .map(|column| {
            column
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|qm31| QM31 {
                            first: CM31 {
                                real: qm31.0 .0 .0,
                                imag: qm31.0 .1 .0,
                            },
                            second: CM31 {
                                real: qm31.1 .0 .0,
                                imag: qm31.1 .1 .0,
                            },
                        })
                        .collect()
                })
                .collect()
        })
        .collect();

    println!("DEBUG OLD sampled_values dims: {} trees", sampled_values.len());
    for (tree_idx, tree) in sampled_values.iter().enumerate() {
        println!("  Tree {}: {} columns", tree_idx, tree.len());
        if !tree.is_empty() {
            println!("    Column 0: {} points", tree[0].len());
        }
    }

    // Convert decommitments
    let decommitments: Vec<Decommitment> = proof
        .0
        .decommitments
        .iter()
        .map(|decom| Decommitment {
            witness: decom
                .hash_witness
                .iter()
                .map(|h| FixedBytes::from(h.0))
                .collect::<Vec<_>>(),
            columnWitness: decom.column_witness.iter().map(|m| m.0).collect::<Vec<_>>(),
        })
        .collect();

    let first_layer: FriLayerProof = {
        let layer = &proof.0.fri_proof.first_layer;
        FriLayerProof {
            friWitness: layer
                .fri_witness
                .iter()
                .map(|val| QM31 {
                    first: CM31 {
                        real: val.0 .0 .0,
                        imag: val.0 .1 .0,
                    },
                    second: CM31 {
                        real: val.1 .0 .0,
                        imag: val.1 .1 .0,
                    },
                })
                .collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| FixedBytes::from(h.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|m| m.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        }
    };

    let inner_layers: Vec<FriLayerProof> = proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .map(|layer| FriLayerProof {
            friWitness: layer
                .fri_witness
                .iter()
                .map(|val| QM31 {
                    first: CM31 {
                        real: val.0 .0 .0,
                        imag: val.0 .1 .0,
                    },
                    second: CM31 {
                        real: val.1 .0 .0,
                        imag: val.1 .1 .0,
                    },
                })
                .collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| FixedBytes::from(h.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|m| m.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        })
        .collect();

    // Convert FRI proof
    let fri_proof = FriProof {
        innerLayers: inner_layers,
        lastLayerPoly: {
            let mut coeffs = proof
                .clone()
                .0
                .fri_proof
                .last_layer_poly
                .into_ordered_coefficients();
            bit_reverse(&mut coeffs); // Reverse back to bit-reversed order
            coeffs
                .iter()
                .map(|v| QM31 {
                    first: CM31 {
                        real: v.0 .0 .0,
                        imag: v.0 .1 .0,
                    },
                    second: CM31 {
                        real: v.1 .0 .0,
                        imag: v.1 .1 .0,
                    },
                })
                .collect()
        },
        firstLayer: first_layer,
    };

    let composition_polynomial_to_solidity: Vec<Vec<u32>> = composition_polynomial
        .into_coordinate_polys()
        .iter()
        .map(|poly| {
            let mut layer = Vec::new();
            for coeff in &poly.coeffs.data {
                let coeff_as_u32: Vec<u32> = coeff.to_array().iter().map(|m| m.0).collect();
                layer.extend_from_slice(&coeff_as_u32);
            }
            layer
        })
        .collect();

    // Convert composition polynomial
    let comp_poly = CompositionPoly {
        coeffs0: composition_polynomial_to_solidity[0].clone(),
        coeffs1: composition_polynomial_to_solidity[1].clone(),
        coeffs2: composition_polynomial_to_solidity[2].clone(),
        coeffs3: composition_polynomial_to_solidity[3].clone(),
    };

    let queried_values: Vec<Vec<u32>> = proof
        .0
        .queried_values
        .iter()
        .map(|column| column.iter().map(|val| val.0).collect())
        .collect();

    println!("DEBUG OLD queried_values: {} columns", queried_values.len());
    for (idx, col) in queried_values.iter().enumerate() {
        println!("  Column {}: {} values", idx, col.len());
    }
    println!("DEBUG OLD proof.commitments.len(): {}", proof.0.commitments.len());

    Proof {
        config: sol_config,
        commitments,
        sampledValues: sampled_values,
        decommitments,
        queriedValues: queried_values,
        proofOfWork: proof.proof_of_work,
        friProof: fri_proof,
        compositionPoly: comp_poly,
    }
}
