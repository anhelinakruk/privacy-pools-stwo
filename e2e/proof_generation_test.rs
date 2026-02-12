use privacy_pools_stwo::{
    convert_to_solidity_proof, generate_privacy_pool_proof, PrivacyPoolProofParams,
};

#[test]
fn test_generate_proof_for_withdraw() {
    // Private input
    let secret = 12345u32;
    let nullifier = 67890u32;

    // Deposit parameters
    let deposit_amount = 100u32;
    let refund_amount = 40u32;
    let withdrawal_amount = deposit_amount - refund_amount; // = 60

    // Public data
    let token_address = 0xABCDu32;
    let recipient = 0xDEADBEEFu32;

    // Merkle proof data 
    let merkle_index = 1u32;
    let merkle_siblings = vec![11111u32, 22222, 33333, 44444, 55555]; // depth 5

    println!("Proof Parameters:");
    println!("   Secret: {}", secret);
    println!("   Nullifier: {}", nullifier);
    println!("   Deposit amount: {}", deposit_amount);
    println!("   Refund amount: {}", refund_amount);
    println!("   Withdrawal amount: {}", withdrawal_amount);
    println!("   Token address: 0x{:X}", token_address);
    println!("   Recipient: 0x{:X}", recipient);
    println!("   Merkle index: {}", merkle_index);
    println!("   Merkle depth: {}", merkle_siblings.len());

    // Step 1: Generate proof
    let params = PrivacyPoolProofParams {
        secret,
        nullifier,
        deposit_amount,
        refund_amount,
        token_address,
        merkle_index,
        merkle_siblings,
        expected_root: 0, // Will be computed from siblings
        recipient,
        log_size: 5,
    };

    let proof_result = generate_privacy_pool_proof(params);
    assert!(
        proof_result.is_ok(),
        "Failed to generate proof: {:?}",
        proof_result.err()
    );

    let proof_data = proof_result.unwrap();
    println!("STARK proof generated!");
    println!("   Digest: {:02x?}...", &proof_data.digest[0..8]);
    println!("   Commitments: {}", proof_data.commitment_roots.len());
    println!(
        "   Proof size estimate: ~{} KB",
        estimate_proof_size(&proof_data)
    );

    // Step 2: Convert to Solidity format
    let sol_proof = convert_to_solidity_proof(
        proof_data.proof,
        proof_data.composition_polynomial,
        proof_data.config,
    );

    println!("Converted to Solidity format!");
    println!("   Config pow_bits: {}", sol_proof.config.powBits);
    println!(
        "   FRI log_blowup_factor: {}",
        sol_proof.config.friConfig.logBlowupFactor
    );
    println!("   Commitments: {}", sol_proof.commitments.len());
    println!(
        "   Sampled values trees: {}",
        sol_proof.sampledValues.len()
    );
    println!("   Decommitments: {}", sol_proof.decommitments.len());
    println!(
        "   FRI inner layers: {}",
        sol_proof.friProof.innerLayers.len()
    );
    println!(
        "   FRI last layer poly: {} coefficients",
        sol_proof.friProof.lastLayerPoly.len()
    );
    println!(
        "   Composition poly size: {} coeffs per coordinate",
        sol_proof.compositionPoly.coeffs0.len()
    );
}

fn estimate_proof_size(proof_data: &privacy_pools_stwo::PrivacyPoolProof) -> usize {
    let commitment_size = proof_data.commitment_roots.len() * 32;
    let digest_size = 32;
    let estimated_fri_size = 50_000; // FRI proofs are typically large
    let estimated_total = commitment_size + digest_size + estimated_fri_size;
    estimated_total / 1024
}
