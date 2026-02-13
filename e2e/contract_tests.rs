use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::Result;
use privacy_pools_stwo::poseidon_hash::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5, EXTERNAL_ROUND_CONSTS,
    INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
};
use stwo_prover::core::fields::m31::BaseField;

/// Helper: Hash two u32 values using our Poseidon2 implementation (returns 8 M31 elements)
fn poseidon2_hash_wide(a: u32, b: u32) -> [u32; 8] {
    // Validate inputs
    const M31_MODULUS: u32 = (1u32 << 31) - 1;
    assert!(a <= M31_MODULUS, "Input 'a' exceeds M31 modulus");
    assert!(b <= M31_MODULUS, "Input 'b' exceeds M31 modulus");

    // Initialize state [a, b, 0, 0, ..., 0]
    let mut state = [BaseField::from_u32_unchecked(0); N_STATE];
    state[0] = BaseField::from_u32_unchecked(a);
    state[1] = BaseField::from_u32_unchecked(b);

    // Apply Poseidon2 permutation
    apply_external_round_matrix(&mut state);

    // First 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round][i];
        }
        state = std::array::from_fn(|i| pow5(state[i]));
        apply_external_round_matrix(&mut state);
    }

    // 14 partial rounds
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] = state[0] + INTERNAL_ROUND_CONSTS[round];
        state[0] = pow5(state[0]);
        apply_internal_round_matrix(&mut state);
    }

    // Last 4 full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
        }
        state = std::array::from_fn(|i| pow5(state[i]));
        apply_external_round_matrix(&mut state);
    }

    // Return first 8 elements (248 bits)
    [
        state[0].0, state[1].0, state[2].0, state[3].0, state[4].0, state[5].0, state[6].0,
        state[7].0,
    ]
}

/// Combine 8 M31 elements into uint256 (matching Solidity's hashTwoWide)
/// Solidity: (state[0] << 217) | (state[1] << 186) | ... | state[7]
fn combine_to_u256(elements: [u32; 8]) -> U256 {
    U256::from(elements[0]) << 217
        | U256::from(elements[1]) << 186
        | U256::from(elements[2]) << 155
        | U256::from(elements[3]) << 124
        | U256::from(elements[4]) << 93
        | U256::from(elements[5]) << 62
        | U256::from(elements[6]) << 31
        | U256::from(elements[7])
}

/// Helper: Hash two u32 values and return uint256 (248 bits)
fn poseidon2_hash(a: u32, b: u32) -> U256 {
    combine_to_u256(poseidon2_hash_wide(a, b))
}

sol! {
    #[sol(rpc)]
    contract PrivacyPool {
        function deposit(uint256 commitment, uint256 amount, address token) external;
        function withdraw(uint256 root, uint256 nullifier, address token, uint256 amount, address recipient) external;
        function getCurrentRoot() external view returns (uint256);
        function poseidonHash(uint256 left, uint256 right) external pure returns (uint256);
    }

    #[sol(rpc)]
    contract MockERC20 {
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

#[tokio::test]
async fn test_basic_setup() -> Result<()> {
    let rpc_url = "http://localhost:8545".parse()?;

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let wallet = EthereumWallet::from(signer.clone());

    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    let my_address = signer.address();
    println!("My address: {}", my_address);

    let balance = provider.get_balance(my_address).await?;
    println!("ETH balance: {} wei", balance);

    let pool_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3".parse()?;
    let token_address: Address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".parse()?;

    let pool = PrivacyPool::new(pool_address, &provider);
    let token = MockERC20::new(token_address, &provider);

    let token_balance = token.balanceOf(my_address).call().await?;
    println!("Token balance: {}", token_balance);

    let amount = U256::from(10000000);
    let receipt = token
        .approve(pool_address, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Approved tx: {:?}", receipt.transaction_hash);

    let secret = 12345u32;
    let nullifier = 67890u32;
    let deposit_amount = 100u32;

    let secret_nullifier_hash = poseidon2_hash(secret, nullifier);
    let hash_result = pool
        .poseidonHash(U256::from(secret), U256::from(nullifier))
        .call()
        .await?;
    println!("   Contract hash(secret, nullifier): {:#x}", hash_result);
    println!(
        "   Rust hash(secret, nullifier):     {:#x}",
        secret_nullifier_hash
    );

    println!("   Secret-Nullifier Hash: {:#x}", secret_nullifier_hash);
    println!("   Amount: {}", deposit_amount);
    println!("   Token: {}", token_address);

    let receipt = pool
        .deposit(
            secret_nullifier_hash,
            U256::from(deposit_amount),
            token_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Deposit successful");
    println!("Tx hash: {:?}", receipt.transaction_hash);

    let new_root = pool.getCurrentRoot().call().await?;
    println!("New Merkle root: {:#x}", new_root);

    Ok(())
}

#[tokio::test]
async fn test_withdraw() -> Result<()> {
    let rpc_url = "http://localhost:8545".parse()?;

    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let wallet = EthereumWallet::from(signer.clone());

    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    let my_address = signer.address();
    println!("My address: {}", my_address);

    let pool_address: Address = "0x5b73C5498c1E3b4dbA84de0F1833c4a029d90519".parse()?;
    let token_address: Address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".parse()?;

    let pool = PrivacyPool::new(pool_address, &provider);
    let token = MockERC20::new(token_address, &provider);

    let amount = U256::from(10000000);
    let approve_receipt = token
        .approve(pool_address, amount)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("📝 Approved: {:?}", approve_receipt.transaction_hash);

    let allowance = token.allowance(my_address, pool_address).call().await?;
    println!("📝 Allowance: {}", allowance);

    let secret = 99999u32;
    let nullifier = 88888u32;
    let deposit_amount = 200u32;

    let secret_nullifier_hash = poseidon2_hash(secret, nullifier);
    println!("Nullifier hash: {:#x}", secret_nullifier_hash);

    let my_balance_before_deposit = token.balanceOf(my_address).call().await?;
    println!(
        "My token balance before deposit: {}",
        my_balance_before_deposit
    );

    let receipt = pool
        .deposit(
            secret_nullifier_hash,
            U256::from(deposit_amount),
            token_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Deposit successful: {:?}", receipt.transaction_hash);
    println!("Gas used: {}", receipt.gas_used);
    println!("Status: {:?}", receipt.status());

    let my_balance_after_deposit = token.balanceOf(my_address).call().await?;
    println!(
        "My token balance after deposit: {}",
        my_balance_after_deposit
    );

    let root = pool.getCurrentRoot().call().await?;
    println!("Merkle root: {:#x}", root);

    let contract_balance_before = token.balanceOf(pool_address).call().await?;
    println!("Contract token balance: {}", contract_balance_before);

    let recipient = my_address;
    let my_balance_before = token.balanceOf(my_address).call().await?;
    println!("My balance before withdraw: {}", my_balance_before);

    let withdraw_receipt = pool
        .withdraw(
            root,
            secret_nullifier_hash, // nullifier is hash(secret, nullifier)
            token_address,
            U256::from(deposit_amount),
            recipient,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    println!(
        "Withdraw successful: {:?}",
        withdraw_receipt.transaction_hash
    );

    let my_balance_after = token.balanceOf(my_address).call().await?;
    let contract_balance_after = token.balanceOf(pool_address).call().await?;

    println!("My balance after withdraw: {}", my_balance_after);
    println!(
        "Contract balance after withdraw: {}",
        contract_balance_after
    );

    assert_eq!(
        my_balance_after,
        my_balance_before + U256::from(deposit_amount)
    );
    assert_eq!(
        contract_balance_after,
        contract_balance_before - U256::from(deposit_amount)
    );

    let result = pool
        .withdraw(
            root,
            secret_nullifier_hash,
            token_address,
            U256::from(deposit_amount),
            recipient,
        )
        .send()
        .await;

    match result {
        Err(_) => println!("Double-spend correctly prevented!"),
        Ok(_) => panic!("Double-spend was not prevented!"),
    }

    Ok(())
}
