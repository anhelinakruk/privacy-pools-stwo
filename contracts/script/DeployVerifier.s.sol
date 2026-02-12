// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "stwo-verifier/verifier/StwoVerifier.sol";

contract DeployVerifierScript is Script {
    function run() external {
        // Use anvil default private key
        uint256 deployerPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

        vm.startBroadcast(deployerPrivateKey);

        // Deploy STWOVerifier
        STWOVerifier verifier = new STWOVerifier();

        console.log("STWOVerifier deployed at:", address(verifier));

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("STWOVerifier:", address(verifier));
    }
}
