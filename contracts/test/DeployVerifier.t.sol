// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "stwo-verifier/verifier/StwoVerifier.sol";

contract DeployVerifierTest is Test {
    function testDeployVerifier() public {
        // This test will actually deploy the verifier on anvil
        STWOVerifier verifier = new STWOVerifier();

        console.log("STWOVerifier deployed at:", address(verifier));

        // Verify it's deployed
        assertTrue(address(verifier) != address(0));

        // Check code exists
        uint256 codeSize;
        address verifierAddr = address(verifier);
        assembly {
            codeSize := extcodesize(verifierAddr)
        }
        console.log("Contract code size:", codeSize, "bytes");
        assertTrue(codeSize > 0, "Contract should have code");
    }
}
