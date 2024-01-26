// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {Signature} from "../src/Signature.sol";
import {FixedSignature} from "../src/FixedSignature.sol";

contract SignatureTest is Test {
    FixedSignature signatureContract;
    address signer;
    uint256 privateKey = 0x1010101010101010101010101010101010101010101010101010101010101010;
    bytes32 messageHash;

    function getEthSignedMessageHash(bytes32 msgHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
    }

    function signMessage(bytes32 msgHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        signer = vm.addr(privateKey);
        messageHash = getEthSignedMessageHash(keccak256(abi.encodePacked("Pessimistic Security")));
    }

    function testCheckMalleability() public {
        signatureContract = new FixedSignature(signer);

        bytes memory sig = signMessage(messageHash);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        bytes32 sAnotherOne =
            bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
        uint8 vAnotherOne = v == 27 ? 28 : 27;

        bool result = signatureContract.checkSignature(messageHash, abi.encodePacked(r, sAnotherOne, vAnotherOne));

        assertFalse(result);
    }

    function testCheck() public {
        signatureContract = new FixedSignature(signer);
        bytes memory sig = signMessage(messageHash);
        bool result = signatureContract.checkSignature(messageHash, sig);
        assertTrue(result);
    }
}
