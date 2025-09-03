// SPDX-license-Identifier: MIT

pragma solidity ^0.8.29;

import {IERC20} from "@oz-v5.4.0/token/ERC20/IERC20.sol";
import {IEntryPoint} from "@account-abstraction-v8/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@oz-v5.4.0/utils/cryptography/MessageHashUtils.sol";
import {BasePaymasterTest as Base} from "test/foundry/paymasterV3/BasePaymasterTest.t.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";
import {_parseValidationData, ValidationData} from "@account-abstraction-v8/core/Helpers.sol";
import {ECDSA} from "@oz-v5.4.0/utils/cryptography/ECDSA.sol";

import {console2 as console} from "lib/forge-std/src/test.sol";

uint256 constant mintTokens = 30e18;

contract PaymasterValidationTest is Base {
    uint48 validUntil = uint48(block.timestamp + 1 days);
    uint48 constant validAfter = 0;
    uint128 constant postGas = 50000;
    uint256 constant preVerificationGas = 800_000;

    modifier mint() {
        _mint(sender, mintTokens);
        _;
    }

    function test_balanceOf() public mint {
        uint256 balance = IERC20(address(mockERC20)).balanceOf(sender);
        assertEq(mintTokens, balance);
    }

    function test_validatePaymasterUserOpModeVERIFYING_MODE() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, 0);
        bytes memory paymasterSignature = this._signPaymasterData(VERIFYING_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, hex"");
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);
    }

    function _signPaymasterData(uint8 _mode, PackedUserOperation calldata _userOp, uint256 _signerIndx)
        external
        view
        returns (bytes memory paymasterSignature)
    {
        bytes32 rawHash = PM.getHash(_mode, _userOp);
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(rawHash);
        uint256 PK = signersPK[_signerIndx];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, ethSignedHash);

        paymasterSignature = abi.encodePacked(r, s, v);
    }

    function _createPaymasterDataMode(PackedUserOperation memory userOp, uint8 _mode)
        internal
        view
        returns (bytes memory paymasterData)
    {
        if (_mode == 0) {
            uint128 verificationGasLimit = uint128(uint256(bytes32(userOp.accountGasLimits)) >> 128);

            paymasterData = abi.encodePacked(
                address(PM),
                verificationGasLimit,
                postGas,
                (_mode << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
                validUntil,
                validAfter
            );
        }
    }

    function _signUserOp(bytes32 hash) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPK, hash);

        signature = abi.encodePacked(r, s, v);
    }
}
