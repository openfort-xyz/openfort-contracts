// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IEntryPoint} from "@account-abstraction-v8/interfaces/IEntryPoint.sol";
import {BasePaymasterTest as Base} from "test/foundry/paymasterV3/BasePaymasterTest.t.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";
import {console2 as console} from "lib/forge-std/src/test.sol";

contract GettersTest is Base {
    function test_signerCount() public {
        uint256 sC = _signerCount();
        assertEq(sC, signers.length);
    }

    function test_signerAt() public {
        uint256 sC = _signerCount();

        for (uint256 i = 0; i < sC;) {
            address signer = PM.signerAt(i);
            assertEq(signer, signers[i]);
            unchecked {
                i++;
            }
        }
    }

    function test_getSigners() public {
        address[] memory getSigners = PM.getSigners();

        for (uint256 i = 0; i < getSigners.length;) {
            assertEq(getSigners[i], signers[i]);
            unchecked {
                i++;
            }
        }
    }

    function test_OnwerAndManager() public {
        address getOwner = PM.OWNER();
        address getManager = PM.MANAGER();

        assertEq(owner, getOwner);
        assertEq(manager, getManager);
    }

    function test_getEP() public {
        IEntryPoint EP = PM.ENTRY_POINT_V8();
        assertEq(address(EP), address(ENTRY_POINT_V8));
    }

    function test_getDeposit() public {
        uint256 getDeposit = PM.getDeposit();
        assertEq(getDeposit, 0);
    }

    function test_getCostInToken() public {
        uint256 _actualGasCost = 100_000;
        uint256 _postOpGas = 80_000;
        uint256 _actualUserOpFeePerGas = 200_000;
        uint256 _exchangeRate = 4000_000;

        uint256 actualRate = ((_actualGasCost + (_postOpGas * _actualUserOpFeePerGas)) * _exchangeRate) / 1e18;

        uint256 getcost = PM.getCostInToken(_actualGasCost, _postOpGas, _actualUserOpFeePerGas, _exchangeRate);

        assertEq(actualRate, getcost);
    }

    function test_getHashModeVERIFYING_MODE() public {
        PackedUserOperation memory userOp = _getFreshUserOp();
        bytes memory paymasterAndData =
            new bytes(PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + VERIFYING_PAYMASTER_DATA_LENGTH);

        bytes20 paymasterAddress = bytes20(address(PM));
        for (uint256 i = 0; i < 20; i++) {
            paymasterAndData[i] = paymasterAddress[i];
        }

        userOp.paymasterAndData = paymasterAndData;
        this._testFetHashModeVERIFYING_MODE(userOp);
    }

    function _testFetHashModeVERIFYING_MODE(PackedUserOperation calldata _userOp) external {
        bytes32 computeHash = _getHash(_userOp, MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + VERIFYING_PAYMASTER_DATA_LENGTH);
        bytes32 hash = PM.getHash(uint8(0), _userOp);
        assertEq(computeHash, hash);
    }

    function test_getHashModeERC20_MODE() public {
        PackedUserOperation memory userOp = _getFreshUserOp();

        uint256 baseLength = PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + ERC20_PAYMASTER_DATA_LENGTH;
        bytes memory paymasterAndData = new bytes(baseLength);

        bytes20 paymasterAddress = bytes20(address(PM));
        for (uint256 i = 0; i < 20; i++) {
            paymasterAndData[i] = paymasterAddress[i];
        }

        uint256 combinedByteIndex = PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH;
        paymasterAndData[combinedByteIndex] = 0x00;

        userOp.paymasterAndData = paymasterAndData;
        this._testGetHashModeERC20_MODE(userOp);
    }

    function _testGetHashModeERC20_MODE(PackedUserOperation calldata _userOp) external {
        uint8 paymasterDataLength = MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + ERC20_PAYMASTER_DATA_LENGTH;
        bytes32 computeHash = _getHash(_userOp, paymasterDataLength);

        bytes32 hash = PM.getHash(uint8(1), _userOp);
        assertEq(computeHash, hash);
    }

    function _signerCount() internal view returns (uint256 counter) {
        counter = PM.signerCount();
    }
}
