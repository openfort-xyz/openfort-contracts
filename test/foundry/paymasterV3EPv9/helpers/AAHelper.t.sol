// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Data} from "test/foundry/paymasterV3EPv9/data/Data.t.sol";
import {Simple7702Account} from "test/foundry/paymasterV3EPv9/mocks/Simple7702Account.sol";
import {IEntryPoint} from "lib/account-abstraction-v09/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";

contract AAHelper is Data {
    function _etch() internal {
        vm.etch(owner7702, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = Simple7702Account(payable(owner7702));
    }

    function _getFreshUserOp(address _owner) internal pure returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: _owner,
            nonce: 0,
            initCode: hex"7702",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _populateUserOp(
        PackedUserOperation memory _userOp,
        bytes memory _callData,
        bytes32 _accountGasLimits,
        uint256 _preVerificationGas,
        bytes32 _gasFees,
        bytes memory _paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        _userOp.nonce = _getNonce(_userOp.sender);
        _userOp.callData = _callData;
        _userOp.accountGasLimits = _accountGasLimits;
        _userOp.preVerificationGas = _preVerificationGas;
        _userOp.gasFees = _gasFees;
        _userOp.paymasterAndData = _paymasterAndData;

        return _userOp;
    }

    function _getUserOpHash(PackedUserOperation memory _userOp) internal view returns (bytes32 hash) {
        hash = IEntryPoint(ENTRY_POINT_V9).getUserOpHash(_userOp);
    }

    function _getNonce(address _sender) internal view returns (uint256) {
        return IEntryPoint(ENTRY_POINT_V9).getNonce(_sender, 1);
    }

    function _signUserOp(bytes32 _userOpHash, uint256 _PK) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_PK, _userOpHash);
        signature = abi.encodePacked(r, s, v);
    }

    function _packAccountGasLimits(uint256 verificationGasLimit, uint256 callGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((verificationGasLimit << 128) | callGasLimit);
    }

    function _packGasFees(uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32((maxPriorityFeePerGas << 128) | maxFeePerGas);
    }
}
