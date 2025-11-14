// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Helper} from "test/foundry/UpgradeToEPv9/helpers/Helper.t.sol";
import {UserOperation} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {IEntryPoint as IEntryPointv6} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint as IEntryPointv9} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";

abstract contract AAHelper is Helper {
    enum EP_Version {
        V6,
        V9
    }

    function _getFreshUserOp(address _owner) internal pure returns (UserOperation memory userOpV6, PackedUserOperation memory userOpV9) {
        userOpV6 = UserOperation({
            sender: _owner,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: hex"",
            signature: hex""
        });
        userOpV9 = PackedUserOperation({
            sender: _owner,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _populateUserOpV6(
        UserOperation memory _userOp,
        bytes memory _callData,
        uint256 _callGasLimit,
        uint256 _verificationGasLimit,
        uint256 _preVerificationGas,
        uint256 _maxFeePerGas,
        uint256 _maxPriorityFeePerGas,
        bytes memory _paymasterAndData
    ) internal view returns (UserOperation memory) {
        _userOp.nonce = _getNonce(_userOp.sender, EP_Version.V6);
        _userOp.callData = _callData;
        _userOp.callGasLimit = _callGasLimit;
        _userOp.verificationGasLimit = _verificationGasLimit;
        _userOp.preVerificationGas = _preVerificationGas;
        _userOp.maxFeePerGas = _maxFeePerGas;
        _userOp.maxPriorityFeePerGas = _maxPriorityFeePerGas;
        _userOp.paymasterAndData = _paymasterAndData;

        return _userOp;
    }
    
    function _populateUserOpV9(
        PackedUserOperation memory _userOp,
        bytes memory _callData,
        bytes32 _accountGasLimits,
        uint256 _preVerificationGas,
        bytes32 _gasFees,
        bytes memory _paymasterAndData
    ) internal view returns (PackedUserOperation memory) {
        _userOp.nonce = _getNonce(_userOp.sender, EP_Version.V9);
        _userOp.callData = _callData;
        _userOp.accountGasLimits = _accountGasLimits;
        _userOp.preVerificationGas = _preVerificationGas;
        _userOp.gasFees = _gasFees;
        _userOp.paymasterAndData = _paymasterAndData;

        return _userOp;
    }

    function _getNonce(address _sender, EP_Version _epVersion) internal view returns (uint256) {
        return _epVersion == EP_Version.V6 ? entryPointV6.getNonce(_sender, 0) : entryPointV9.getNonce(_sender, 0);
    }

    function _getUserOpHashV6(UserOperation memory _userOp) internal view returns (bytes32 hash) {
        hash = entryPointV6.getUserOpHash(_userOp);
    }

    function _getUserOpHashV9(PackedUserOperation memory _userOp) internal view returns (bytes32 hash) {
        hash = entryPointV9.getUserOpHash(_userOp);
    }

    function _depositTo(address _sender, EP_Version _epVersion) internal {
        vm.prank(_sender);
        _epVersion == EP_Version.V6 ? entryPointV6.depositTo{value: 0.1 ether}(_sender) : entryPointV9.depositTo{value: 0.1 ether}(_sender);
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