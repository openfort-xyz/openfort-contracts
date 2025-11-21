// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IPaymasterV8} from "./interfaces/IPaymasterV8.sol";
import {BaseSingletonPaymaster} from "./core/BaseSingletonPaymaster.sol";
import {SafeTransferLib} from "lib/solady/src/utils/SafeTransferLib.sol";
import {ECDSA} from "lib/oz-v5.4.0/contracts/utils/cryptography/ECDSA.sol";
import {_packValidationData} from "lib/account-abstraction-v09/contracts/core/Helpers.sol";
import {UserOperationLib} from "lib/account-abstraction-v09/contracts/core/UserOperationLib.sol";
import {MessageHashUtils} from "lib/oz-v5.4.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";

/**
 * @title PaymasterV3
 * @author 0xKoiner@Openfort
 * @notice Inspired by Pimlico and Solady Paymaster.
 * @dev Paymaster implementation compatible with account-abstraction v0.0.9 and OpenZeppelin v5.4.0
 *
 * @notice DEPENDENCY REQUIREMENTS:
 * This contract requires specific versions to avoid compatibility conflicts with newer versions:
 *
 * - Account Abstraction: v0.0.9 (conflicts with v0.6/v0.7/v0.8)
 * - OpenZeppelin Contracts: v5.4.0 (conflicts with v5.1+)
 *
 * @dev INSTALLATION:
 * Install the required dependencies with custom aliases to avoid conflicts:
 *
 * ```bash
 * forge install account-abstractionV8=eth-infinitism/account-abstraction v0.9.0
 * forge install oz-v5.4.0=OpenZeppelin/openzeppelin-contracts v5.4.0
 * ```
 * @dev COMPATIBILITY NOTES:
 * - Uses legacy EntryPoint interface from account-abstraction v0.0.9
 * - OpenZeppelin v5.4.0 provides stable API before breaking changes in v5.1+
 * - This setup maintains isolation from conflicting dependency versions
 */
contract OPFPaymasterV3 is BaseSingletonPaymaster, IPaymasterV8 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           USING                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    using UserOperationLib for PackedUserOperation;
    using UserOperationLib for bytes;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   constant/immutable                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    uint256 private constant PENALTY_PERCENT = 10;
    uint256 private constant PAYMASTER_DATA_OFFSET = UserOperationLib.PAYMASTER_DATA_OFFSET;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    constructor(address _owner, address _manager, address[] memory _signers)
        BaseSingletonPaymaster(_owner, _manager, _signers)
    {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*        ENTRYPOINT V0.8 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       EXTERNAL FUNC.                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 requiredPreFund)
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, requiredPreFund);
    }

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external
        override
    {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       INTERNAL FUNC.                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Internal helper to parse and validate the userOperation's paymasterAndData.
     * @param _userOp The userOperation.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The context and validation data to return to the EntryPoint.
     *
     * @dev paymasterAndData for mode 0:
     * - paymaster address (20 bytes)
     * - paymaster verification gas (16 bytes)
     * - paymaster postop gas (16 bytes)
     * - validUntil (6 bytes)
     * - validAfter (6 bytes)
     * - signature (64 or 65 bytes)
     * @dev Async flow: +10 bytes [uint16(signature.length)] + [PAYMASTER_SIG_MAGIC]
     *
     * @dev paymasterAndData for mode 1:
     * - paymaster address (20 bytes)
     * - paymaster verification gas (16 bytes)
     * - paymaster postop gas (16 bytes)
     * - constantFeePresent and recipientPresent and preFundPresent (1 byte) - 00000{preFundPresent
     * bit}{recipientPresent bit}{constantFeePresent bit}
     * - validUntil (6 bytes)
     * - validAfter (6 bytes)
     * - token address (20 bytes)
     * - postOpGas (16 bytes)
     * - exchangeRate (32 bytes)
     * - paymasterValidationGasLimit (16 bytes)
     * - treasury (20 bytes)
     * - preFund (16 bytes) - only if preFundPresent is 1
     * - constantFee (16 bytes - only if constantFeePresent is 1)
     * - recipient (20 bytes - only if recipientPresent is 1)
     * - signature (64 or 65 bytes)
     * @dev Async flow: +10 bytes [uint16(signature.length)] + [PAYMASTER_SIG_MAGIC]
     */
    function _validatePaymasterUserOp(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    ) internal returns (bytes memory, uint256) {
        (uint8 mode, bytes calldata paymasterConfig) =
            _parsePaymasterAndData(_userOp.paymasterAndData, PAYMASTER_DATA_OFFSET);

        uint256 sigLength = _userOp.paymasterAndData.getPaymasterSignatureLength();

        if (mode != ERC20_MODE && mode != VERIFYING_MODE) {
            revert OPFPaymasterV3__PaymasterModeInvalid();
        }

        bytes memory context;
        uint256 validationData;

        if (mode == VERIFYING_MODE) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash, sigLength);
        }

        if (mode == ERC20_MODE) {
            (context, validationData) =
                _validateERC20Mode(mode, _userOp, paymasterConfig, _userOpHash, _requiredPreFund, sigLength);
        }

        return (context, validationData);
    }

    function _validateVerifyingMode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _sigLength
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) =
            _parseVerifyingConfig(_paymasterConfig, _sigLength);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(VERIFYING_MODE, _userOp));
        address recoveredSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _getSender(_userOp), VERIFYING_MODE, address(0), 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(
        uint8 _mode,
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _requiredPreFund,
        uint256 _sigLength
    ) internal returns (bytes memory, uint256) {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig, _sigLength);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(_mode, _userOp));
        address recoveredSigner = ECDSA.recover(hash, cfg.signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, cfg.validUntil, cfg.validAfter);
        bytes memory context = _createPostOpContext(_userOp, _userOpHash, cfg, _requiredPreFund);

        if (!isSignatureValid) {
            return (context, validationData);
        }

        uint256 costInToken = getCostInToken(_requiredPreFund, 0, 0, cfg.exchangeRate);

        if (cfg.preFundInToken > costInToken) {
            revert OPFPaymasterV3__PreFundTooHigh();
        }

        if (cfg.preFundInToken > 0) {
            SafeTransferLib.safeTransferFrom(cfg.token, _userOp.sender, cfg.treasury, cfg.preFundInToken);
        }

        return (context, validationData);
    }

    function _postOp(
        PostOpMode, /* mode */
        bytes calldata _context,
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas
    )
        internal
    {
        ERC20PostOpContext memory ctx = _parsePostOpContext(_context);

        uint256 expectedPenaltyGasCost = _expectedPenaltyGasCost(
            _actualGasCost, _actualUserOpFeePerGas, ctx.postOpGas, ctx.preOpGasApproximation, ctx.executionGasLimit
        );

        uint256 actualGasCost = _actualGasCost + expectedPenaltyGasCost;

        uint256 costInToken =
            getCostInToken(actualGasCost, ctx.postOpGas, _actualUserOpFeePerGas, ctx.exchangeRate) + ctx.constantFee;

        uint256 absoluteCostInToken =
            costInToken > ctx.preFundCharged ? costInToken - ctx.preFundCharged : ctx.preFundCharged - costInToken;

        SafeTransferLib.safeTransferFrom(
            ctx.token,
            costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
            costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
            absoluteCostInToken
        );

        uint256 preFundInToken = (ctx.preFund * ctx.exchangeRate) / 1e18;

        if (ctx.recipient != address(0) && preFundInToken > costInToken) {
            SafeTransferLib.safeTransferFrom(ctx.token, ctx.sender, ctx.recipient, preFundInToken - costInToken);
        }

        emit UserOperationSponsored(ctx.userOpHash, ctx.sender, ERC20_MODE, ctx.token, costInToken, ctx.exchangeRate);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PURE/VIEW                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _expectedPenaltyGasCost(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 postOpGas,
        uint256 preOpGasApproximation,
        uint256 executionGasLimit
    ) public pure virtual returns (uint256) {
        uint256 executionGasUsed = 0;
        uint256 actualGas = _actualGasCost / _actualUserOpFeePerGas + postOpGas;

        if (actualGas > preOpGasApproximation) {
            executionGasUsed = actualGas - preOpGasApproximation;
        }

        uint256 expectedPenaltyGas = 0;
        if (executionGasLimit > executionGasUsed) {
            expectedPenaltyGas = ((executionGasLimit - executionGasUsed) * PENALTY_PERCENT) / 100;
        }

        return expectedPenaltyGas * _actualUserOpFeePerGas;
    }

    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view returns (bytes32) {
        if (_mode == VERIFYING_MODE) {
            return _getHash(_userOp, MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + VERIFYING_PAYMASTER_DATA_LENGTH);
        } else {
            uint8 paymasterDataLength = MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + ERC20_PAYMASTER_DATA_LENGTH;

            uint8 combinedByte =
                uint8(_userOp.paymasterAndData[PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH]);
            // constantFeePresent is in the *lowest* bit
            bool constantFeePresent = (combinedByte & 0x01) != 0;
            // recipientPresent is in the second lowest bit
            bool recipientPresent = (combinedByte & 0x02) != 0;
            // preFundPresent is in the third lowest bit
            bool preFundPresent = (combinedByte & 0x04) != 0;

            if (preFundPresent) {
                paymasterDataLength += 16;
            }

            if (constantFeePresent) {
                paymasterDataLength += 16;
            }

            if (recipientPresent) {
                paymasterDataLength += 20;
            }

            return _getHash(_userOp, paymasterDataLength);
        }
    }

    function _getHash(PackedUserOperation calldata _userOp, uint256 paymasterDataLength)
        internal
        view
        returns (bytes32)
    {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _getSender(_userOp),
                _userOp.nonce,
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                // hashing over all paymaster fields besides signature
                keccak256(_userOp.paymasterAndData[:PAYMASTER_DATA_OFFSET + paymasterDataLength])
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Admin function to set new Manager
     * @param _newManager Address of new manager.
     */
    function setManager(address _newManager) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_newManager == address(0) || _newManager == MANAGER || _newManager == OWNER || signers[_newManager]) {
            revert BasePaymaster__WrongManagerAddress(_newManager);
        }
        address _oldManager = MANAGER;
        _revokeRole(MANAGER_ROLE, MANAGER);
        _grantRole(MANAGER_ROLE, _newManager);
        MANAGER = _newManager;
        emit ManagerChanged(_oldManager, _newManager);
    }
}
