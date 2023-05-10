// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {BaseAccount, UserOperation} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";
import {StaticAccountFactory} from "./StaticAccountFactory.sol";


contract StaticAccount is Initializable, IERC1271, BaseAccount, AccessControlEnumerable, TokenCallbackHandler {
    using ECDSA for bytes32;
    
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    address public immutable factory;

    IEntryPoint private immutable entrypointContract;
    
    // solhint-disable-next-line no-empty-blocks
    receive() external payable virtual {}

    constructor(IEntryPoint _entrypoint, address _factory) {
        _disableInitializers();
        entrypointContract = _entrypoint;
        factory = _factory;
    }

    /// @notice Initializes the smart contract wallet.
    function initialize(address _defaultAdmin, bytes calldata) public virtual initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
    }

    /// @notice Checks whether the caller is the EntryPoint contract or the admin.
    modifier onlyAdminOrEntrypoint() {
        require(
            msg.sender == address(entryPoint()) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Account: not admin or EntryPoint."
        );
        _;
    }

    /**
     * @inheritdoc BaseAccount
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return entrypointContract;
    }

    /**
     * Check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /// @notice Returns whether a signer is authorized to perform transactions using the wallet.
    function isValidSigner(address _signer) public view virtual returns (bool) {
        return hasRole(SIGNER_ROLE, _signer) || hasRole(DEFAULT_ADMIN_ROLE, _signer);
    }

    /// @notice See EIP-1271
    function isValidSignature(bytes32 _hash, bytes memory _signature)
        public
        view
        virtual
        override
        returns (bytes4 magicValue)
    {
        address signer = _hash.recover(_signature);
        if (isValidSigner(signer)) {
            magicValue = MAGICVALUE;
        }
    }

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external onlyAdminOrEntrypoint {
        _call(dest, value, func);
    }

    /**
     * Execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external onlyAdminOrEntrypoint {
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * Deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * Withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     * @notice ONLY the owner can call this function (it's not using _requireFromEntryPointOrOwner())
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * @dev Calls a target contract and reverts if it fails.
     */
    function _call(
        address _target,
        uint256 value,
        bytes memory _calldata
    ) internal {
        (bool success, bytes memory result) = _target.call{ value: value }(_calldata);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @inheritdoc BaseAccount
     */
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);

        if (!isValidSigner(signer))
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    /// @notice Registers a signer in the factory.
    function _setupRole(bytes32 role, address account) internal virtual override {
        super._setupRole(role, account);

        if (role == SIGNER_ROLE && factory.code.length > 0) {
            StaticAccountFactory(factory).addSigner(account);
        }
    }

    /// @notice Un-registers a signer in the factory.
    function _revokeRole(bytes32 role, address account) internal virtual override {
        super._revokeRole(role, account);

        if (role == SIGNER_ROLE && factory.code.length > 0) {
            StaticAccountFactory(factory).removeSigner(account);
        }
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, TokenCallbackHandler) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}