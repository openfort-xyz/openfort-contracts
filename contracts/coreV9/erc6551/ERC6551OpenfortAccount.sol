// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC6551Account} from "erc6551/src/interfaces/IERC6551Account.sol";
import {IERC6551Executable} from "erc6551/src/interfaces/IERC6551Executable.sol";
import {ERC6551AccountLib} from "erc6551/src/lib/ERC6551AccountLib.sol";
import {BaseOpenfortAccount, IEntryPoint, ECDSAUpgradeable} from "../base/BaseOpenfortAccount.sol";

/**
 * @title ERC6551OpenfortAccount (Non-upgradeable)
 * @notice Smart contract wallet with session keys following the ERC-4337 and EIP-6551 standards.
 * It inherits from:
 *  - BaseOpenfortAccount to comply with ERC-4337
 *  - IERC6551Account to have permissions using ERC-721 tokens
 *  - IERC6551Executable
 */
contract ERC6551OpenfortAccount is BaseOpenfortAccount, IERC6551Account, IERC6551Executable {
    using ECDSAUpgradeable for bytes32;

    // bytes4(keccak256("execute(address,uint256,bytes,uint8)")
    bytes4 internal constant EXECUTE_ERC6551_SELECTOR = 0x51945447;
    address constant DEFAULT_ENTRYPOINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    address internal entrypointContract;
    uint256 public state;

    error OperationNotAllowed();

    receive() external payable override(BaseOpenfortAccount, IERC6551Account) {}

    constructor() {}

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize() public initializer {
        entrypointContract = DEFAULT_ENTRYPOINT;
        __EIP712_init("Openfort", "0.5");
        state = 1;
    }

    /*
     * Returns the address of the owner
     */
    function owner() public view override returns (address) {
        (uint256 chainId, address contractAddress, uint256 tokenId) = token();
        if (chainId != block.chainid) return address(0);
        return IERC721(contractAddress).ownerOf(tokenId);
    }

    /**
     * @dev {See IERC6551Account-token}
     */
    function token() public view virtual override returns (uint256, address, uint256) {
        return ERC6551AccountLib.token();
    }

    /**
     * @dev {See IERC6551Account-isValidSigner}
     */
    function isValidSigner(address _signer, bytes calldata) external view override returns (bytes4) {
        if (_isValidSigner(_signer)) return IERC6551Account.isValidSigner.selector;
        return bytes4(0);
    }

    function _isValidSigner(address _signer) internal view returns (bool) {
        return _signer == owner();
    }

    /**
     * @dev {See IERC6551Executable-execute}
     */
    function execute(address _target, uint256 _value, bytes calldata _data, uint8 _operation)
        external
        payable
        override
        returns (bytes memory _result)
    {
        if (_operation != 0) revert OperationNotAllowed();
        _requireFromEntryPointOrOwner();
        ++state;
        bool success;
        (success, _result) = _target.call{value: _value}(_data);
        require(success, string(_result));
        return _result;
    }

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address _dest, uint256 _value, bytes calldata _func) public payable override {
        ++state;
        super.execute(_dest, _value, _func);
    }

    /**
     * Execute a sequence of transactions. Maximum 9.
     */
    function executeBatch(address[] calldata _target, uint256[] calldata _value, bytes[] calldata _calldata)
        public
        payable
        override
    {
        state += _target.length;
        super.executeBatch(_target, _value, _calldata);
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external {
        _requireFromOwner();
        if (_newEntrypoint == address(0)) revert ZeroAddressNotAllowed();
        ++state;
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(entrypointContract);
    }

    function supportsInterface(bytes4 _interfaceId) external pure override returns (bool) {
        return (
            _interfaceId == type(IERC6551Account).interfaceId || _interfaceId == type(IERC6551Executable).interfaceId
                || _interfaceId == type(IERC1155Receiver).interfaceId || _interfaceId == type(IERC721Receiver).interfaceId
                || _interfaceId == type(IERC165).interfaceId
        );
    }

    function onERC721Received(address, address, uint256 receivedTokenId, bytes memory)
        external
        view
        override
        returns (bytes4)
    {
        _revertIfOwnershipCycle(msg.sender, receivedTokenId);
        return IERC721Receiver.onERC721Received.selector;
    }

    /**
     * @dev Helper method to check if a received token is in the ownership chain of the wallet.
     * @param receivedTokenAddress The address of the token being received.
     * @param receivedTokenId The ID of the token being received.
     */
    function _revertIfOwnershipCycle(address receivedTokenAddress, uint256 receivedTokenId) internal view virtual {
        (uint256 _chainId, address _contractAddress, uint256 _tokenId) = token();
        require(
            _chainId != block.chainid || receivedTokenAddress != _contractAddress || receivedTokenId != _tokenId,
            "Cannot own yourself"
        );

        address currentOwner = owner();
        require(currentOwner != address(this), "Token in ownership chain");
        uint256 depth = 0;
        while (currentOwner.code.length > 0) {
            try IERC6551Account(payable(currentOwner)).token() returns (
                uint256 chainId, address contractAddress, uint256 tokenId
            ) {
                require(
                    chainId != block.chainid || contractAddress != receivedTokenAddress || tokenId != receivedTokenId,
                    "Token in ownership chain"
                );
                // Advance up the ownership chain
                currentOwner = IERC721(contractAddress).ownerOf(tokenId);
                require(currentOwner != address(this), "Token in ownership chain");
            } catch {
                break;
            }
            unchecked {
                ++depth;
            }
            if (depth == 5) revert("Ownership chain too deep");
        }
    }
}
