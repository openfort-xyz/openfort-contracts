// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC6551Account} from "erc6551/src/interfaces/IERC6551Account.sol";
import {IERC6551Executable} from "erc6551/src/interfaces/IERC6551Executable.sol";
import {ERC6551AccountLib} from "erc6551/src/lib/ERC6551AccountLib.sol";

import {BaseOpenfortAccount, IEntryPoint, ECDSAUpgradeable} from "../BaseOpenfortAccount.sol";

/**
 * @title EIP6551OpenfortAccount (Non-upgradeable)
 * @notice Smart contract wallet with session keys following the ERC-4337 and EIP-6551 standards.
 * It inherits from:
 *  - BaseOpenfortAccount to comply with ERC-4337
 *  - IERC6551Account to have permissions using ERC-721 tokens
 *  - IERC6551Executable
 */
contract EIP6551OpenfortAccount is BaseOpenfortAccount, IERC6551Account, IERC6551Executable {
    using ECDSAUpgradeable for bytes32;

    address internal entrypointContract;

    // bytes4(keccak256("execute(address,uint256,bytes,uint8)")
    bytes4 internal constant EXECUTE_ERC6551_SELECTOR = 0x51945447;

    uint256 public state;

    error OperationNotAllowed();

    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);

    receive() external payable override(BaseOpenfortAccount, IERC6551Account) {}

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _entrypoint) public initializer {
        if (_entrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        emit EntryPointUpdated(entrypointContract, _entrypoint);
        entrypointContract = _entrypoint;
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
        ++state;
        bool success;
        (success, _result) = _target.call{value: _value}(_data);
        require(success, string(_result));
        return _result;
    }

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address _dest, uint256 _value, bytes calldata _func) public override {
        ++state;
        super.execute(_dest, _value, _func);
    }

    /**
     * Execute a sequence of transactions. Maximum 9.
     */
    function executeBatch(address[] calldata _target, uint256[] calldata _value, bytes[] calldata _calldata)
        public
        override
    {
        state += _target.length;
        super.executeBatch(_target, _value, _calldata);
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external {
        if (_newEntrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _requireFromOwner();
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

    function supportsInterface(bytes4 _interfaceId) public pure override returns (bool) {
        return (
            _interfaceId == type(IERC6551Account).interfaceId || _interfaceId == type(IERC6551Executable).interfaceId
                || _interfaceId == type(IERC1155Receiver).interfaceId || _interfaceId == type(IERC721Receiver).interfaceId
                || _interfaceId == type(IERC165).interfaceId
        );
    }
}
