// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

interface IBaseOpenfortAccount is IAccount {
    error InsufficientBalance(uint256 amountRequired, uint256 currentBalance);
    error InvalidParameterLength();
    error MustSendNativeToken();
    error NotOwner();
    error NotOwnerOrEntrypoint();
    error OwnerNotAllowed();
    error ZeroAddressNotAllowed();
    error ZeroValueNotAllowed();

    event AccountImplementationDeployed(address indexed creator);
    event EIP712DomainChanged();
    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);
    event Initialized(uint8 version);
    event SessionKeyRegistered(address indexed key);
    event SessionKeyRevoked(address indexed key);

    receive() external payable;

    function addDeposit() external payable;
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
    function entryPoint() external view returns (address);
    function execute(address dest, uint256 value, bytes memory func) external payable;
    function executeBatch(address[] memory _target, uint256[] memory _value, bytes[] memory _calldata)
        external
        payable;
    function getDeposit() external view returns (uint256);
    function getNonce() external view returns (uint256);
    function isValidSessionKey(address _sessionKey, bytes memory _callData) external returns (bool);
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view returns (bytes4);
    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory)
        external
        pure
        returns (bytes4);
    function onERC1155Received(address, address, uint256, uint256, bytes memory) external pure returns (bytes4);
    function onERC721Received(address, address, uint256, bytes memory) external view returns (bytes4);
    function owner() external view returns (address);
    function registerSessionKey(
        address _key,
        uint48 _validAfter,
        uint48 _validUntil,
        uint48 _limit,
        address[] memory _whitelist
    ) external;
    function revokeSessionKey(address _key) external;
    function sessionKeys(address sessionKey)
        external
        view
        returns (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            bool whitelisting,
            address registrarAddress
        );
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function tokensReceived(address, address, address, uint256, bytes memory, bytes memory) external pure;
    function withdrawDepositTo(address payable _withdrawAddress, uint256 _amount) external;
}
