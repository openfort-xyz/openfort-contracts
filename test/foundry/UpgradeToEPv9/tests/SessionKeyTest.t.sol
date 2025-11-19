// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {BaseOpenfortAccount} from "contracts/coreV9/base/BaseOpenfortAccount.sol";
import {IBaseRecoverableAccount} from "contracts/interfaces/IBaseRecoverableAccount.sol";
import {IERC165} from "node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract SessionKeyTest is Deploy {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address internal SK;
    uint256 internal SK_PK;

    uint48 private constant VALID_AFTER = 0;
    uint48 private VALID_UNTIL;
    uint48 private constant LIMIT = 10;

    function setUp() public override {
        super.setUp();
        VALID_UNTIL = uint48(block.timestamp + 10 days);
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (SK, SK_PK) = makeAddrAndKey("sessionKey");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
    }

    function test_RegisterSKDirect() external {
        _registerSKDirect();
        _assertRegistratedSK(SK);
    }

    function test_RegisterSKAA() external {
        _registerSKAA();
        _assertRegistratedSK(SK);
    }

    function test_RevokeSKDirect() external {
        _registerSKAA();
        _assertRegistratedSK(SK);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.revokeSessionKey(SK);

        _assertRevokationSK(SK);
    }
    
    function test_RevokeSKAA() external {
        _registerSKAA();
        _assertRegistratedSK(SK);

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        address[] memory whitelist = new address[](1);
        whitelist[0] = (address(erc20));

        bytes memory callData = abi.encodeWithSelector(_RandomOwnerSC.revokeSessionKey.selector, SK);

        userOp = _populateUserOpV9(
            userOp,
            callData,
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);

        _assertRevokationSK(SK);
    }

    function _createAccountV9() internal {
        address _RandomOwnerSCAddr = openfortFactoryV9.getAddressWithNonce(_RandomOwner, _RandomOwnerSalt);
        _RandomOwnerSC = UpgradeableOpenfortAccountV9(payable(_RandomOwnerSCAddr));
        _depositTo(_RandomOwner, address(_RandomOwnerSC), EP_Version.V9);
        _sendAssetsToSC(_RandomOwner, address(_RandomOwnerSC));

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = hex"";
        userOp = _populateUserOpV9(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        bytes memory initCode = abi.encodeWithSignature(
            "createAccountWithNonce(address,bytes32,bool)", _RandomOwner, _RandomOwnerSalt, false
        );
        userOp.initCode = abi.encodePacked(address(openfortFactoryV9), initCode);

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
        _assertAfterCreation();
    }

    function _relayUserOpV9(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));
    }

    function _registerSKDirect() internal {
        address[] memory whitelist = new address[](1);
        whitelist[0] = (address(erc20));
        vm.prank(_RandomOwner);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, VALID_UNTIL, LIMIT, whitelist);
    }

    function _registerSKAA() internal {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        address[] memory whitelist = new address[](1);
        whitelist[0] = (address(erc20));

        bytes memory callData = abi.encodeWithSelector(_RandomOwnerSC.registerSessionKey.selector, SK, VALID_AFTER, VALID_UNTIL, LIMIT, whitelist);

        userOp = _populateUserOpV9(
            userOp,
            callData,
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
     }

    function _assertAfterCreation() internal {
        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(address(_RandomOwnerSC)));
        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
        assertEq(proxy.implementation(), address(upgradeableOpenfortAccountImplV9));
        assertEq(address(_RandomOwnerSC.entryPoint()), address(entryPointV9));
    }

    function _assertRegistratedSK(address _sK) internal {
        (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            bool whitelisting,
            address registrarAddress
        ) = _RandomOwnerSC.sessionKeys(_sK);
        assertEq(validAfter, VALID_AFTER);
        assertEq(validUntil, VALID_UNTIL);
        assertEq(limit, LIMIT);
        assertEq(masterSessionKey, false);
        assertEq(whitelisting, true);
        assertEq(registrarAddress, _RandomOwner);
    }

    function _assertRevokationSK(address _sK) internal {
        (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            ,
            address registrarAddress
        ) = _RandomOwnerSC.sessionKeys(_sK);
        assertEq(validAfter, 0);
        assertEq(validUntil, 0);
        assertEq(limit, 0);
        assertEq(masterSessionKey, false);
        assertEq(registrarAddress, address(0));
    }
}
