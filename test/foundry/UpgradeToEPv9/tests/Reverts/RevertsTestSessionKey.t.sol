// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "lib/account-abstraction-v09/contracts/interfaces/IEntryPoint.sol";
import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract RevertsTestSessionKey is Deploy {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address internal _SessionKey;
    uint256 internal _SessionKeyPK;
    address internal _MasterSessionKey;
    uint256 internal _MasterSessionKeyPK;

    address internal _Attacker;
    address internal _Target;

    uint48 internal constant MAX_LIMIT = type(uint48).max;

    error NotOwnerOrEntrypoint();

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (_SessionKey, _SessionKeyPK) = makeAddrAndKey("_SessionKey");
        (_MasterSessionKey, _MasterSessionKeyPK) = makeAddrAndKey("_MasterSessionKey");
        _Attacker = makeAddr("_Attacker");
        _Target = makeAddr("_Target");
        _deal(_RandomOwner, 5 ether);
        _deal(_Target, 1 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
    }

    function test_revert_registerSessionKey_notOwner() external {
        address[] memory whitelist = new address[](0);

        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(0),
            uint48(block.timestamp + 1 days),
            100,
            whitelist
        );
    }

    function test_revert_registerSessionKey_invalidTimeRange() external {
        address[] memory whitelist = new address[](0);

        vm.prank(_RandomOwner);
        vm.expectRevert("_validAfter must be lower than _validUntil");
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(block.timestamp + 2 days),
            uint48(block.timestamp + 1 days),
            100,
            whitelist
        );
    }

    function test_revert_registerSessionKey_alreadyRegistered() external {
        address[] memory whitelist = new address[](0);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(0),
            uint48(block.timestamp + 1 days),
            100,
            whitelist
        );

        vm.prank(_RandomOwner);
        vm.expectRevert("SessionKey already registered");
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(block.timestamp),
            uint48(block.timestamp + 2 days),
            200,
            whitelist
        );
    }

    function test_revert_registerSessionKey_expired() external {
        address[] memory whitelist = new address[](0);

        vm.warp(block.timestamp + 10 days);

        vm.prank(_RandomOwner);
        vm.expectRevert("Cannot register an expired session key");
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(1),
            uint48(block.timestamp - 1),
            100,
            whitelist
        );
    }

    function test_revert_registerSessionKey_whitelistTooBig() external {
        address[] memory whitelist = new address[](11);
        for (uint256 i = 0; i < 11; i++) {
            whitelist[i] = address(uint160(i + 1));
        }

        vm.prank(_RandomOwner);
        vm.expectRevert("Whitelist too big");
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(0),
            uint48(block.timestamp + 1 days),
            100,
            whitelist
        );
    }

    function test_registerSessionKey_limitedKey() external {
        address[] memory whitelist = new address[](0);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(0),
            uint48(block.timestamp + 1 days),
            100,
            whitelist
        );

        (uint48 validAfter, uint48 validUntil, uint48 limit, bool master,,) = _RandomOwnerSC.sessionKeys(_SessionKey);
        assertEq(validAfter, uint48(0));
        assertEq(validUntil, uint48(block.timestamp + 1 days));
        assertEq(limit, 100);
        assertFalse(master);
    }

    function test_registerSessionKey_masterKey() external {
        address[] memory whitelist = new address[](0);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.registerSessionKey(
            _MasterSessionKey,
            uint48(0),
            uint48(block.timestamp + 1 days),
            MAX_LIMIT,
            whitelist
        );

        (,,, bool master,,) = _RandomOwnerSC.sessionKeys(_MasterSessionKey);
        assertTrue(master);
    }

    function test_registerSessionKey_whitelistedKey() external {
        address[] memory whitelist = new address[](2);
        whitelist[0] = _Target;
        whitelist[1] = address(erc20);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.registerSessionKey(
            _SessionKey,
            uint48(0),
            uint48(block.timestamp + 1 days),
            100,
            whitelist
        );

        (,,,, bool whitelisting,) = _RandomOwnerSC.sessionKeys(_SessionKey);
        assertTrue(whitelisting);
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
    }

    function _relayUserOpV9(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));
    }
}
