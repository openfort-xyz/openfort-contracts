// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";

contract UpgradeTest is Deploy {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;
    UpgradeableOpenfortAccountV9 internal _RandomSC;

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
    }

    function test_UpgradeImplDirect() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.upgradeTo(address(upgradeableOpenfortAccountImplV6));
        _assertAfterUpdateImpl();
    }

    function test_UpgradeImplsAA() external {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = abi.encodeWithSignature("upgradeTo(address)", address(upgradeableOpenfortAccountImplV6));

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
        _assertAfterUpdateImpl();
    }

    function test_UpgradeImplDAAEveryOneReverts() external {
        (address _Random, uint256 _RandomPK) = makeAddrAndKey("_Random");
        _deal(_Random, 10 ether);

        address _RandomOwnerSCAddr = openfortFactoryV9.getAddressWithNonce(_Random, _RandomOwnerSalt);
        _RandomSC = UpgradeableOpenfortAccountV9(payable(_RandomOwnerSCAddr));
        _depositTo(_Random, address(_RandomSC), EP_Version.V9);
        _sendAssetsToSC(_Random, address(_RandomSC));

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomSC));

        bytes memory callData = abi.encodeWithSignature("upgradeTo(address)", address(upgradeableOpenfortAccountImplV6));

        userOp = _populateUserOpV9(
            userOp, _createExecuteCall(address(_RandomOwnerSC), 0, callData), _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        bytes memory initCode = abi.encodeWithSignature(
            "createAccountWithNonce(address,bytes32,bool)", _Random, _RandomOwnerSalt, false
        );
        userOp.initCode = abi.encodePacked(address(openfortFactoryV9), initCode);

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomPK);

        bytes memory revertMSG = abi.encodeWithSelector(0xbe8de9b8);
        vm.expectEmit(true, true, false, false);
        emit IEntryPoint.UserOperationRevertReason(0xa2f64c8cd99e8e978e8e5fe956484a78ef4faad0a6b2bea61aef8b67e2163dbb, 0xcac5AE5981ACBf9E11aA4bc6c703F546D3Fafcc4, 0, revertMSG);
        _relayUserOpV9(userOp);
    }

    function test_UpdateEPAddressDirect() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.updateEntryPoint(ENTRY_POINT_V6);
        _assertAfterUpdateEPAddress();
    }

    function test_UpdateEPAddressAA() external {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = abi.encodeWithSignature("updateEntryPoint(address)", ENTRY_POINT_V6);

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
        _assertAfterUpdateEPAddress();
    }

    function test_UpdateAndUpgradeDirect() external {
        bytes memory upgradeTo = abi.encodeWithSignature("upgradeTo(address)", address(upgradeableOpenfortAccountImplV6));
        bytes memory updateEntryPoint = abi.encodeWithSignature("updateEntryPoint(address)", address(entryPointV6));
        address[] memory addrs = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        addrs[0] = address(_RandomOwnerSC);
        addrs[1] = address(_RandomOwnerSC);
        values[0] = 0;
        values[1] = 0;
        datas[0] = updateEntryPoint;
        datas[1] = upgradeTo;

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(addrs, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
        _assertAfterUpdateImpl();
        _assertAfterUpdateEPAddress();
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

    function _assertAfterCreation() internal {
        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(address(_RandomOwnerSC)));
        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
        assertEq(proxy.implementation(), address(upgradeableOpenfortAccountImplV9));
        assertEq(address(_RandomOwnerSC.entryPoint()), address(entryPointV9));
    }

    function _assertAfterUpdateImpl() internal {
        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(address(_RandomOwnerSC)));
        assertEq(proxy.implementation(), address(upgradeableOpenfortAccountImplV6));
    }

    function _assertAfterUpdateEPAddress() internal {
        assertEq(address(_RandomOwnerSC.entryPoint()), address(entryPointV6));
    }
}