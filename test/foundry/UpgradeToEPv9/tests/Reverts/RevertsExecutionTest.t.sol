// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract RevertingContract {
    error CustomRevertError();

    function revertWithCustomError() external pure {
        revert CustomRevertError();
    }

    function revertWithMessage() external pure {
        revert("Target reverted");
    }
}

contract RevertsExecutionTest is Deploy {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address internal _Attacker;
    uint256 internal _AttackerPK;

    RevertingContract internal revertingContract;

    error NotOwnerOrEntrypoint();
    error InvalidParameterLength();

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (_Attacker, _AttackerPK) = makeAddrAndKey("_Attacker");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);

        revertingContract = new RevertingContract();
    }

    function test_revert_execute_notOwnerOrEntrypoint() external {
        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.execute(address(0xbabe), 0.01 ether, hex"");
    }

    function test_revert_execute_targetCallReverts() external {
        vm.prank(_RandomOwner);
        vm.expectRevert(RevertingContract.CustomRevertError.selector);
        _RandomOwnerSC.execute(
            address(revertingContract), 0, abi.encodeWithSelector(RevertingContract.revertWithCustomError.selector)
        );
    }

    function test_revert_execute_targetCallRevertsWithMessage() external {
        vm.prank(_RandomOwner);
        vm.expectRevert("Target reverted");
        _RandomOwnerSC.execute(
            address(revertingContract), 0, abi.encodeWithSelector(RevertingContract.revertWithMessage.selector)
        );
    }

    function test_revert_execute_insufficientBalance() external {
        vm.prank(_RandomOwner);
        vm.expectRevert();
        _RandomOwnerSC.execute(address(0xbabe), 1000 ether, hex"");
    }

    function test_revert_executeAA_notOwner() external {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteCall(address(0xbabe), 0.01 ether, hex""),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _AttackerPK);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        vm.expectRevert();
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));
    }

    function test_revert_executeAA_targetCallReverts() external {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData =
            abi.encodeWithSelector(RevertingContract.revertWithCustomError.selector);

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteCall(address(revertingContract), 0, callData),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
    }

    function test_revert_executeAA_insufficientBalance() external {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteCall(address(0xbabe), 1000 ether, hex""),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
    }

    function test_revert_executeBatch_notOwnerOrEntrypoint() external {
        address[] memory targets = new address[](2);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);

        uint256[] memory values = new uint256[](2);
        values[0] = 0.01 ether;
        values[1] = 0.01 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = hex"";
        datas[1] = hex"";

        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.executeBatch(targets, values, datas);
    }

    function test_revert_executeBatch_arrayLengthMismatchTargetsValues() external {
        address[] memory targets = new address[](3);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);
        targets[2] = address(0xbeef);

        uint256[] memory values = new uint256[](2);
        values[0] = 0.01 ether;
        values[1] = 0.01 ether;

        bytes[] memory datas = new bytes[](3);
        datas[0] = hex"";
        datas[1] = hex"";
        datas[2] = hex"";

        vm.prank(_RandomOwner);
        vm.expectRevert(InvalidParameterLength.selector);
        _RandomOwnerSC.executeBatch(targets, values, datas);
    }

    function test_revert_executeBatch_arrayLengthMismatchTargetsDatas() external {
        address[] memory targets = new address[](3);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);
        targets[2] = address(0xbeef);

        uint256[] memory values = new uint256[](3);
        values[0] = 0.01 ether;
        values[1] = 0.01 ether;
        values[2] = 0.01 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = hex"";
        datas[1] = hex"";

        vm.prank(_RandomOwner);
        vm.expectRevert(InvalidParameterLength.selector);
        _RandomOwnerSC.executeBatch(targets, values, datas);
    }

    function test_revert_executeBatch_tooManyCalls() external {
        address[] memory targets = new address[](10);
        uint256[] memory values = new uint256[](10);
        bytes[] memory datas = new bytes[](10);

        for (uint256 i = 0; i < 10;) {
            targets[i] = address(0xbabe);
            values[i] = 0.01 ether;
            datas[i] = hex"";
            unchecked {
                ++i;
            }
        }

        vm.prank(_RandomOwner);
        vm.expectRevert(InvalidParameterLength.selector);
        _RandomOwnerSC.executeBatch(targets, values, datas);
    }

    function test_revert_executeBatch_oneCallFails() external {
        address[] memory targets = new address[](3);
        targets[0] = address(0xbabe);
        targets[1] = address(revertingContract);
        targets[2] = address(0xbeef);

        uint256[] memory values = new uint256[](3);
        values[0] = 0;
        values[1] = 0;
        values[2] = 0;

        bytes[] memory datas = new bytes[](3);
        datas[0] = hex"";
        datas[1] = abi.encodeWithSelector(RevertingContract.revertWithMessage.selector);
        datas[2] = hex"";

        vm.prank(_RandomOwner);
        vm.expectRevert("Target reverted");
        _RandomOwnerSC.executeBatch(targets, values, datas);
    }

    function test_revert_executeBatch_insufficientBalance() external {
        address[] memory targets = new address[](2);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);

        uint256[] memory values = new uint256[](2);
        values[0] = 100 ether;
        values[1] = 100 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = hex"";
        datas[1] = hex"";

        vm.prank(_RandomOwner);
        vm.expectRevert();
        _RandomOwnerSC.executeBatch(targets, values, datas);
    }

    function test_revert_executeBatchAA_notOwner() external {
        address[] memory targets = new address[](2);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);

        uint256[] memory values = new uint256[](2);
        values[0] = 0.01 ether;
        values[1] = 0.01 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = hex"";
        datas[1] = hex"";

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(targets, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _AttackerPK);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        vm.expectRevert();
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));
    }

    function test_revert_executeBatchAA_arrayLengthMismatch() external {
        address[] memory targets = new address[](3);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);
        targets[2] = address(0xbeef);

        uint256[] memory values = new uint256[](2);
        values[0] = 0.01 ether;
        values[1] = 0.01 ether;

        bytes[] memory datas = new bytes[](3);
        datas[0] = hex"";
        datas[1] = hex"";
        datas[2] = hex"";

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(targets, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
    }

    function test_revert_executeBatchAA_tooManyCalls() external {
        address[] memory targets = new address[](10);
        uint256[] memory values = new uint256[](10);
        bytes[] memory datas = new bytes[](10);

        for (uint256 i = 0; i < 10;) {
            targets[i] = address(0xbabe);
            values[i] = 0.01 ether;
            datas[i] = hex"";
            unchecked {
                ++i;
            }
        }

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(targets, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
    }


    function test_revert_executeBatchAA_oneCallFails() external {
        address[] memory targets = new address[](3);
        targets[0] = address(0xbabe);
        targets[1] = address(revertingContract);
        targets[2] = address(0xbeef);

        uint256[] memory values = new uint256[](3);
        values[0] = 0;
        values[1] = 0;
        values[2] = 0;

        bytes[] memory datas = new bytes[](3);
        datas[0] = hex"";
        datas[1] = abi.encodeWithSelector(RevertingContract.revertWithCustomError.selector);
        datas[2] = hex"";

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(targets, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
    }

    function test_revert_executeBatchAA_insufficientBalance() external {
        address[] memory targets = new address[](2);
        targets[0] = address(0xbabe);
        targets[1] = address(0xdead);

        uint256[] memory values = new uint256[](2);
        values[0] = 100 ether;
        values[1] = 100 ether;

        bytes[] memory datas = new bytes[](2);
        datas[0] = hex"";
        datas[1] = hex"";

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(targets, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
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
