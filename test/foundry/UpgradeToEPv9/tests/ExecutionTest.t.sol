// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {IERC20} from "lib/oz-v5.4.0/contracts/token/ERC20/IERC20.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";

contract ExecutionTest is Deploy {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    uint256 private _SC_BALANCE_BEFORE;
    uint256 private _SC_BALANCE_AFTER;
    uint256 private _SC_RECIVER_BEFORE;
    uint256 private _SC_RECIVER_AFTER;

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
    }

    function test_ReciveETH() external {
        _SC_BALANCE_BEFORE = address(_RandomOwnerSC).balance;

        address random = makeAddr("random");
        _deal(random, 1 ether);

        vm.prank(random);
        (bool res,) = address(_RandomOwnerSC).call{value: 0.5 ether}("");
        if (!res) revert("BAD CALL!!!");
        _SC_BALANCE_AFTER = address(_RandomOwnerSC).balance;

        assertEq(_SC_BALANCE_BEFORE + 0.5 ether, _SC_BALANCE_AFTER);
    }

    function test_SendEthToAnyAddressDirect() external {
        _assertBalances(address(0xbabe), true, 0.01 ether);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.execute(address(0xbabe), 0.01 ether, hex"");

        _assertBalances(address(0xbabe), false, 0.01 ether);
    }

    function test_SendEthToAnyAddressAA() external {
        _assertBalances(address(0xbabe), true, 0.01 ether);

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

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
        _assertBalances(address(0xbabe), false, 0.01 ether);
    }

    function test_SendBatchEthToAnyAddressDirect() external {
        _assertBalances(address(0xbabe), true, 0.01 ether);

        address[] memory addrs = new address[](5);
        uint256[] memory values = new uint256[](5);
        bytes[] memory datas = new bytes[](5);

        for (uint256 i = 0; i < 5;) {
            addrs[i] = address(0xbabe);
            values[i] = 0.01 ether;
            datas[i] = hex"";
            unchecked {
                ++i;
            }
        }

        vm.prank(_RandomOwner);
        _RandomOwnerSC.executeBatch(addrs, values, datas);

        _assertBalances(address(0xbabe), false, 0.01 ether * 5);
    }

    function test_SendBatchEthToAnyAddressAA() external {
        _assertBalances(address(0xbabe), true, 0.01 ether);

        address[] memory addrs = new address[](5);
        uint256[] memory values = new uint256[](5);
        bytes[] memory datas = new bytes[](5);

        for (uint256 i = 0; i < 5;) {
            addrs[i] = address(0xbabe);
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
            _createExecuteBatchCall(addrs, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
        _assertBalances(address(0xbabe), false, 0.01 ether * 5);
    }

    function test_ReciveERC20() external {
        _SC_BALANCE_BEFORE = IERC20(erc20).balanceOf(address(_RandomOwnerSC));

        address random = makeAddr("random");
        _mint(random, 100 ether);

        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(_RandomOwnerSC), 5 ether);

        vm.prank(random);
        (bool res,) = address(erc20).call{value: 0}(callData);
        if (!res) revert("BAD CALL!!!");
        _SC_BALANCE_AFTER = IERC20(erc20).balanceOf(address(_RandomOwnerSC));

        assertEq(_SC_BALANCE_BEFORE + 5 ether, _SC_BALANCE_AFTER);
    }

    function test_SendERC20ToAnyAddressDirect() external {
        _mint(address(_RandomOwnerSC), 100 ether);
        _assertBalancesERC20(address(0xbabe), true, 0.01 ether);

        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(0xbabe), 5 ether);
        vm.prank(_RandomOwner);
        _RandomOwnerSC.execute(address(erc20), 0 ether, callData);

        _assertBalancesERC20(address(0xbabe), false, 5 ether);
    }

    function test_SendERC20ToAnyAddressAA() external {
        _mint(address(_RandomOwnerSC), 100 ether);
        _assertBalancesERC20(address(0xbabe), true, 0.01 ether);

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(0xbabe), 5 ether);

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteCall(address(erc20), 0, callData),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
        _assertBalancesERC20(address(0xbabe), false, 5 ether);
    }

    function test_SendBatchERC20ToAnyAddressDirect() external {
        _mint(address(_RandomOwnerSC), 100 ether);
        _assertBalancesERC20(address(0xbabe), true, 0.01 ether);

        address[] memory addrs = new address[](5);
        uint256[] memory values = new uint256[](5);
        bytes[] memory datas = new bytes[](5);

        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(0xbabe), 5 ether);

        for (uint256 i = 0; i < 5;) {
            addrs[i] = address(erc20);
            values[i] = 0;
            datas[i] = callData;
            unchecked {
                ++i;
            }
        }

        vm.prank(_RandomOwner);
        _RandomOwnerSC.executeBatch(addrs, values, datas);

        _assertBalancesERC20(address(0xbabe), false, 5 ether * 5);
    }

    function test_SendBatchERC20ToAnyAddressAA() external {
        _mint(address(_RandomOwnerSC), 100 ether);
        _assertBalancesERC20(address(0xbabe), true, 0.01 ether);

        address[] memory addrs = new address[](5);
        uint256[] memory values = new uint256[](5);
        bytes[] memory datas = new bytes[](5);

        bytes memory callData = abi.encodeWithSignature("transfer(address,uint256)", address(0xbabe), 5 ether);

        for (uint256 i = 0; i < 5;) {
            addrs[i] = address(erc20);
            values[i] = 0;
            datas[i] = callData;
            unchecked {
                ++i;
            }
        }

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
        _assertBalancesERC20(address(0xbabe), false, 5 ether * 5);
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

    function _assertBalances(address _reciver, bool _isBefore, uint256 _expectedTransferAmount) internal {
        if (_isBefore) {
            _SC_BALANCE_BEFORE = address(_RandomOwnerSC).balance;
            _SC_RECIVER_BEFORE = _reciver.balance;
            assertEq(_SC_BALANCE_BEFORE, 5 ether);
            assertEq(_SC_RECIVER_BEFORE, 0);
        } else {
            _SC_BALANCE_AFTER = address(_RandomOwnerSC).balance;
            _SC_RECIVER_AFTER = _reciver.balance;

            assertEq(
                _SC_RECIVER_AFTER - _SC_RECIVER_BEFORE, _expectedTransferAmount, "Receiver didn't get expected amount"
            );

            uint256 scLoss = _SC_BALANCE_BEFORE - _SC_BALANCE_AFTER;
            assertGe(scLoss, _expectedTransferAmount, "SC didn't lose enough (less than transfer amount)");

            uint256 gasFees = scLoss - _expectedTransferAmount;
            assertLt(gasFees, 0.1 ether, "Gas fees unexpectedly high");
        }
    }

    function _assertBalancesERC20(address _reciver, bool _isBefore, uint256 _expectedTransferAmount) internal {
        if (_isBefore) {
            _SC_BALANCE_BEFORE = IERC20(erc20).balanceOf(address(_RandomOwnerSC));
            _SC_RECIVER_BEFORE = IERC20(erc20).balanceOf(_reciver);
            assertEq(_SC_BALANCE_BEFORE, 100 ether);
            assertEq(_SC_RECIVER_BEFORE, 0);
        } else {
            _SC_BALANCE_AFTER = IERC20(erc20).balanceOf(address(_RandomOwnerSC));
            _SC_RECIVER_AFTER = IERC20(erc20).balanceOf(_reciver);

            assertEq(
                _SC_RECIVER_AFTER - _SC_RECIVER_BEFORE, _expectedTransferAmount, "Receiver didn't get expected amount"
            );

            uint256 scLoss = _SC_BALANCE_BEFORE - _SC_BALANCE_AFTER;
            assertGe(scLoss, _expectedTransferAmount, "SC didn't lose enough (less than transfer amount)");

            uint256 gasFees = scLoss - _expectedTransferAmount;
            assertLt(gasFees, 0.1 ether, "Gas fees unexpectedly high");
        }
    }
}
