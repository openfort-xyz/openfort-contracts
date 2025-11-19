// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {IERC20} from "lib/oz-v5.4.0/contracts/token/ERC20/IERC20.sol";
import {BaseOpenfortAccount} from "contracts/coreV9/base/BaseOpenfortAccount.sol";
import {IBaseRecoverableAccount} from "contracts/interfaces/IBaseRecoverableAccount.sol";
import {IERC165} from "node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";

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

    uint256 private _SC_BALANCE_BEFORE;
    uint256 private _SC_BALANCE_AFTER;
    uint256 private _SC_RECIVER_BEFORE;
    uint256 private _SC_RECIVER_AFTER;

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

    function test_RegisterMKDirect() external {
        _registerKey(true);
        _assertRegistratedKey(SK, true);
    }

    function test_RegisterSKDirect() external {
        _registerKey(false);
        _assertRegistratedKey(SK, false);
    }

    function test_RegisterMKAA() external {
        _registerKeyAA(true);
        _assertRegistratedKey(SK, true);
    }

    function test_RegisterSKAA() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false);
    }

    function test_RevokeMKDirect() external {
        _registerKeyAA(true);
        _assertRegistratedKey(SK, true);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.revokeSessionKey(SK);

        _assertRevokationSK(SK);
    }

    function test_RevokeSKDirect() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false);

        vm.prank(_RandomOwner);
        _RandomOwnerSC.revokeSessionKey(SK);

        _assertRevokationSK(SK);
    }

    function test_RevokeMKAA() external {
        _registerKeyAA(true);
        _assertRegistratedKey(SK, true);

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

    function test_RevokeSKAA() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false); 

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

    function test_SendEthToAnyAddressWithMKAA() external {
        _registerKeyAA(true);
        _assertRegistratedKey(SK, true);
        _deal(address(_RandomOwnerSC), 5 ether);
        _assertBalances(address(0xdeadbabe), true, 0.01 ether);
    
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteCall(address(0xdeadbabe), 0.01 ether, hex""),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, SK_PK);

        _relayUserOpV9(userOp);
        _assertBalances(address(0xdeadbabe), false, 0.01 ether);
    }

    function test_SendEthToAnyAddressWithSKAA() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false); 
        _deal(address(_RandomOwnerSC), 5 ether);
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

        userOp.signature = _signUserOp(userOpHash, SK_PK);

        _relayUserOpV9(userOp);
        _assertBalances(address(0xbabe), false, 0.01 ether);
    }

    function test_SendBatchEthToAnyAddressWithSKAA() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false); 
        _deal(address(_RandomOwnerSC), 5 ether);
        _assertBalances(address(0xbabe), true, 0.01 ether);
    
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

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
        
        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(addrs, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, SK_PK);

        _relayUserOpV9(userOp);
        _assertBalances(address(0xbabe), false, 0.01 ether * 5);
    }

    function test_SendERC20ToAnyAddressWithSKAA() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false); 
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

        userOp.signature = _signUserOp(userOpHash, SK_PK);

        _relayUserOpV9(userOp);
        _assertBalancesERC20(address(0xbabe), false, 5 ether);
    }

    function test_SendBatchERC20ToAnyAddressWithSKAA() external {
        _registerKeyAA(false);
        _assertRegistratedKey(SK, false); 
        _mint(address(_RandomOwnerSC), 100 ether);
        _assertBalancesERC20(address(0xbabe), true, 0.01 ether);
    
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

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

        userOp = _populateUserOpV9(
            userOp,
            _createExecuteBatchCall(addrs, values, datas),
            _packAccountGasLimits(400_000, 600_000),
            800_000,
            _packGasFees(15 gwei, 80 gwei),
            hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, SK_PK);

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

    function _registerKey(bool _isMK) internal {
        address[] memory whitelist;
        if (!_isMK){ 
            whitelist = new address[](1);
            whitelist[0] = (address(erc20));
        }

        uint48 limits = _isMK ? type(uint48).max : LIMIT;

        vm.prank(_RandomOwner);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, VALID_UNTIL, limits, whitelist);
    }

    function _registerKeyAA(bool _isMK) internal {
        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        address[] memory whitelist;

        if (!_isMK) {
            whitelist = new address[](2);
            whitelist[0] = (address(erc20));
            whitelist[1] = address(0xbabe);
        }

        uint48 limits = _isMK ? type(uint48).max : LIMIT;

        bytes memory callData = abi.encodeWithSelector(_RandomOwnerSC.registerSessionKey.selector, SK, VALID_AFTER, VALID_UNTIL, limits, whitelist);

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

    function _assertRegistratedKey(address _sK, bool _isMK) internal {
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
        if (!_isMK) {
            assertEq(limit, LIMIT);
            assertEq(masterSessionKey, false);
            assertEq(whitelisting, true);
        } else {
            assertEq(limit, type(uint48).max);
            assertEq(masterSessionKey, true);
            assertEq(whitelisting, false);
        }

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
