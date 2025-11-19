// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";
import {UserOperation} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";

contract FactoryTest is Deploy {
    address internal _RandomOwner;
    address internal _RandomOwnerSC;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
    }

    function test_CreateNewAccountWithEPv6() external {
        _RandomOwnerSC = openfortFactoryV6.getAddressWithNonce(_RandomOwner, _RandomOwnerSalt);

        _depositTo(_RandomOwner, _RandomOwnerSC, EP_Version.V6);
        _sendAssetsToSC(_RandomOwner, _RandomOwnerSC);

        UserOperation memory userOp;
        (userOp,) = _getFreshUserOp(_RandomOwnerSC);

        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xbabe), 0.1 ether, hex"");
        userOp = _populateUserOpV6(userOp, callData, 400_000, 600_000, 800_000, 15 gwei, 80 gwei, hex"");

        bytes memory initCode = abi.encodeWithSignature(
            "createAccountWithNonce(address,bytes32,bool)", _RandomOwner, _RandomOwnerSalt, false
        );
        userOp.initCode = abi.encodePacked(address(openfortFactoryV6), initCode);
        bytes32 userOpHash = _getUserOpHashV6(userOp);

        console.log(vm.toString(userOpHash));

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        entryPointV6.handleOps(ops, payable(_OpenfortAdmin));

        assertEq(address(0xbabe).balance, 0.1 ether);
    }

    function test_CreateNewAccountWithEPv9() external {
        _RandomOwnerSC = openfortFactoryV9.getAddressWithNonce(_RandomOwner, _RandomOwnerSalt);

        _depositTo(_RandomOwner, _RandomOwnerSC, EP_Version.V9);
        _sendAssetsToSC(_RandomOwner, _RandomOwnerSC);

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(_RandomOwnerSC);

        bytes memory callData =
            abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xbabe), 0.1 ether, hex"");
        userOp = _populateUserOpV9(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        bytes memory initCode = abi.encodeWithSignature(
            "createAccountWithNonce(address,bytes32,bool)", _RandomOwner, _RandomOwnerSalt, false
        );
        userOp.initCode = abi.encodePacked(address(openfortFactoryV9), initCode);
        bytes32 userOpHash = _getUserOpHashV9(userOp);

        console.log(vm.toString(userOpHash));

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));

        assertEq(address(0xbabe).balance, 0.1 ether);
    }

    function test_CreateAccountWithNonceViaFactoryV6() external {
        vm.prank(_OpenfortAdmin);
        address accountAddress2 = openfortFactoryV6.getAddressWithNonce(_OpenfortAdmin, "2");

        vm.expectEmit(true, true, false, true);
        emit AccountCreated(accountAddress2, _OpenfortAdmin);

        vm.prank(_OpenfortAdmin);
        openfortFactoryV6.createAccountWithNonce(_OpenfortAdmin, "2", true);

        vm.prank(_OpenfortAdmin);
        openfortFactoryV6.createAccountWithNonce(_OpenfortAdmin, "2", true);
        
        vm.prank(_OpenfortAdmin);
        assertEq(accountAddress2, openfortFactoryV6.getAddressWithNonce(_OpenfortAdmin, "2"));
    }

    function test_CreateAccountWithNonceViaFactoryV9() external {
        vm.prank(_OpenfortAdmin);
        address accountAddress2 = openfortFactoryV9.getAddressWithNonce(_OpenfortAdmin, "2");

        vm.expectEmit(true, true, false, true);
        emit AccountCreated(accountAddress2, _OpenfortAdmin);

        vm.prank(_OpenfortAdmin);
        openfortFactoryV9.createAccountWithNonce(_OpenfortAdmin, "2", true);

        vm.prank(_OpenfortAdmin);
        openfortFactoryV9.createAccountWithNonce(_OpenfortAdmin, "2", true);
        
        vm.prank(_OpenfortAdmin);
        assertEq(accountAddress2, openfortFactoryV9.getAddressWithNonce(_OpenfortAdmin, "2"));
    }
}
