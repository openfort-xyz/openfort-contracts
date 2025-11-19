// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {IBaseRecoverableAccount} from "contracts/interfaces/IBaseRecoverableAccount.sol";
import {IERC165} from "node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {IERC721Receiver} from "node_modules/@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC777Recipient} from "node_modules/@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import {IERC1155Receiver} from "node_modules/@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract AccountTest is Deploy {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
    }

    function test_SupportsInterface() external {
        IBaseRecoverableAccount account = IBaseRecoverableAccount(payable(address(_RandomOwnerSC)));
        assertTrue(account.supportsInterface(type(IERC721Receiver).interfaceId));
        assertTrue(account.supportsInterface(type(IERC777Recipient).interfaceId));
        assertTrue(account.supportsInterface(type(IERC1155Receiver).interfaceId));
        assertTrue(account.supportsInterface(type(IERC165).interfaceId));
        assertFalse(account.supportsInterface(bytes4(0x0000)));
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
}