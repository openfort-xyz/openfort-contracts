// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {MessageHashUtils} from "lib/oz-v5.4.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseOpenfortAccount} from "contracts/coreV9/base/BaseOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {SocialRecoveryHelper} from "test/foundry/UpgradeToEPv9/helpers/SocialRecoveryHelper.t.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract GettersTest is SocialRecoveryHelper {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address internal _NewOwner;
    uint256 internal _NewOwnerPK;

    address internal SK;
    uint256 internal SK_PK;

    uint48 private constant VALID_AFTER = 0;
    uint48 private VALID_UNTIL;
    uint48 private constant LIMIT = 10;

    RandomOwner internal randomOwner;

    function setUp() public override {
        super.setUp();
        VALID_UNTIL = uint48(block.timestamp + 10 days);
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (_NewOwner, _NewOwnerPK) = makeAddrAndKey("_NewOwner");
        (SK, SK_PK) = makeAddrAndKey("sessionKey");
        (_RecoveryOwner, _RecoveryOwnerPK) = makeAddrAndKey("_RecoveryOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
        randomOwner = RandomOwner(_RandomOwner, _RandomOwnerSC);
    }

    function test_GetOwner() external {
        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
    }

    function test_GetOwnerAfterTransferOwnership() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
        assertEq(_RandomOwnerSC.pendingOwner(), _NewOwner);

        vm.prank(_NewOwner);
        _RandomOwnerSC.acceptOwnership();

        assertEq(_RandomOwnerSC.owner(), _NewOwner);
        assertEq(_RandomOwnerSC.pendingOwner(), address(0));
    }

    function test_GetPendingOwnerNoPending() external {
        assertEq(_RandomOwnerSC.pendingOwner(), address(0));
    }

    function test_GetPendingOwnerDuringTransfer() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        assertEq(_RandomOwnerSC.pendingOwner(), _NewOwner);
    }

    function test_GetPendingOwnerAfterAccept() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        vm.prank(_NewOwner);
        _RandomOwnerSC.acceptOwnership();

        assertEq(_RandomOwnerSC.pendingOwner(), address(0));
    }

    function test_GetEntryPoint() external {
        assertEq(address(_RandomOwnerSC.entryPoint()), address(entryPointV9));
    }

    function test_GetDepositAfterDeposit() external {
        uint256 deposit = _RandomOwnerSC.getDeposit();
        assertTrue(deposit > 0);
    }

    function test_GetDepositReturnsValue() external {
        uint256 deposit = _RandomOwnerSC.getDeposit();
        assertTrue(deposit >= 0);
    }

    function test_GetNonceInitial() external {
        uint256 nonce = _RandomOwnerSC.getNonce();
        assertEq(nonce, 1);
    }

    function test_GetNonceAfterUserOp() external {
        uint256 nonceBefore = _RandomOwnerSC.getNonce();

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = hex"";
        userOp = _populateUserOpV9(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);

        uint256 nonceAfter = _RandomOwnerSC.getNonce();
        assertEq(nonceAfter, nonceBefore + 1);
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

    function _registerMasterSessionKey() internal {
        vm.prank(_RandomOwner);
        address[] memory emptyWhitelist = new address[](0);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, VALID_UNTIL, type(uint48).max, emptyWhitelist);
    }

    function _registerLimitedSessionKey() internal {
        vm.prank(_RandomOwner);
        address[] memory whitelist = new address[](1);
        whitelist[0] = address(erc20);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, VALID_UNTIL, LIMIT, whitelist);
    }

    function _signMessage(bytes32 _hash, uint256 _privateKey) internal view returns (bytes memory) {
        bytes32 OF_MSG_TYPEHASH = 0x57159f03b9efda178eab2037b2ec0b51ce11be0051b8a2a9992c29dc260e4a30;
        bytes32 structHash = keccak256(abi.encode(OF_MSG_TYPEHASH, _hash));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Openfort")),
                keccak256(bytes("0.9")),
                block.chainid,
                address(_RandomOwnerSC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
