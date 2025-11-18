// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Data} from "test/foundry/UpgradeToEPv9/Data/Data.t.sol";

abstract contract Helper is Data {
    function _deal(address _addr, uint256 _amount) internal {
        deal(_addr, _amount);
    }

    function _sendAssetsToSC(address _depositor, address _sc) internal {
        vm.prank(_depositor);
        (bool succ,) = _sc.call{value: 0.5 ether}("");
        require(succ, "Revert");
    }

    function _createExecuteCall(address _to, uint256 _value, bytes memory _data)
        internal
        pure
        returns (bytes memory callData)
    {
        callData = abi.encodeWithSignature("execute(address,uint256,bytes)", _to, _value, _data);
    }

    function _createExecuteBatchCall(address[] memory _to, uint256[] memory _value, bytes[] memory _data)
        internal
        pure
        returns (bytes memory callData)
    {
        callData = abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _to, _value, _data);
    }
}
