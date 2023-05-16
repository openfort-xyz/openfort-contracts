# Openfort Contracts
Official Contracts of the Openfort Project

## For Unit and Integration Testing

Make sure [Hardhat](https://hardhat.org/hardhat-runner/docs/getting-started#installation) is installed. Then:

```
hh compile
hh test
```

## For Fuzzing Testing

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed. Then:

```
forge install
forge build
forge test
```

$ forge create --rpc-url https://mumbai.rpc.thirdweb.com \
    --constructor-args 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 \
    --private-key fae3df967d92ca4d3bd7d16707c014ae60a91e4f56c6cf7e0a992b5d0f2f3cf7 \
    --etherscan-api-key DCDSDJKPSHPH9HZVZH4XEQPHB7BTNE4BPE \
    --verify \
    src/core/static/StaticOpenfortAccountFactory.sol:StaticOpenfortAccountFactory
