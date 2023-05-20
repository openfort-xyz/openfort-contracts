# Openfort Contracts
Official Contracts of the Openfort Project

## Running all Foundry tests

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed. Then:

```
forge install
forge build
forge test
```

Deployment of one static factory and account:

```
forge script script/deployStaticAccounts.sol --fork-url $POLYGON_MUMBAI_RPC -vvvvv --verify --broadcast
```

Deployment of one upgradeable factory and account:

```
forge script script/deployUpgradeableAccounts.sol.sol --fork-url $POLYGON_MUMBAI_RPC -vvvvv --verify --broadcast
```
