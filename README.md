# Openfort Contracts
Official Contracts of the Openfort Project

## Running all Foundry tests

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed. Then:

```
forge install
forge build
forge test
```


## Use different built-in scripts

Before executing any of the scripts below, make sure you've properly configured your `.env` file.

### Generate a gas report

```
./script/gasProfile.sh
```

### Check paymaster's deposit on different chains

```
forge script CheckPaymasterDeposit
```

### Deploy one static factory and one account

Simulation:

```
forge script StaticOpenfortDeploy --fork-url $<rpc_network>
```

Actual deployment:

```
forge script StaticOpenfortDeploy --fork-url $<rpc_network> --verify --broadcast
```

### Deploy one upgradeable factory and one account

Simulation:

```
forge script UpgradeableOpenfortDeploy --fork-url $<rpc_network>
```

Actual deployment:
```
forge script UpgradeableOpenfortDeploy --fork-url $<rpc_network> --verify --broadcast
```
