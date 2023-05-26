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

### Deploy Static and Upgradeable factories to all chains

```
./script/deployAllChains.sh
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

### Compare gas costs

You can compare gas costs by running the following command against different gas reports:

```
forge snapshot --silent --diff gas_reports/2023-05-24_11:52.snap.out
```

## Gas Stats

As of 26th of May 2023, the current average cost for deploying the different smart contracts of this project is:

- StaticOpenfortFactory: 2.269.483
- StaticOpenfortAccount: 1.868.978

- UpgradeableOpenfortFactory: 2.971.793
- UpgradeableOpenfortAccount: 2.228.876

- OpenfortPaymaster: 1.216.063
