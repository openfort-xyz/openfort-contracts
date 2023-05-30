![Firm Protocol][banner-image]

<div align="center">
  <h4>
    <a href="https://www.openfort.xyz/">
      Website
    </a>
    <span> | </span>
    <a href="https://www.openfort.xyz/docs">
      Documentation
    </a>
    <span> | </span>
    <a href="https://www.openfort.xyz/docs/api">
      API Docs
    </a>
    <span> | </span>
    <a href="https://twitter.com/openfortxyz">
      Twitter
    </a>
  </h4>
</div>

[banner-image]: .github/img/fullOpenfortRed.png


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

As of 26th of May 2023, the current average gas cost for deploying or using the different smart contracts of this project is:

|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
|   StaticOpenfortFactory  | Factory to create static accounts (containing StaticOpenfortAccount's implementation) | 1 | 2,505,952 |
|   StaticOpenfortAccount  | Creation of a new static account using the `createAccount()` of the factory | indefinite | 145,878  |
|   StaticOpenfortAccount  | Creation of a new static account using the `createAccountWithNonce()` of the factory | indefinite | 146,047  |
|   StaticOpenfortAccount  | Updating the EntryPoint address using `updateEntryPoint()` | indefinite | 1,483  |
|   StaticOpenfortAccount  | Transfering the ownership using `transferOwnership()` | indefinite | 22,375  |

|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
| UpgradeableOpenfortFactory | Factory to create upgradeable accounts (containing UpgradeableOpenfortAccount's implementation) | 1 | 3,262,120  |
|   UpgradeableOpenfortAccount  | Creation of a new upgradeable account using the `createAccount()` of the factory | indefinite | 202,604  |
|   UpgradeableOpenfortAccount  | Creation of a new upgradeable account using the `createAccountWithNonce()` of the factory | indefinite | 202,797 |
|   UpgradeableOpenfortAccount  | Updating to a new implementation using `upgradeTo()` | indefinite | 3,226  |

|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
|   OpenfortPaymaster | Paymaster to pay gas in ERC20s | 1 | 1,216,063  |
