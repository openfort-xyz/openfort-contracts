![Openfort Protocol][banner-image]

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

[banner-image]: .github/img/OpenfortRed.png

# Openfort Contracts
Official Contracts of the Openfort Project

## Development

### Install [Foundry](https://github.com/foundry-rs/foundry#installation)
```
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
```

### Build and test
```
  git clone https://github.com/openfort-xyz/openfort-contracts.git && cd openfort-contracts
  yarn
  forge install
  forge build
  forge test
```

### Unit Test Coverage

You can use `Foundry` to get the unit test coverage.
Use the `lcov` report format and `genhtml` to view the coverage data in a nice web interface.
```
  forge coverage --report lcov
  genhtml -o report --branch-coverage lcov.info
```


## Use different built-in scripts

> Before executing any of the scripts below, make sure you've properly configured your `.env` file.

### Generate a gas report

```
./script/gasProfile.sh
```

### Deploy Static and Upgradeable factories to all chains

```
./script/deployAllChains.sh
```

### Check paymaster's deposit and Patron's balance on different chains

```
forge script CheckDeposits --force
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

## Static Analyzers

### Static analysis using Slither
If you want to perform a static analysis of the smart contracts using Slither, you can run the following commands:

```
  pip3 install slither-analyzer
  pip3 install solc-select
  solc-select install 0.8.19
  solc-select use 0.8.19
  slither .
```

### Static analysis using Mythril
If you want to perform a static analysis of the smart contracts using Mythril, you can run the following commands:

```
  rustup default nightly
  pip3 install mythril
  myth analyze contracts/core/static/StaticOpenfortAccount.sol --solc-json mythril.config.json
```

If you run into the error `ImportError: cannot import name 'getargspec' from 'inspect'` from Python3 running the commands above, please see the temporary fix [on this comment](https://github.com/ethereum/web3.py/issues/2704#issuecomment-1333163491).

## Gas Stats

As of May 2023, the current average gas cost for deploying or using the different smart contracts of this project is:

### Static Accounts
|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
|   StaticOpenfortFactory  | Deploy factory (containing StaticOpenfortAccount's implementation) | 1 | 2,505,952 |
|   StaticOpenfortAccount  | Create a new static account using the `createAccount()` of the factory | indefinite | 145,878  |
|   StaticOpenfortAccount  | Create a new static account using the `createAccountWithNonce()` of the factory | indefinite | 146,047  |
|   StaticOpenfortAccount  | Updating the EntryPoint address using `updateEntryPoint()` | indefinite | 1,483  |
|   StaticOpenfortAccount  | Transfering the ownership using `transferOwnership()` | indefinite | 22,375  |

### Upgradeable Accounts
|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
| UpgradeableOpenfortFactory | Deploy factory (containing UpgradeableOpenfortAccount's implementation) | 1 | 3,262,120  |
|   UpgradeableOpenfortAccount  | Create a new upgradeable account using the `createAccount()` of the factory | indefinite | 202,604  |
|   UpgradeableOpenfortAccount  | Create a new upgradeable account using the `createAccountWithNonce()` of the factory | indefinite | 202,797 |
|   UpgradeableOpenfortAccount  | Updating to a new implementation using `upgradeTo()` | indefinite | 3,226  |

### Paymaster
|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
|   OpenfortPaymaster | Deploy Paymaster to pay gas in ERC20s | 1 | 1,216,063  |
