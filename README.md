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
Official Contracts of the Openfort Project.

The following standards are supported:
- ERC-20, ERC-721, ERC-777 and ERC-1155 for different token handling.
- ERC-173 for ownership standard.
- EIP-712 and EIP-5267 for typed structured data hashing and signing.
- ERC-1271 for standard signature validation.
- ERC-1967 and ERC-1822 for proxies (upgradeable Openfort accounts).
- EIP-1014 for generating counterfactual addresses using Openfort factories.
- ERC-4337 for leveraging Account Abstraction using alternative mempools.
- ERC-6551 for leveraging Token Bound Accounts 

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

### Deploy Upgradeable and Managed factories to all chains

```
./script/deployAllChains.sh
```

### Check paymaster's deposit and Patron's balance on different chains

```
forge script CheckDeposits --force
```

### Deploy one upgradeable factory and one account

Simulation:

```
forge script --force script/deployManagedAccounts.s.sol -vvvvv --optimizer-runs 1000000 --slow --fork-url $<rpc_network>
```

Actual deployment:
```
forge script --force script/deployManagedAccounts.s.sol  -vvvvv --optimizer-runs 1000000 --slow --fork-url $<rpc_network> --broadcast --verify --etherscan-api-key $<api_key>
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

There are two different categories of benchmarks measured in this test: User Operation and Runtime.

- User Operation: Fees are calculated based on the transaction receipt and the serialized signed EIP-1559 transaction for entryPoint.handleUserOp([userOp]). As multi-user-op bundles become more prevalent, we can expect actual fees to undercut the data presented here.
- Runtime: Runtime transactions are defined as those performed outside of the user operation flow, with the owner key interacting directly with the account factory or account, akin to the way you might use MetaMask today to interact directly with smart contracts.

## Runtime

### Upgradeable Accounts
|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
| UpgradeableOpenfortFactory | Deploy factory (containing UpgradeableOpenfortAccount's implementation) | 1 | ~3,250,000  |
|   UpgradeableOpenfortAccount  | Create a new upgradeable account using the `createAccountWithNonce()` of the factory | indefinite | ~250,000 |
|   UpgradeableOpenfortAccount  | Updating to a new implementation using `upgradeTo()` | indefinite | ~3,500  |


### Paymaster
|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
|   OpenfortPaymaster | Deploy Paymaster to pay gas in ERC20s | 1 | ~1,250,000  |

## User Operation

### Upgradeable Accounts
|   Smart Contract   |    Description    |    # of deployments per game/ecosystem    |    Avg gas cost    |
| :----------------- | :---------------------------------- | :---------------------------------- | :------------------------ |
|   UpgradeableOpenfortAccount  | Create a new upgradeable account | indefinite | ~350,000 |
|   UpgradeableOpenfortAccount  | Send native tokens | NA | ~170,000   |
|   UpgradeableOpenfortAccount  | Send ERC20 tokens | NA | ~190,000  |


## Gas Stats in USD

As of April 2024, the gas price range is reported as the daily average gas price for the first 90 days of 2023 ± one standard deviation.

|   Blockchain   |    Gas Price Range    |    Token Price    |     Create an Upgradeable account   |    Native Transfer    |    ERC20 Transfer    |
| :------------- | :-------------------- | :---------------- |  :------ | :-------------------- | :------------------ |
| Arbitrum | 0.01 ±0.00001853 gwei | ~$3000 | $0.0103-$0.0103 | $0.0050-$0.0050 | $0.0056-$0.0056 |
| Optimism | 0.06102 ±24.05 gwei | ~$3000 | $0.0630-$24.8828 | $0.0306-$12.0859 | $0.0342-$13.5078 |
| Base | 0.0535 ±24.05 gwei | ~$3000 | $0.0552-$24.8751 | $0.0268-$12.0822 | $0.0300-$13.5036 |
| Polygon | 30 ±108 gwei | ~$0.67 | $0.0070-$0.0324 | $0.0034-$0.0157 | $0.0038-$0.0176 |
| Avalanche | 29 ±4.5 nAVAX | ~$33 | $0.3350-$0.3869 | $0.1627-$0.1879 | $0.1818-$0.2100 |
| BSC | 4 ±0.55 gwei | ~$580 | $0.8120-$0.9236 | $0.3944-$0.4486 | $0.4408-$0.5014 |
| Ethereum | 3.5 ±24 gwei | ~$3000 | $3.6120-$28.3803 | $1.7544-$13.7847 | $1.9608-$15.4064 |
