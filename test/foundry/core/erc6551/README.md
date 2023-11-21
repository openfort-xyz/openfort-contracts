# Upgradeable Openfort Accounts vs ERC6551 Openfort Accounts


## Table
The table below represents the difference of gas needed to perform a set of actions using Upgradeable Openfort accounts vs ERC6551 Openfort accounts. The numbers were taken using the version 0.4 of the contracts in August 2023. Even though the account creation of ERC6551 is cheaper (26%), using the:

|   Action   |    Upgradeable    |    ERC6551    |    Difference    |
| :---------- | :------------------ | :----------------- | :------------------- |
|   Check ownership   |   14,794   |   18,890   |  27.68% increase   |
|   Transfer ownership   |   41,224   | 64,059   |   55.4% increase   |
|   Transfer native funds   |   46,040   |   48,901   |   6.2%  increase   |
|   Transfer ERC20s   |   54,796   |   57,338   |   4.6% increase   |
|   Transfer 10 ERC20s   |   110,193   |   137,043   |   24.3% increase   |

Further "complex" tests were performed like the `test9TransferOwnerERC6551Complex`.
This represents a transfer of an ERC6551 account owned by an Openfort Upgradeable account.
For that, an NFT owned by the EOA (that is also the owner of the Upgradeable account) is transferred to another EOA.
This costs 83,248 gas (compared to 41,224 of the upgradeable and 64,059 gas of the simple ERC6551 account).
This is an increase of 102% in relation to the upgradeable account and 29.96%.


## How to reproduce it

```
 forge test --mc ERC6551OpenfortBenchmark
```
