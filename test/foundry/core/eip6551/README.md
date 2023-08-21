# Upgradeable Openfort Accounts vs EIP6551 Openfort Accounts


## Table
The table below represents the difference of gas needed to perform a set of actions using Upgradeable Openfort accounts vs EIP6551 Openfort accounts. The numbers were taken using the version 0.4 of the contracts in August 2023. Even though the account creation of EIP6551 is cheaper (26%), using the:

|   Action   |    Upgradeable    |    EIP6551    |    Difference    |
| :---------- | :------------------ | :----------------- | :------------------- |
|   Check ownership   |   14,794   |   18,890   |  27.68% increase   |
|   Transfer ownership   |   41,224   | 64,059   |   55.4% increase   |
|   Transfer native funds   |   46,040   |   48,901   |   6.2%  increase   |
|   Transfer ERC20s   |   54,796   |   57,338   |   4.6% increase   |
|   Transfer 10 ERC20s   |   110,193   |   137,043   |   24.3% increase   |


## How to reproduce it

```
 forge test --mc EIP6551OpenfortBenchmark
```
