# Recoverable Accounts
Recoverable accounts are a special type of accounts that support social recovery.
They let owners define a set of guardians to help recover the account in case the private key of the owner is compromised (forgotten, disclosed, stolen...).

## Context 

As explained by Vitalik in a famous post (https://vitalik.ca/general/2021/01/11/recovery.html), guardians are the next thing after multisig wallets.

Observe the image below from the mentioned blog post to visualize how guardians work.

![Guardians][guardians-image]

[guardians-image]: ../../../.github/img/guardiansDiagramVitalik.png

If enough guardians confirm the recovery of an account, they can help the legitimate owner of the account update the signing key (aka owner).

## How do Recoverable Accounts Work

The owner can:
 - Propose a new gaurdian.
 - Cancel the proposal of a new guardian.
 - Revoke a guardian.
 - Cancel the revocation of a new guardian.
 - Cancel the recovery mode.
 - Transfer the ownership of the account (2 step process).

A guardian can:
 - Start a recovery process.
 - Lock and unlock the account for a period of time (`lockPeriod`).

Anyone can:
 - When a guardian has been proposed for enough time (`securityPeriod`), confirm its proposal.
 - When a guardian has been revoked for enough time (`securityPeriod`), confirm its revocation.
 - When in recovery mode, submit the list of needed signatures (from half of the gaurdians) to complete the recovery of the account.


## More Information
 - https://vitalik.ca/general/2021/01/11/recovery.html
 - https://medium.com/nightlycrypto/smart-wallets-guardians-756d27a749c7
 - https://www.makeuseof.com/what-is-crypto-social-recovery-wallet-how-does-it-work/
 - https://support.argent.xyz/hc/en-us/articles/360022631992-About-guardians
 - https://docs-wallet.loopring.io/security/guardians
