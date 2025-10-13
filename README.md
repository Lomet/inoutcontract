# InOut Contract - Simple ERC20 Portal

A simple and secure smart contract that acts as a portal/gateway for ERC20 token deposits and withdrawals, designed to integrate with backend systems (Redis, databases, etc).

## Features

- **Simple Deposits**: Users can deposit ERC20 tokens without any signature requirements
- **Secure Withdrawals**: Backend-controlled withdrawals using cryptographic signatures  
- **Transaction History**: Complete on-chain record of all deposits and withdrawals
- **Nonce System**: Prevents replay attacks using transaction indices
- **Time-Limited Signatures**: Withdrawals require signatures with expiration timestamps
- **Multiple Signers**: Owner can add/remove authorized backend signers
- **Gas Efficient**: Uses arrays and minimal storage for optimal gas usage

## Architecture

This contract serves as a **gateway** between users and your backend:

1. **Users deposit** → Tokens held in contract → Events emitted
2. **Backend indexes** → Events tracked in Redis/DB → User balances calculated  
3. **Users withdraw** → Backend signs approval → Contract validates & transfers

## Contract Overview

- **Deposits**: Permissionless, just requires ERC20 approval
- **Withdrawals**: Requires backend signer approval with time-limited signatures
- **Transaction Tracking**: Each operation stored with amount and type (deposit/withdrawal)
- **Access Control**: Owner manages authorized signers

## Usage

### Running Tests

To run all the tests in the project, execute the following command:

```shell
npx hardhat test
```

You can also selectively run the Solidity or `node:test` tests:

```shell
npx hardhat test solidity
npx hardhat test nodejs
```

### Make a deployment to Sepolia

This project includes an example Ignition module to deploy the contract. You can deploy this module to a locally simulated chain or to Sepolia.

To run the deployment to a local chain:

```shell
npx hardhat ignition deploy ignition/modules/InOutContract.ts
```

To run the deployment to Sepolia, you need an account with funds to send the transaction. The provided Hardhat configuration includes a Configuration Variable called `SEPOLIA_PRIVATE_KEY`, which you can use to set the private key of the account you want to use.

You can set the `SEPOLIA_PRIVATE_KEY` variable using the `hardhat-keystore` plugin or by setting it as an environment variable.

To set the `SEPOLIA_PRIVATE_KEY` config variable using `hardhat-keystore`:

```shell
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
```

After setting the variable, you can run the deployment with the Sepolia network:

```shell
npx hardhat ignition deploy --network sepolia ignition/modules/Counter.ts
```
