// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "./InOutContractBase.sol";

/**
 * @title InOutContract
 * @notice A secure withdrawal contract with ERC-712 signature-based authorization
 * @dev This contract manages token withdrawals using off-chain signatures from authorized signers.
 *      Deposits are tracked via an external indexer monitoring transfer events.
 * 
 * Features:
 * - ERC-712 typed signatures for withdrawal authorization
 * - Nonce-based replay attack protection
 * - Pausable for emergency stops
 * - Reentrancy protection
 * - SafeERC20 for secure token transfers
 * - Support for meta-transactions via withdrawFor
 * - Multi-signer support for decentralized authorization
 */
contract InOutContract is InOutContractBase {

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /**
     * @notice Initializes the contract with a specific ERC20 token
     * @param _token The address of the ERC20 token to be managed
     */
    constructor(address _token) InOutContractBase(_token) {}

    // ============================================
    // PUBLIC FUNCTIONS
    // ============================================

    /**
     * @notice Allows a user to withdraw tokens to their own address
     * @dev Requires valid ERC-712 signature from authorized signer
     * @param amount The amount of tokens to withdraw
     * @param validUntil Timestamp until which the signature is valid
     * @param signature ERC-712 signature from an authorized signer
     */
    function withdraw(
        uint256 amount,
        uint256 validUntil,
        bytes memory signature
    ) external whenNotPaused nonReentrant {
        _withdraw(msg.sender, amount, validUntil, signature);
    }

    /**
     * @notice Allows anyone to execute a withdrawal on behalf of another address
     * @dev Useful for meta-transactions and gasless withdrawals. Tokens always go to the signed user address
     * @param user The address that will receive the tokens (must match signature)
     * @param amount The amount of tokens to withdraw
     * @param validUntil Timestamp until which the signature is valid
     * @param signature ERC-712 signature from an authorized signer
     */
    function withdrawFor(
        address user,
        uint256 amount,
        uint256 validUntil,
        bytes memory signature
    ) external whenNotPaused nonReentrant {
        _withdraw(user, amount, validUntil, signature);
    }
}
