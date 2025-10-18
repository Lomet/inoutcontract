import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { parseEther, Address } from "viem";

// Helper function to create ERC-712 signature for withdrawal
async function signWithdrawal(
  signer: any,
  contractAddress: Address,
  userAddress: Address,
  amount: bigint,
  nonce: bigint,
  validUntil: bigint,
  tokenAddr: Address
) {
  const domain = {
    name: "InOutContract",
    version: "1",
    chainId: 31337, // Hardhat default chain ID
    verifyingContract: contractAddress,
  };

  const types = {
    Withdraw: [
      { name: "user", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "validUntil", type: "uint256" },
      { name: "tokenAddr", type: "address" },
    ],
  };

  const message = {
    user: userAddress,
    amount: amount,
    nonce: nonce,
    validUntil: validUntil,
    tokenAddr: tokenAddr,
  };

  return await signer.signTypedData({
    domain,
    types,
    primaryType: "Withdraw",
    message,
  });
}

describe("InOutContract", async function () {
  const { viem } = await network.connect();

  it("Should deploy InOutContract with correct token", async function () {
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    const tokenAddress = await inOutContract.read.token();
    assert.equal(tokenAddress.toLowerCase(), mockToken.address.toLowerCase());
  });

  it("Should allow owner to add and remove signers", async function () {
    const [, signer1] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer1.account.address]);
    const isSignerBefore = await inOutContract.read.isSigner([signer1.account.address]);
    assert.equal(isSignerBefore, true);

    // Remove signer
    await inOutContract.write.removeSigner([signer1.account.address]);
    const isSignerAfter = await inOutContract.read.isSigner([signer1.account.address]);
    assert.equal(isSignerAfter, false);
  });

  it("Should allow pause and unpause by owner", async function () {
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Pause the contract
    await inOutContract.write.pause();

    // Unpause the contract
    await inOutContract.write.unpause();
  });

  it("Should allow withdrawals with valid ERC-712 signer signature", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint tokens directly to contract (simulating deposits tracked by indexer)
    await mockToken.write.mint([inOutContract.address, withdrawAmount]);

    // Get current nonce
    const nonce = await inOutContract.read.getNonce([user.account.address]);
    
    // Prepare withdrawal signature using ERC-712
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

    const signature = await signWithdrawal(
      signer,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // Get user balance before withdrawal
    const userBalanceBefore = await mockToken.read.balanceOf([user.account.address]);

    // Perform withdrawal
    await inOutContract.write.withdraw([withdrawAmount, validUntil, signature], { account: user.account });

    // Verify user received tokens
    const userBalanceAfter = await mockToken.read.balanceOf([user.account.address]);
    assert.equal(userBalanceAfter, userBalanceBefore + withdrawAmount);

    // Verify nonce was incremented
    const newNonce = await inOutContract.read.getNonce([user.account.address]);
    assert.equal(newNonce, nonce + 1n);

    // Verify contract balance decreased
    const finalContractBalance = await inOutContract.read.getContractBalance();
    assert.equal(finalContractBalance, 0n);
  });

  it("Should reject withdrawals with invalid signatures", async function () {
    const [, signer, user, invalidSigner] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add only one signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint tokens directly to contract
    await mockToken.write.mint([inOutContract.address, withdrawAmount]);

    // Get current nonce
    const nonce = await inOutContract.read.nonces([user.account.address]);
    
    // Prepare withdrawal signature with invalid signer using ERC-712
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const invalidSignature = await signWithdrawal(
      invalidSigner,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // Should reject withdrawal
    try {
      await inOutContract.write.withdraw([withdrawAmount, validUntil, invalidSignature], { account: user.account });
      assert.fail("Should have thrown an error");
    } catch (error: any) {
      assert(error.message.includes("Invalid signer"));
    }
  });

  it("Should reject expired signatures", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint tokens directly to contract
    await mockToken.write.mint([inOutContract.address, withdrawAmount]);

    // Get current nonce
    const nonce = await inOutContract.read.nonces([user.account.address]);
    
    // Prepare withdrawal signature with expired timestamp
    const validUntil = BigInt(Math.floor(Date.now() / 1000) - 3600); // 1 hour ago (expired)

    const signature = await signWithdrawal(
      signer,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // Should reject withdrawal
    try {
      await inOutContract.write.withdraw([withdrawAmount, validUntil, signature], { account: user.account });
      assert.fail("Should have thrown an error");  
    } catch (error: any) {
      assert(error.message.includes("Signature expired"));
    }
  });

  it("Should reject withdrawals when paused", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint tokens directly to contract
    await mockToken.write.mint([inOutContract.address, withdrawAmount]);

    // Get current nonce
    const nonce = await inOutContract.read.nonces([user.account.address]);
    
    // Prepare withdrawal signature
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const signature = await signWithdrawal(
      signer,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // Pause the contract
    await inOutContract.write.pause();

    // Should reject withdrawal when paused
    try {
      await inOutContract.write.withdraw([withdrawAmount, validUntil, signature], { account: user.account });
      assert.fail("Should have thrown an error");
    } catch (error: any) {
      assert(error.message.includes("EnforcedPause"));
    }
  });

  it("Should reject withdrawals with zero amount", async function () {
    const [, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);
    
    // Should reject zero amount withdrawal
    try {
      await inOutContract.write.withdraw([0n, validUntil, "0x00"], { account: user.account });
      assert.fail("Should have thrown an error");
    } catch (error: any) {
      assert(error.message.includes("Amount must be greater than 0"));
    }
  });

  it("Should reject adding zero address as signer", async function () {
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Should reject zero address signer
    try {
      await inOutContract.write.addSigner(["0x0000000000000000000000000000000000000000"]);
      assert.fail("Should have thrown an error");
    } catch (error: any) {
      assert(error.message.includes("Invalid signer address"));
    }
  });

  it("Should test emergency withdraw function", async function () {
    const [owner] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    const depositAmount = parseEther("100");

    // Mint tokens directly to contract
    await mockToken.write.mint([inOutContract.address, depositAmount]);

    // Check owner balance before emergency withdraw
    const ownerBalanceBefore = await mockToken.read.balanceOf([owner.account.address]);
    
    // Emergency withdraw
    await inOutContract.write.emergencyWithdraw();

    // Check owner balance after emergency withdraw
    const ownerBalanceAfter = await mockToken.read.balanceOf([owner.account.address]);
    assert.equal(ownerBalanceAfter, ownerBalanceBefore + depositAmount);

    // Contract should have zero balance
    const contractBalance = await inOutContract.read.getContractBalance();
    assert.equal(contractBalance, 0n);
  });

  it("Should prevent replay attacks with nonce increment", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint enough tokens to contract for two withdrawals
    await mockToken.write.mint([inOutContract.address, withdrawAmount * 2n]);

    // Get current nonce
    const nonce = await inOutContract.read.nonces([user.account.address]);
    
    // Prepare withdrawal signature
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const signature = await signWithdrawal(
      signer,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // First withdrawal should succeed
    await inOutContract.write.withdraw([withdrawAmount, validUntil, signature], { account: user.account });

    // Verify nonce was incremented
    const newNonce = await inOutContract.read.nonces([user.account.address]);
    assert.equal(newNonce, nonce + 1n);

    // Try to reuse the same signature - should fail
    try {
      await inOutContract.write.withdraw([withdrawAmount, validUntil, signature], { account: user.account });
      assert.fail("Should have thrown an error");
    } catch (error: any) {
      assert(error.message.includes("Invalid signer"));
    }
  });

  it("Should allow withdrawFor to withdraw to any address", async function () {
    const [, signer, user, recipient] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint tokens directly to contract
    await mockToken.write.mint([inOutContract.address, withdrawAmount]);

    // Get current nonce for user
    const nonce = await inOutContract.read.nonces([user.account.address]);
    
    // Prepare withdrawal signature for user
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const signature = await signWithdrawal(
      signer,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // Get balances before withdrawal
    const userBalanceBefore = await mockToken.read.balanceOf([user.account.address]);

    // Recipient calls withdrawFor on behalf of user
    await inOutContract.write.withdrawFor([user.account.address, withdrawAmount, validUntil, signature], { account: recipient.account });

    // Verify user received tokens (not recipient who called the function)
    const userBalanceAfter = await mockToken.read.balanceOf([user.account.address]);
    assert.equal(userBalanceAfter, userBalanceBefore + withdrawAmount);

    // Verify nonce was incremented for user
    const newNonce = await inOutContract.read.nonces([user.account.address]);
    assert.equal(newNonce, nonce + 1n);
  });

  it("Should allow user to call withdrawFor for themselves", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const withdrawAmount = parseEther("50");

    // Mint tokens directly to contract
    await mockToken.write.mint([inOutContract.address, withdrawAmount]);

    // Get current nonce
    const nonce = await inOutContract.read.nonces([user.account.address]);
    
    // Prepare withdrawal signature
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const signature = await signWithdrawal(
      signer,
      inOutContract.address,
      user.account.address,
      withdrawAmount,
      nonce,
      validUntil,
      mockToken.address
    );

    // Get user balance before withdrawal
    const userBalanceBefore = await mockToken.read.balanceOf([user.account.address]);

    // User calls withdrawFor for themselves
    await inOutContract.write.withdrawFor([user.account.address, withdrawAmount, validUntil, signature], { account: user.account });

    // Verify user received tokens
    const userBalanceAfter = await mockToken.read.balanceOf([user.account.address]);
    assert.equal(userBalanceAfter, userBalanceBefore + withdrawAmount);

    // Verify nonce was incremented
    const newNonce = await inOutContract.read.nonces([user.account.address]);
    assert.equal(newNonce, nonce + 1n);
  });
});