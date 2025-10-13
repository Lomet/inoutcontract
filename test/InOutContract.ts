import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { parseEther, encodePacked, keccak256 } from "viem";

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

  it("Should allow deposits and update transactions correctly", async function () {
    const [, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    const depositAmount = parseEther("100");

    // Mint tokens to user
    await mockToken.write.mint([user.account.address, depositAmount]);

    // Approve tokens for contract
    await mockToken.write.approve([inOutContract.address, depositAmount], { account: user.account });

    // Check initial transaction count and contract balance
    const initialCount = await inOutContract.read.getUserTransactionCount([user.account.address]);
    const initialContractBalance = await inOutContract.read.getContractBalance();
    assert.equal(initialCount, 0n);
    assert.equal(initialContractBalance, 0n);

    // Deposit tokens
    await inOutContract.write.deposit([depositAmount], { account: user.account });

    // Check updated transaction count and contract balance
    const finalCount = await inOutContract.read.getUserTransactionCount([user.account.address]);
    const finalContractBalance = await inOutContract.read.getContractBalance();
    assert.equal(finalCount, 1n);
    assert.equal(finalContractBalance, depositAmount);

    // Check transaction record
    const [amount, isDeposit] = await inOutContract.read.getUserTransaction([user.account.address, 0n]);
    assert.equal(amount, depositAmount);
    assert.equal(isDeposit, true);
  });

  it("Should allow withdrawals with valid signer signature", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const depositAmount = parseEther("100");
    const withdrawAmount = parseEther("50");

    // Mint and deposit tokens
    await mockToken.write.mint([user.account.address, depositAmount]);
    await mockToken.write.approve([inOutContract.address, depositAmount], { account: user.account });
    await inOutContract.write.deposit([depositAmount], { account: user.account });

    // Prepare withdrawal signature
    const expectedTransactionIndex = 1n; // Second transaction (withdrawal)
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour from now

    // Create message hash
    const messageHash = keccak256(
      encodePacked(
        ["address", "uint256", "uint256", "uint256", "address"],
        [user.account.address, withdrawAmount, expectedTransactionIndex, validUntil, inOutContract.address]
      )
    );

    // Sign the message
    const signature = await signer.signMessage({
      message: { raw: messageHash },
    });

    // Perform withdrawal
    await inOutContract.write.withdraw([withdrawAmount, expectedTransactionIndex, validUntil, signature], { account: user.account });

    // Verify transaction count
    const transactionCount = await inOutContract.read.getUserTransactionCount([user.account.address]);
    assert.equal(transactionCount, 2n);

    // Verify withdrawal transaction record
    const [amount, isDeposit] = await inOutContract.read.getUserTransaction([user.account.address, 1n]);
    assert.equal(amount, withdrawAmount);
    assert.equal(isDeposit, false);

    // Verify contract balance
    const finalContractBalance = await inOutContract.read.getContractBalance();
    assert.equal(finalContractBalance, depositAmount - withdrawAmount);
  });

  it("Should reject withdrawals with invalid signatures", async function () {
    const [, signer, user, invalidSigner] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add only one signer
    await inOutContract.write.addSigner([signer.account.address]);

    const depositAmount = parseEther("100");
    const withdrawAmount = parseEther("50");

    // Mint and deposit tokens
    await mockToken.write.mint([user.account.address, depositAmount]);
    await mockToken.write.approve([inOutContract.address, depositAmount], { account: user.account });
    await inOutContract.write.deposit([depositAmount], { account: user.account });

    // Prepare withdrawal signature with invalid signer
    const expectedTransactionIndex = 1n;
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const messageHash = keccak256(
      encodePacked(
        ["address", "uint256", "uint256", "uint256", "address"],
        [user.account.address, withdrawAmount, expectedTransactionIndex, validUntil, inOutContract.address]
      )
    );

    // Sign with invalid signer
    const invalidSignature = await invalidSigner.signMessage({
      message: { raw: messageHash },
    });

    // Should reject withdrawal
    try {
      await inOutContract.write.withdraw([withdrawAmount, expectedTransactionIndex, validUntil, invalidSignature], { account: user.account });
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

    const depositAmount = parseEther("100");
    const withdrawAmount = parseEther("50");

    // Mint and deposit tokens
    await mockToken.write.mint([user.account.address, depositAmount]);
    await mockToken.write.approve([inOutContract.address, depositAmount], { account: user.account });
    await inOutContract.write.deposit([depositAmount], { account: user.account });

    // Prepare withdrawal signature with expired timestamp
    const expectedTransactionIndex = 1n;
    const validUntil = BigInt(Math.floor(Date.now() / 1000) - 3600); // 1 hour ago (expired)

    const messageHash = keccak256(
      encodePacked(
        ["address", "uint256", "uint256", "uint256", "address"],
        [user.account.address, withdrawAmount, expectedTransactionIndex, validUntil, inOutContract.address]
      )
    );

    const signature = await signer.signMessage({
      message: { raw: messageHash },
    });

    // Should reject withdrawal
    try {
      await inOutContract.write.withdraw([withdrawAmount, expectedTransactionIndex, validUntil, signature], { account: user.account });
      assert.fail("Should have thrown an error");  
    } catch (error: any) {
      assert(error.message.includes("Signature expired"));
    }
  });

  it("Should allow fetching all user transactions", async function () {
    const [, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    const amount1 = parseEther("100");
    const amount2 = parseEther("200");

    // Mint tokens to user
    await mockToken.write.mint([user.account.address, amount1 + amount2]);

    // Approve tokens for contract
    await mockToken.write.approve([inOutContract.address, amount1 + amount2], { account: user.account });

    // Make two deposits
    await inOutContract.write.deposit([amount1], { account: user.account });
    await inOutContract.write.deposit([amount2], { account: user.account });

    // Fetch all transactions
    const transactions = await inOutContract.read.getUserTransactions([user.account.address]);
    
    assert.equal(transactions.length, 2);
    assert.equal(transactions[0].amount, amount1);
    assert.equal(transactions[0].isDeposit, true);
    assert.equal(transactions[1].amount, amount2);
    assert.equal(transactions[1].isDeposit, true);
  });

  it("Should reject deposits with zero amount", async function () {
    const [, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Should reject zero amount deposit
    try {
      await inOutContract.write.deposit([0n], { account: user.account });
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
    const [owner, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    const depositAmount = parseEther("100");

    // Mint and deposit tokens
    await mockToken.write.mint([user.account.address, depositAmount]);
    await mockToken.write.approve([inOutContract.address, depositAmount], { account: user.account });
    await inOutContract.write.deposit([depositAmount], { account: user.account });

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

  it("Should reject invalid transaction index for withdrawals", async function () {
    const [, signer, user] = await viem.getWalletClients();
    
    // Deploy mock ERC20 token
    const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);

    // Deploy InOutContract
    const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);

    // Add signer
    await inOutContract.write.addSigner([signer.account.address]);

    const depositAmount = parseEther("100");
    const withdrawAmount = parseEther("50");

    // Mint and deposit tokens
    await mockToken.write.mint([user.account.address, depositAmount]);
    await mockToken.write.approve([inOutContract.address, depositAmount], { account: user.account });
    await inOutContract.write.deposit([depositAmount], { account: user.account });

    // Try withdrawal with wrong transaction index
    const wrongTransactionIndex = 5n; // Should be 1
    const validUntil = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const messageHash = keccak256(
      encodePacked(
        ["address", "uint256", "uint256", "uint256", "address"],
        [user.account.address, withdrawAmount, wrongTransactionIndex, validUntil, inOutContract.address]
      )
    );

    const signature = await signer.signMessage({
      message: { raw: messageHash },
    });

    // Should reject withdrawal with invalid transaction index
    try {
      await inOutContract.write.withdraw([withdrawAmount, wrongTransactionIndex, validUntil, signature], { account: user.account });
      assert.fail("Should have thrown an error");
    } catch (error: any) {
      assert(error.message.includes("Invalid transaction index"));
    }
  });
});