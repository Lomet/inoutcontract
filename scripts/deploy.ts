import { network } from "hardhat";
import { parseEther } from "viem";

async function main() {
  const { viem } = await network.connect();

  console.log("🚀 Deploying InOutContract...");

  // Deploy mock ERC20 token
  console.log("📄 Deploying MockERC20...");
  const mockToken = await viem.deployContract("MockERC20", ["Test Token", "TEST"]);
  console.log("✅ MockERC20 deployed to:", mockToken.address);

  // Deploy InOutContract
  console.log("📄 Deploying InOutContract...");
  const inOutContract = await viem.deployContract("InOutContract", [mockToken.address]);
  console.log("✅ InOutContract deployed to:", inOutContract.address);

  // Get wallet clients
  const [owner, signer, user] = await viem.getWalletClients();

  // Add a signer
  console.log("👤 Adding signer:", signer.account.address);
  await inOutContract.write.addSigner([signer.account.address]);

  // Mint some tokens to user for testing
  const mintAmount = parseEther("1000");
  console.log("💰 Minting", mintAmount.toString(), "tokens to user:", user.account.address);
  await mockToken.write.mint([user.account.address, mintAmount]);

  console.log("\n📋 Contract Summary:");
  console.log("═".repeat(50));
  console.log("MockERC20 Address    :", mockToken.address);
  console.log("InOutContract Address:", inOutContract.address);
  console.log("Owner Address        :", owner.account.address);
  console.log("Signer Address       :", signer.account.address);
  console.log("Test User Address    :", user.account.address);
  console.log("═".repeat(50));

  console.log("\n🎯 Next Steps:");
  console.log("1. User can approve and deposit tokens");
  console.log("2. Backend (signer) can authorize withdrawals");
  console.log("3. All transactions are recorded on-chain");
  
  console.log("\n✨ Deployment completed successfully!");
}

main().catch((error) => {
  console.error("❌ Deployment failed:", error);
  process.exitCode = 1;
});