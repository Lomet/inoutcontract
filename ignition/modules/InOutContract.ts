import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("InOutContractModule", (m) => {
  // Deploy a mock ERC20 token for testing
  const mockToken = m.contract("MockERC20", ["Test Token", "TEST"]);

  // Deploy the main InOutContract
  const inOutContract = m.contract("InOutContract", [mockToken]);

  return { mockToken, inOutContract };
});
