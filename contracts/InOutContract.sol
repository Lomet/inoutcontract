// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract InOutContract is Ownable, Pausable, ReentrancyGuard, EIP712 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    
    // Signers authorized to approve withdrawals
    mapping(address => bool) public signers;
    
    // ERC712 type hash for withdraw
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address user,uint256 amount,uint256 nonce,uint256 validUntil,address tokenAddr)"
    );
    
    // Nonce for each user to prevent replay attacks
    mapping(address => uint256) public nonces;

    event Withdraw(address indexed user, uint256 amount, uint256 nonce);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);

    constructor(address _token) Ownable(msg.sender) EIP712("InOutContract", "1") {
        require(_token != address(0), "Invalid token address");
        token = IERC20(_token);
    }

    // Owner functions
    function addSigner(address _signer) external onlyOwner {
        require(_signer != address(0), "Invalid signer address");
        signers[_signer] = true;
        emit SignerAdded(_signer);
    }

    function removeSigner(address _signer) external onlyOwner {
        signers[_signer] = false;
        emit SignerRemoved(_signer);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // Internal withdraw function - requires signer signature using ERC712
    function _withdraw(
        address user,
        uint256 amount,
        uint256 validUntil,
        bytes memory signature
    ) internal {
        require(amount > 0, "Amount must be greater than 0");
        require(block.timestamp <= validUntil, "Signature expired");
        
        // Check contract has enough tokens
        require(token.balanceOf(address(this)) >= amount, "Insufficient contract balance");

        uint256 currentNonce = nonces[user];
        
        // Create ERC712 hash
        bytes32 structHash = keccak256(abi.encode(
            WITHDRAW_TYPEHASH,
            user,
            amount,
            currentNonce,
            validUntil,
            address(token)
        ));
        
        bytes32 hash = _hashTypedDataV4(structHash);
        
        // Verify signer signature
        address signer = hash.recover(signature);
        require(signers[signer], "Invalid signer");
        
        // Increment nonce
        nonces[user] = currentNonce + 1;
        
        // Transfer tokens to user
        token.safeTransfer(user, amount);
        
        emit Withdraw(user, amount, currentNonce);
    }

    // Withdraw function - user withdraws to their own address
    function withdraw(
        uint256 amount,
        uint256 validUntil,
        bytes memory signature
    ) external whenNotPaused nonReentrant {
        _withdraw(msg.sender, amount, validUntil, signature);
    }

    // Withdraw for - anyone can call to withdraw to a specified address
    function withdrawFor(
        address user,
        uint256 amount,
        uint256 validUntil,
        bytes memory signature
    ) external whenNotPaused nonReentrant {
        _withdraw(user, amount, validUntil, signature);
    }

    // View functions
    function getContractBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function isSigner(address _signer) external view returns (bool) {
        return signers[_signer];
    }

    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }

    // Emergency function for owner to withdraw contract tokens
    function emergencyWithdraw() external onlyOwner {
        uint256 contractBalance = token.balanceOf(address(this));
        token.safeTransfer(owner(), contractBalance);
    }
}
