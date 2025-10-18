// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title InOutContractBase
 * @notice Base contract with admin functions and internal withdrawal logic
 * @dev This contract contains the core admin functions and internal withdrawal implementation
 */
abstract contract InOutContractBase is Ownable, Pausable, ReentrancyGuard, EIP712 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice The ERC20 token managed by this contract
    IERC20 public immutable token;
    
    /// @notice Mapping of addresses authorized to sign withdrawal approvals
    mapping(address => bool) public signers;
    
    /// @notice ERC-712 type hash for withdraw operations
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address user,uint256 amount,uint256 nonce,uint256 validUntil,address tokenAddr)"
    );
    
    /// @notice Nonce for each user to prevent replay attacks
    mapping(address => uint256) public nonces;

    // ============================================
    // EVENTS
    // ============================================

    /// @notice Emitted when a withdrawal is successfully executed
    event Withdraw(address indexed user, uint256 amount, uint256 nonce);
    
    /// @notice Emitted when a new signer is authorized
    event SignerAdded(address indexed signer);
    
    /// @notice Emitted when a signer is removed
    event SignerRemoved(address indexed signer);

    /// @notice Emitted when emergency withdrawal is executed
    event EmergencyWithdraw(address indexed token, uint256 amount, address indexed to);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /**
     * @notice Initializes the contract with a specific ERC20 token
     * @param _token The address of the ERC20 token to be managed
     */
    constructor(address _token) Ownable(msg.sender) EIP712("InOutContract", "1") {
        require(_token != address(0), "Invalid token address");
        token = IERC20(_token);
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Adds a new authorized signer who can approve withdrawals
     * @dev Only owner can call this function
     * @param _signer The address to be added as an authorized signer
     */
    function addSigner(address _signer) external onlyOwner {
        require(_signer != address(0), "Invalid signer address");
        signers[_signer] = true;
        emit SignerAdded(_signer);
    }

    /**
     * @notice Removes an authorized signer
     * @dev Only owner can call this function
     * @param _signer The address to be removed from authorized signers
     */
    function removeSigner(address _signer) external onlyOwner {
        signers[_signer] = false;
        emit SignerRemoved(_signer);
    }

    /**
     * @notice Pauses the contract, preventing withdrawals
     * @dev Only owner can call this function. Emergency stop mechanism
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpauses the contract, re-enabling withdrawals
     * @dev Only owner can call this function
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Emergency function to withdraw tokens from the contract
     * @dev Only owner can call this function. Can withdraw any ERC20 token that gets stuck
     * @param tokenAddress The address of the token to withdraw
     * @param amount The amount of tokens to withdraw
     */
    function emergencyWithdraw(address tokenAddress, uint256 amount) external onlyOwner {
        require(tokenAddress != address(0), "Invalid token address");
        require(amount > 0, "Amount must be greater than 0");
        
        IERC20 tokenToWithdraw = IERC20(tokenAddress);
        uint256 contractBalance = tokenToWithdraw.balanceOf(address(this));
        require(contractBalance >= amount, "Insufficient token balance");
        
        tokenToWithdraw.safeTransfer(owner(), amount);
        emit EmergencyWithdraw(tokenAddress, amount, owner());
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    /**
     * @notice Internal function that handles the core withdrawal logic
     * @dev Validates ERC-712 signature, checks nonce, and transfers tokens
     * @param user The address that will receive the tokens
     * @param amount The amount of tokens to withdraw
     * @param validUntil Timestamp until which the signature is valid
     * @param signature ERC-712 signature from an authorized signer
     */
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

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Returns the total token balance held by the contract
     * @return The contract's token balance
     */
    function getContractBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /**
     * @notice Checks if an address is an authorized signer
     * @param _signer The address to check
     * @return True if the address is an authorized signer, false otherwise
     */
    function isSigner(address _signer) external view returns (bool) {
        return signers[_signer];
    }

    /**
     * @notice Returns the current nonce for a user
     * @dev Nonce increments with each withdrawal to prevent replay attacks
     * @param user The address to check the nonce for
     * @return The current nonce value for the user
     */
    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}
