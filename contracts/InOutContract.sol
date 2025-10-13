// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract InOutContract is Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    IERC20 public immutable token;
    
    // Signers authorized to approve withdrawals
    mapping(address => bool) public signers;
    
    // Transaction record structure
    struct TransactionRecord {
        uint256 amount;
        bool isDeposit; // true for deposit, false for withdrawal
    }
    
    // User transaction history: user => array of records
    mapping(address => TransactionRecord[]) public userTransactions;

    event Deposit(address indexed user, uint256 amount, uint256 transactionIndex);
    event Withdraw(address indexed user, uint256 amount, uint256 transactionIndex);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);

    constructor(address _token) Ownable(msg.sender) {
        require(_token != address(0), "Invalid token address");
        token = IERC20(_token);
    }

    modifier onlySigner() {
        require(signers[msg.sender], "Not authorized signer");
        _;
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

    // Deposit function - no signature required
    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");
        
        // Transfer tokens from user to contract
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        
        // Record the transaction
        uint256 transactionIndex = userTransactions[msg.sender].length;
        userTransactions[msg.sender].push(TransactionRecord({
            amount: amount,
            isDeposit: true
        }));
        
        emit Deposit(msg.sender, amount, transactionIndex);
    }

    // Deposit with permit (ERC20Permit) - no signature required from signer
    function depositWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(amount > 0, "Amount must be greater than 0");
        
        // Use permit to approve tokens
        IERC20Permit(address(token)).permit(msg.sender, address(this), amount, deadline, v, r, s);
        
        // Transfer tokens from user to contract
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        
        // Record the transaction
        uint256 transactionIndex = userTransactions[msg.sender].length;
        userTransactions[msg.sender].push(TransactionRecord({
            amount: amount,
            isDeposit: true
        }));
        
        emit Deposit(msg.sender, amount, transactionIndex);
    }

    // Withdraw function - requires signer signature
    function withdraw(
        uint256 amount,
        uint256 expectedTransactionIndex,
        uint256 validUntil,
        bytes memory signature
    ) external {
        require(amount > 0, "Amount must be greater than 0");
        require(expectedTransactionIndex == userTransactions[msg.sender].length, "Invalid transaction index");
        require(block.timestamp <= validUntil, "Signature expired");
        
        // Check contract has enough tokens
        require(token.balanceOf(address(this)) >= amount, "Insufficient contract balance");

        // Create message hash
        bytes32 messageHash = keccak256(abi.encodePacked(
            msg.sender,
            amount,
            expectedTransactionIndex,
            validUntil,
            address(this)
        ));
        
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        // Verify signer signature
        address signer = ethSignedMessageHash.recover(signature);
        require(signers[signer], "Invalid signer");
        
        // Record the transaction
        uint256 transactionIndex = userTransactions[msg.sender].length;
        userTransactions[msg.sender].push(TransactionRecord({
            amount: amount,
            isDeposit: false
        }));
        
        // Transfer tokens to user
        require(token.transfer(msg.sender, amount), "Transfer failed");
        
        emit Withdraw(msg.sender, amount, transactionIndex);
    }

    // View functions
    function getUserTransactionCount(address user) external view returns (uint256) {
        return userTransactions[user].length;
    }
    
    function getUserTransaction(address user, uint256 index) external view returns (uint256 amount, bool isDeposit) {
        require(index < userTransactions[user].length, "Transaction index out of bounds");
        TransactionRecord memory record = userTransactions[user][index];
        return (record.amount, record.isDeposit);
    }
    
    function getUserTransactions(address user) external view returns (TransactionRecord[] memory) {
        return userTransactions[user];
    }
    
    function getContractBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function isSigner(address _signer) external view returns (bool) {
        return signers[_signer];
    }

    // Emergency function for owner to withdraw contract tokens
    function emergencyWithdraw() external onlyOwner {
        uint256 contractBalance = token.balanceOf(address(this));
        require(token.transfer(owner(), contractBalance), "Emergency withdraw failed");
    }
}
