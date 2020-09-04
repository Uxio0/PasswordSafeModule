pragma solidity ^0.5.0;

import "@gnosis.pm/safe-contracts/contracts/base/ModuleManager.sol";
import "@gnosis.pm/safe-contracts/contracts/base/OwnerManager.sol";
import "@gnosis.pm/safe-contracts/contracts/base/Module.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";


/// @title Password Protected Module - Allows a user to unlock a Safe with a password
/// @author Uxío Fuentefría - <uxio@gnosis.io>
contract PasswordSafeModule is Module {
    // using SafeMath for uint256;

    string public constant NAME = "Password Protected Module";
    string public constant VERSION = "0.1.0";

    // Store a hash and the block number when it was approved
    mapping (bytes32 => uint256) public approvedHashes;
    bytes32 passwordHash;

    /// @dev Setup function sets the passwordHash
    /// @param _passwordHash Keccak256 of the user password.
    function setup(bytes32 _passwordHash)
        public
    {
        require(_passwordHash != bytes32(0), "A non-zero password hash must be set.");
        passwordHash = _passwordHash;
        setManager();
    }

    /// @dev Prepares the sender to execute a Safe transaction, to prevent frontrunning
    /// @param approvedHash Keccak256(abi.encodePacked(byte(0x19), byte(0), this, password, msg.sender))
    function approveHash(
        bytes32 approvedHash
    )
        public
    {
        require(approvedHash != passwordHash, "ApprovedHash cannot be equal to passwordHash");
        approvedHashes[approvedHash] = block.number;
    }

    /// @dev Allows the user to execute a Safe transaction, maybe changing the owner/threshold
    /// @param password Password of the user
    /// @param newPasswordHash New password hash to be stored on the module
    function executeTransaction(
        string memory password,
        bytes32 newPasswordHash,
        address to,
        bytes memory data
    )
        public
    {
        bytes32 approvedHash = getApprovedHash(password);
        require(keccak256(abi.encodePacked(password)) != passwordHash, "Invalid password");
        require(approvedHashes[approvedHash] != 0, "Cannot find approved hash for msg.sender");
        // require(block.number - approvedHashes[approvedHash] > 5760, "A day has not passed since the approvedHash was created");
        require(passwordHash != newPasswordHash, "New password must be different from the old one");

        passwordHash = newPasswordHash;
        require(manager.execTransactionFromModule(to, 0, data, Enum.Operation.Call), "Could not execute password protected transaction");
    }


    /// @dev Returns approvedHash.
    /// @param password Password known by the user. This is a helper function and should never be called, as a malicious
    /// user could find out the password.
    /// @return Approved hash.
    function getApprovedHash(
        string memory password
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(byte(0x19), byte(0), this, password, msg.sender)
        );
    }

}
