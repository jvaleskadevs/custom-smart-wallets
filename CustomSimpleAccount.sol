// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "../core/BaseAccount.sol";
import "./callback/TokenCallbackHandler.sol";

/**
  * custom recovery account
  *  this is sample custom minimal account with recovery options.
  *  has execute, eth handling methods
  *  every address in the signers' mapping can send requests trough the entryPoint
  *  the entrypoint will require only one signature
  *  this is not a multi-sig smart wallet but a smart wallet with recovery options
  *  in case of lost access to an address, other addresses still have access
  */
contract CustomSimpleAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    address public owner;
    // every address in the mapping can use this account to send UserOps
    mapping(address => bool) private signers;

    IEntryPoint private immutable _entryPoint;

    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    
    modifier onlySigners() {
        _onlySigners();
        _;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }


    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }
    
    function _onlySigners() internal view {
        //directly from EOA signers, or through the account itself (which gets redirected through execute())
        require(signers[msg.sender] == true || msg.sender == address(this), "only signers");
    }

    /**
     * execute a transaction (called directly from signers, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrSigners();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrSigners();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        signers[anOwner] = true;
        emit SimpleAccountInitialized(_entryPoint, owner);
    }
    
    // Require the function call went through EntryPoint or signers
    function _requireFromEntryPointOrSigners() internal view {
        require(msg.sender == address(entryPoint()) || signers[msg.sender] == true, "account: not Signer or EntryPoint");
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signerRecovered = hash.recover(userOp.signature);
        if (signers[signerRecovered] != true)
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlySigners {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlySigners();
    }
    
    /**
     * functions to add/remove wallet(s) to the signers mapping
     * only the signers can call theses functions
     */
    
    function addRecoveryWallet(address _wallet) public onlySigners {
        require(address(0) != _wallet, "ZeroAddress");
        signers[_wallet] = true;
    }
    
    function removeRecoveryWallet(address _wallet) public onlySigners {
        signers[_wallet] = false;
    }
    
    function addRecoveryWalletBatch(address[] memory _wallets) public onlySigners {
        for (uint i = 0; i < _wallets.length; i++) {
            addRecoveryWallet(_wallets[i]);
        }
    }
    
    function removeRecoveryWalletBatch(address[] memory _wallets) public onlySigners {
        for (uint i = 0; i < _wallets.length; i++) {
            removeRecoveryWallet(_wallets[i]);
        }
    }
}

