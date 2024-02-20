
/** 
 *  SourceUnit: c:\Users\anjan\OneDrive\Desktop\ai-protocol-contracts\ai-protocol-contracts\contracts\bonding_curves\RewardSystem.sol
*/
            
////// SPDX-License-Identifier-FLATTEN-SUPPRESS-WARNING: MIT
pragma solidity ^0.8.2;
abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}
////import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title Initializable Role-based Access Control (RBAC) // ERC1967Proxy
 *
 * @notice Access control smart contract provides an API to check
 *      if a specific operation is permitted globally and/or
 *      if a particular user has a permission to execute it.
 *
 * @notice This contract is inherited by other contracts requiring the role-based access control (RBAC)
 *      protection for the restricted access functions
 *
 * @notice It deals with two main entities: features and roles.
 *
 * @notice Features are designed to be used to enable/disable public functions
 *      of the smart contract (used by a wide audience).
 * @notice User roles are designed to control the access to restricted functions
 *      of the smart contract (used by a limited set of maintainers).
 *
 * @notice Terms "role", "permissions" and "set of permissions" have equal meaning
 *      in the documentation text and may be used interchangeably.
 * @notice Terms "permission", "single permission" implies only one permission bit set.
 *
 * @notice Access manager is a special role which allows to grant/revoke other roles.
 *      Access managers can only grant/revoke permissions which they have themselves.
 *      As an example, access manager with no other roles set can only grant/revoke its own
 *      access manager permission and nothing else.
 *
 * @notice Access manager permission should be treated carefully, as a super admin permission:
 *      Access manager with even no other permission can interfere with another account by
 *      granting own access manager permission to it and effectively creating more powerful
 *      permission set than its own.
 *
 * @dev Both current and OpenZeppelin AccessControl implementations feature a similar API
 *      to check/know "who is allowed to do this thing".
 * @dev Zeppelin implementation is more flexible:
 *      - it allows setting unlimited number of roles, while current is limited to 256 different roles
 *      - it allows setting an admin for each role, while current allows having only one global admin
 * @dev Current implementation is more lightweight:
 *      - it uses only 1 bit per role, while Zeppelin uses 256 bits
 *      - it allows setting up to 256 roles at once, in a single transaction, while Zeppelin allows
 *        setting only one role in a single transaction
 *
 * @dev This smart contract is designed to be inherited by other
 *      smart contracts which require access control management capabilities.
 *
 * @dev Access manager permission has a bit 255 set.
 *      This bit must not be used by inheriting contracts for any other permissions/features.
 *
 * @dev This is an initializable version of the RBAC, based on Zeppelin implementation,
 *      it can be used for ERC1967 proxies, as well as for EIP-1167 minimal proxies
 *      see https://docs.openzeppelin.com/contracts/4.x/upgradeable
 *      see https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable
 *      see https://forum.openzeppelin.com/t/uups-proxies-tutorial-solidity-javascript/7786
 *      see https://eips.ethereum.org/EIPS/eip-1167
 *      see https://docs.openzeppelin.com/contracts/4.x/api/proxy#Clones
 *
 * @author Basil Gorin
 */
abstract contract InitializableAccessControl is Initializable {
	/**
	 * @dev Privileged addresses with defined roles/permissions
	 * @dev In the context of ERC20/ERC721 tokens these can be permissions to
	 *      allow minting or burning tokens, transferring on behalf and so on
	 *
	 * @dev Maps user address to the permissions bitmask (role), where each bit
	 *      represents a permission
	 * @dev Bitmask 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
	 *      represents all possible permissions
	 * @dev 'This' address mapping represents global features of the smart contract
	 *
	 * @dev We keep the mapping private to prevent direct writes to it from the inheriting
	 *      contracts, `getRole()` and `updateRole()` functions should be used instead
	 */
	mapping(address => uint256) private userRoles;

	/**
	 * @dev Empty reserved space in storage. The size of the __gap array is calculated so that
	 *      the amount of storage used by a contract always adds up to the 50.
	 *      See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
	 */
	uint256[49] private __gap;

	/**
	 * @notice Access manager is responsible for assigning the roles to users,
	 *      enabling/disabling global features of the smart contract
	 * @notice Access manager can add, remove and update user roles,
	 *      remove and update global features
	 *
	 * @dev Role ROLE_ACCESS_MANAGER allows modifying user roles and global features
	 * @dev Role ROLE_ACCESS_MANAGER has single bit at position 255 enabled
	 */
	uint256 public constant ROLE_ACCESS_MANAGER = 0x8000000000000000000000000000000000000000000000000000000000000000;

	/**
	 * @notice Upgrade manager is responsible for smart contract upgrades,
	 *      see https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable
	 *      see https://docs.openzeppelin.com/contracts/4.x/upgradeable
	 *
	 * @dev Role ROLE_UPGRADE_MANAGER allows passing the _authorizeUpgrade() check
	 * @dev Role ROLE_UPGRADE_MANAGER has single bit at position 254 enabled
	 */
	uint256 public constant ROLE_UPGRADE_MANAGER = 0x4000000000000000000000000000000000000000000000000000000000000000;

	/**
	 * @dev Bitmask representing all the possible permissions (super admin role)
	 * @dev Has all the bits are enabled (2^256 - 1 value)
	 */
	uint256 private constant FULL_PRIVILEGES_MASK = type(uint256).max; // before 0.8.0: uint256(-1) overflows to 0xFFFF...

	/**
	 * @dev Fired in updateRole() and updateFeatures()
	 *
	 * @param operator address which was granted/revoked permissions
	 * @param requested permissions requested
	 * @param assigned permissions effectively set
	 */
	event RoleUpdated(address indexed operator, uint256 requested, uint256 assigned);

	/**
	 * @notice Function modifier making a function defined as public behave as restricted
	 *      (so that only a pre-configured set of accounts can execute it)
	 *
	 * @param role the role transaction executor is required to have;
	 *      the function throws an "access denied" exception if this condition is not met
	 */
	modifier restrictedTo(uint256 role) {
		// verify the access permission
		require(isSenderInRole(role), "access denied");

		// execute the rest of the function
		_;
	}

	/**
	 * @dev Creates/deploys the ACL implementation to be used in a proxy
	 *
	 * @dev Note:
	 *      the implementation is already initialized and
	 *      `_postConstruct` is not executable on the implementation
	 *      `_postConstruct` is still available in the context of a proxy
	 *      and should be executed on the proxy deployment (in the same tx)
	 */
	 // constructor() initializer {}

	/**
	 * @dev Contract initializer, sets the contract owner to have full privileges
	 *
	 * @dev Can be executed only once, reverts when executed second time
	 *
	 * @dev ////IMPORTANT:
	 *      this function SHOULD be executed during proxy deployment (in the same transaction)
	 *
	 * @param _owner smart contract owner having full privileges
	 */
	function _postConstruct(address _owner) internal virtual onlyInitializing {
		// grant owner full privileges
		__setRole(_owner, FULL_PRIVILEGES_MASK, FULL_PRIVILEGES_MASK);
	}

	/**
	 * @dev Highest version that has been initialized.
	 *      Non-zero value means contract was already initialized.
	 * @dev see {Initializable}, {reinitializer}.
	 *
	 * @return highest version that has been initialized
	 */
/*
	function getInitializedVersion() public view returns(uint64) {
		// delegate to `_getInitializedVersion`
		return _getInitializedVersion();
	}
*/

	/**
	 * @notice Retrieves globally set of features enabled
	 *
	 * @dev Effectively reads userRoles role for the contract itself
	 *
	 * @return 256-bit bitmask of the features enabled
	 */
	function features() public view returns (uint256) {
		// features are stored in 'this' address mapping of `userRoles`
		return getRole(address(this));
	}

	/**
	 * @notice Updates set of the globally enabled features (`features`),
	 *      taking into account sender's permissions
	 *
	 * @dev Requires transaction sender to have `ROLE_ACCESS_MANAGER` permission
	 * @dev Function is left for backward compatibility with older versions
	 *
	 * @param _mask bitmask representing a set of features to enable/disable
	 */
	function updateFeatures(uint256 _mask) public {
		// delegate call to `updateRole`
		updateRole(address(this), _mask);
	}

	/**
	 * @notice Reads the permissions (role) for a given user from the `userRoles` mapping
	 *      (privileged addresses with defined roles/permissions)
	 * @notice In the context of ERC20/ERC721 tokens these can be permissions to
	 *      allow minting or burning tokens, transferring on behalf and so on
	 *
	 * @dev Having a simple getter instead of making the mapping public
	 *      allows enforcing the encapsulation of the mapping and protects from
	 *      writing to it directly in the inheriting smart contracts
	 *
	 * @param operator address of a user to read permissions for,
	 *      or self address to read global features of the smart contract
	 */
	function getRole(address operator) public view returns(uint256) {
		// read the value from `userRoles` and return
		return userRoles[operator];
	}

	/**
	 * @notice Updates set of permissions (role) for a given user,
	 *      taking into account sender's permissions.
	 *
	 * @dev Setting role to zero is equivalent to removing an all permissions
	 * @dev Setting role to `FULL_PRIVILEGES_MASK` is equivalent to
	 *      copying senders' permissions (role) to the user
	 * @dev Requires transaction sender to have `ROLE_ACCESS_MANAGER` permission
	 *
	 * @param operator address of a user to alter permissions for,
	 *       or self address to alter global features of the smart contract
	 * @param role bitmask representing a set of permissions to
	 *      enable/disable for a user specified
	 */
	function updateRole(address operator, uint256 role) public {
		// caller must have a permission to update user roles
		require(isSenderInRole(ROLE_ACCESS_MANAGER), "access denied");

		// evaluate the role and reassign it
		__setRole(operator, role, _evaluateBy(msg.sender, getRole(operator), role));
	}

	/**
	 * @notice Determines the permission bitmask an operator can set on the
	 *      target permission set
	 * @notice Used to calculate the permission bitmask to be set when requested
	 *     in `updateRole` and `updateFeatures` functions
	 *
	 * @dev Calculated based on:
	 *      1) operator's own permission set read from userRoles[operator]
	 *      2) target permission set - what is already set on the target
	 *      3) desired permission set - what do we want set target to
	 *
	 * @dev Corner cases:
	 *      1) Operator is super admin and its permission set is `FULL_PRIVILEGES_MASK`:
	 *        `desired` bitset is returned regardless of the `target` permission set value
	 *        (what operator sets is what they get)
	 *      2) Operator with no permissions (zero bitset):
	 *        `target` bitset is returned regardless of the `desired` value
	 *        (operator has no authority and cannot modify anything)
	 *
	 * @dev Example:
	 *      Consider an operator with the permissions bitmask     00001111
	 *      is about to modify the target permission set          01010101
	 *      Operator wants to set that permission set to          00110011
	 *      Based on their role, an operator has the permissions
	 *      to update only lowest 4 bits on the target, meaning that
	 *      high 4 bits of the target set in this example is left
	 *      unchanged and low 4 bits get changed as desired:      01010011
	 *
	 * @param operator address of the contract operator which is about to set the permissions
	 * @param target input set of permissions to operator is going to modify
	 * @param desired desired set of permissions operator would like to set
	 * @return resulting set of permissions given operator will set
	 */
	function _evaluateBy(address operator, uint256 target, uint256 desired) internal view returns (uint256) {
		// read operator's permissions
		uint256 p = getRole(operator);

		// taking into account operator's permissions,
		// 1) enable the permissions desired on the `target`
		target |= p & desired;
		// 2) disable the permissions desired on the `target`
		target &= FULL_PRIVILEGES_MASK ^ (p & (FULL_PRIVILEGES_MASK ^ desired));

		// return calculated result
		return target;
	}

	/**
	 * @notice Checks if requested set of features is enabled globally on the contract
	 *
	 * @param required set of features to check against
	 * @return true if all the features requested are enabled, false otherwise
	 */
	function isFeatureEnabled(uint256 required) public view returns (bool) {
		// delegate call to `__hasRole`, passing `features` property
		return __hasRole(features(), required);
	}

	/**
	 * @notice Checks if transaction sender `msg.sender` has all the permissions required
	 *
	 * @dev Used in smart contracts only. Off-chain clients should use `isOperatorInRole`.
	 *
	 * @param required set of permissions (role) to check against
	 * @return true if all the permissions requested are enabled, false otherwise
	 */
	function isSenderInRole(uint256 required) public view returns (bool) {
		// delegate call to `isOperatorInRole`, passing transaction sender
		return isOperatorInRole(msg.sender, required);
	}

	/**
	 * @notice Checks if operator has all the permissions (role) required
	 *
	 * @param operator address of the user to check role for
	 * @param required set of permissions (role) to check
	 * @return true if all the permissions requested are enabled, false otherwise
	 */
	function isOperatorInRole(address operator, uint256 required) public view returns (bool) {
		// delegate call to `__hasRole`, passing operator's permissions (role)
		return __hasRole(getRole(operator), required);
	}

	/**
	 * @dev Sets the `assignedRole` role to the operator, logs both `requestedRole` and `actualRole`
	 *
	 * @dev Unsafe:
	 *      provides direct write access to `userRoles` mapping without any security checks,
	 *      doesn't verify the executor (msg.sender) permissions,
	 *      must be kept private at all times
	 *
	 * @param operator address of a user to alter permissions for,
	 *       or self address to alter global features of the smart contract
	 * @param requestedRole bitmask representing a set of permissions requested
	 *      to be enabled/disabled for a user specified, used only to be logged into event
	 * @param assignedRole bitmask representing a set of permissions to
	 *      enable/disable for a user specified, used to update the mapping and to be logged into event
	 */
	function __setRole(address operator, uint256 requestedRole, uint256 assignedRole) private {
		// assign the role to the operator
		userRoles[operator] = assignedRole;

		// fire an event
		emit RoleUpdated(operator, requestedRole, assignedRole);
	}

	/**
	 * @dev Checks if role `actual` contains all the permissions required `required`
	 *
	 * @param actual existent role
	 * @param required required role
	 * @return true if actual has required role (all permissions), false otherwise
	 */
	function __hasRole(uint256 actual, uint256 required) private pure returns (bool) {
		// check the bitmask for the role required and return the result
		return actual & required == required;
	}
}




/** 
 *  SourceUnit: c:\Users\anjan\OneDrive\Desktop\ai-protocol-contracts\ai-protocol-contracts\contracts\bonding_curves\RewardSystem.sol
*/
            
////// SPDX-License-Identifier-FLATTEN-SUPPRESS-WARNING: MIT
pragma solidity ^0.8.4;

/**
 * @notice Replaces built-in Solidity address.transfer and address.send functions
 *      with the address.call function
 */
library Transfers {
	/// @dev Mimics address.send forwarding 4,900 gas
	function send(address payable to, uint256 value) internal returns(bool) {
		(bool success, ) = to.call{gas: 4900, value: value}("");
		return success;
	}

	/// @dev Mimics address.transfer forwarding 4,900 gas
	function transfer(address payable to, uint256 value) internal {
		require(send(to, value), "failed to send ether");
	}

	/// @dev Alias for `send`
	function send1(address payable to, uint256 value) internal returns(bool) {
		return send(to, value);
	}

	/// @dev Alias for `transfer`
	function transfer1(address payable to, uint256 value) internal {
		transfer(to, value);
	}
}




/** 
 *  SourceUnit: c:\Users\anjan\OneDrive\Desktop\ai-protocol-contracts\ai-protocol-contracts\contracts\bonding_curves\RewardSystem.sol
*/
            
////// SPDX-License-Identifier-FLATTEN-SUPPRESS-WARNING: MIT
pragma solidity ^0.8.2;

////import "./InitializableAccessControl.sol";
////import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title Upgradeable Role-based Access Control (RBAC) // ERC1967Proxy
 *
 * @notice Access control smart contract provides an API to check
 *      if a specific operation is permitted globally and/or
 *      if a particular user has a permission to execute it.
 *
 * @notice This contract is inherited by other contracts requiring the role-based access control (RBAC)
 *      protection for the restricted access functions
 *
 * @notice It deals with two main entities: features and roles.
 *
 * @notice Features are designed to be used to enable/disable public functions
 *      of the smart contract (used by a wide audience).
 * @notice User roles are designed to control the access to restricted functions
 *      of the smart contract (used by a limited set of maintainers).
 *
 * @notice Terms "role", "permissions" and "set of permissions" have equal meaning
 *      in the documentation text and may be used interchangeably.
 * @notice Terms "permission", "single permission" implies only one permission bit set.
 *
 * @notice Access manager is a special role which allows to grant/revoke other roles.
 *      Access managers can only grant/revoke permissions which they have themselves.
 *      As an example, access manager with no other roles set can only grant/revoke its own
 *      access manager permission and nothing else.
 *
 * @notice Access manager permission should be treated carefully, as a super admin permission:
 *      Access manager with even no other permission can interfere with another account by
 *      granting own access manager permission to it and effectively creating more powerful
 *      permission set than its own.
 *
 * @dev Both current and OpenZeppelin AccessControl implementations feature a similar API
 *      to check/know "who is allowed to do this thing".
 * @dev Zeppelin implementation is more flexible:
 *      - it allows setting unlimited number of roles, while current is limited to 256 different roles
 *      - it allows setting an admin for each role, while current allows having only one global admin
 * @dev Current implementation is more lightweight:
 *      - it uses only 1 bit per role, while Zeppelin uses 256 bits
 *      - it allows setting up to 256 roles at once, in a single transaction, while Zeppelin allows
 *        setting only one role in a single transaction
 *
 * @dev This smart contract is designed to be inherited by other
 *      smart contracts which require access control management capabilities.
 *
 * @dev Access manager permission has a bit 255 set.
 *      This bit must not be used by inheriting contracts for any other permissions/features.
 *
 * @dev This is an upgradeable version of the ACL, based on Zeppelin implementation for ERC1967,
 *      see https://docs.openzeppelin.com/contracts/4.x/upgradeable
 *      see https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable
 *      see https://forum.openzeppelin.com/t/uups-proxies-tutorial-solidity-javascript/7786
 *
 * @author Basil Gorin
 */
abstract contract UpgradeableAccessControl is InitializableAccessControl, UUPSUpgradeable {
	/**
	 * @dev Creates/deploys the ACL implementation to be used in a proxy
	 *
	 * @dev Note:
	 *      the implementation is already initialized and
	 *      `_postConstruct` is not executable on the implementation
	 *      `_postConstruct` is still available in the context of a proxy
	 *      and should be executed on the proxy deployment (in the same tx)
	 */
	constructor() initializer {}

	/**
	 * @notice Returns an address of the implementation smart contract,
	 *      see ERC1967Upgrade._getImplementation()
	 *
	 * @return the current implementation address
	 */
	function getImplementation() public view virtual returns (address) {
		// delegate to `ERC1967Upgrade._getImplementation()`
		return _getImplementation();
	}

	/**
	 * @inheritdoc UUPSUpgradeable
	 */
	function _authorizeUpgrade(address) internal virtual override {
		// caller must have a permission to upgrade the contract
		require(isSenderInRole(ROLE_UPGRADE_MANAGER), "access denied");
	}
}




/** 
 *  SourceUnit: c:\Users\anjan\OneDrive\Desktop\ai-protocol-contracts\ai-protocol-contracts\contracts\bonding_curves\RewardSystem.sol
*/
            
////// SPDX-License-Identifier-FLATTEN-SUPPRESS-WARNING: MIT
pragma solidity ^0.8.4;

/**
 * @title EIP-20: ERC-20 Token Standard
 *
 * @notice The ERC-20 (Ethereum Request for Comments 20), proposed by Fabian Vogelsteller in November 2015,
 *      is a Token Standard that implements an API for tokens within Smart Contracts.
 *
 * @notice It provides functionalities like to transfer tokens from one account to another,
 *      to get the current token balance of an account and also the total supply of the token available on the network.
 *      Besides these it also has some other functionalities like to approve that an amount of
 *      token from an account can be spent by a third party account.
 *
 * @notice If a Smart Contract implements the following methods and events it can be called an ERC-20 Token
 *      Contract and, once deployed, it will be responsible to keep track of the created tokens on Ethereum.
 *
 * @notice See https://ethereum.org/en/developers/docs/standards/tokens/erc-20/
 * @notice See https://eips.ethereum.org/EIPS/eip-20
 */
interface ERC20 {
	/**
	 * @dev Fired in transfer(), transferFrom() to indicate that token transfer happened
	 *
	 * @param from an address tokens were consumed from
	 * @param to an address tokens were sent to
	 * @param value number of tokens transferred
	 */
	event Transfer(address indexed from, address indexed to, uint256 value);

	/**
	 * @dev Fired in approve() to indicate an approval event happened
	 *
	 * @param owner an address which granted a permission to transfer
	 *      tokens on its behalf
	 * @param spender an address which received a permission to transfer
	 *      tokens on behalf of the owner `_owner`
	 * @param value amount of tokens granted to transfer on behalf
	 */
	event Approval(address indexed owner, address indexed spender, uint256 value);

	/**
	 * @return name of the token (ex.: USD Coin)
	 */
	// OPTIONAL - This method can be used to improve usability,
	// but interfaces and other contracts MUST NOT expect these values to be present.
	// function name() external view returns (string memory);

	/**
	 * @return symbol of the token (ex.: USDC)
	 */
	// OPTIONAL - This method can be used to improve usability,
	// but interfaces and other contracts MUST NOT expect these values to be present.
	// function symbol() external view returns (string memory);

	/**
	 * @dev Returns the number of decimals used to get its user representation.
	 *      For example, if `decimals` equals `2`, a balance of `505` tokens should
	 *      be displayed to a user as `5,05` (`505 / 10 ** 2`).
	 *
	 * @dev Tokens usually opt for a value of 18, imitating the relationship between
	 *      Ether and Wei. This is the value {ERC20} uses, unless this function is
	 *      overridden;
	 *
	 * @dev NOTE: This information is only used for _display_ purposes: it in
	 *      no way affects any of the arithmetic of the contract, including
	 *      {IERC20-balanceOf} and {IERC20-transfer}.
	 *
	 * @return token decimals
	 */
	// OPTIONAL - This method can be used to improve usability,
	// but interfaces and other contracts MUST NOT expect these values to be present.
	// function decimals() external view returns (uint8);

	/**
	 * @return the amount of tokens in existence
	 */
	function totalSupply() external view returns (uint256);

	/**
	 * @notice Gets the balance of a particular address
	 *
	 * @param _owner the address to query the the balance for
	 * @return balance an amount of tokens owned by the address specified
	 */
	function balanceOf(address _owner) external view returns (uint256 balance);

	/**
	 * @notice Transfers some tokens to an external address or a smart contract
	 *
	 * @dev Called by token owner (an address which has a
	 *      positive token balance tracked by this smart contract)
	 * @dev Throws on any error like
	 *      * insufficient token balance or
	 *      * incorrect `_to` address:
	 *          * zero address or
	 *          * self address or
	 *          * smart contract which doesn't support ERC20
	 *
	 * @param _to an address to transfer tokens to,
	 *      must be either an external address or a smart contract,
	 *      compliant with the ERC20 standard
	 * @param _value amount of tokens to be transferred,, zero
	 *      value is allowed
	 * @return success true on success, throws otherwise
	 */
	function transfer(address _to, uint256 _value) external returns (bool success);

	/**
	 * @notice Transfers some tokens on behalf of address `_from' (token owner)
	 *      to some other address `_to`
	 *
	 * @dev Called by token owner on his own or approved address,
	 *      an address approved earlier by token owner to
	 *      transfer some amount of tokens on its behalf
	 * @dev Throws on any error like
	 *      * insufficient token balance or
	 *      * incorrect `_to` address:
	 *          * zero address or
	 *          * same as `_from` address (self transfer)
	 *          * smart contract which doesn't support ERC20
	 *
	 * @param _from token owner which approved caller (transaction sender)
	 *      to transfer `_value` of tokens on its behalf
	 * @param _to an address to transfer tokens to,
	 *      must be either an external address or a smart contract,
	 *      compliant with the ERC20 standard
	 * @param _value amount of tokens to be transferred,, zero
	 *      value is allowed
	 * @return success true on success, throws otherwise
	 */
	function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);

	/**
	 * @notice Approves address called `_spender` to transfer some amount
	 *      of tokens on behalf of the owner (transaction sender)
	 *
	 * @dev Transaction sender must not necessarily own any tokens to grant the permission
	 *
	 * @param _spender an address approved by the caller (token owner)
	 *      to spend some tokens on its behalf
	 * @param _value an amount of tokens spender `_spender` is allowed to
	 *      transfer on behalf of the token owner
	 * @return success true on success, throws otherwise
	 */
	function approve(address _spender, uint256 _value) external returns (bool success);

	/**
	 * @notice Returns the amount which _spender is still allowed to withdraw from _owner.
	 *
	 * @dev A function to check an amount of tokens owner approved
	 *      to transfer on its behalf by some other address called "spender"
	 *
	 * @param _owner an address which approves transferring some tokens on its behalf
	 * @param _spender an address approved to transfer some tokens on behalf
	 * @return remaining an amount of tokens approved address `_spender` can transfer on behalf
	 *      of token owner `_owner`
	 */
	function allowance(address _owner, address _spender) external view returns (uint256 remaining);
}

/**
 * @title Mintable/burnable ERC20 Extension
 *
 * @notice Adds mint/burn functions to ERC20 interface, these functions
 *      are usually present in ERC20 implementations, but these become
 *      a must for the bridged tokens in L2 since the bridge on L2
 *      needs to have a way to mint tokens deposited from L1 to L2
 *      and to burn tokens to be withdrawn from L2 to L1
 */
interface MintableBurnableERC20 is ERC20 {
	/**
	 * @dev Mints (creates) some tokens to address specified
	 * @dev The value specified is treated as is without taking
	 *      into account what `decimals` value is
	 *
	 * @param _to an address to mint tokens to
	 * @param _value an amount of tokens to mint (create)
	 */
	function mint(address _to, uint256 _value) external;

	/**
	 * @dev Burns (destroys) some tokens from the address specified
	 *
	 * @dev The value specified is treated as is without taking
	 *      into account what `decimals` value is
	 *
	 * @param _from an address to burn some tokens from
	 * @param _value an amount of tokens to burn (destroy)
	 */
	function burn(address _from, uint256 _value) external;
}


/** 
 *  SourceUnit: c:\Users\anjan\OneDrive\Desktop\ai-protocol-contracts\ai-protocol-contracts\contracts\bonding_curves\RewardSystem.sol
*/

////// SPDX-License-Identifier-FLATTEN-SUPPRESS-WARNING: MIT
pragma solidity ^0.8.4;

////import "../interfaces/ERC20Spec.sol";
////import "../utils/UpgradeableAccessControl.sol";
////import "../utils/Transfers.sol";
////import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title Leaderboard Reward System
 *
 * @notice leaderboard reward system designated to release reward for all leaderboard winner
 *
 * @notice reward system uses merkle root to maintain list of winners and reward amounts,
 *      once new winner list is announced, merkle root will be update which include
 *      new winner list and past winners and tier respective won reward amount.
 *
 * @notice leaderboard reward system is proxy upgradeable.
 *
 */
contract RewardSystem is UpgradeableAccessControl {
	// Use Zeppelin MerkleProof Library to verify Merkle proofs
	using MerkleProof for bytes32[];

	// Input data root, Merkle tree root for an array of (address, totalReward) pairs,
	// Merkle root effectively "compresses" the (potentially) huge array of data elements
	// and allows to store it in a single 256-bits storage slot on-chain
	bytes32 public root;

	// maps userAddress => total claimed reward
	// mapping packed into array, the last array element is "active"
	// while the first n-1 elements are "archive" and not used in the contract
	mapping(address => uint256) [] private claimedRewards;

	// ERC20 reward token address
	// reward system type:
	// zero address means contract supports ETH reward
	// non-zero address means contract supports ERC20 reward
	ERC20 public erc20RewardToken;

	// cumulative reward claimed
	uint256 public totalClaimedReward;

	/**
	 * @notice Data Root manager is responsible for supplying the valid input data array
	 *      Merkle root which then can be used to check total reward won by user.
	 *
	 * @dev Role ROLE_DATA_ROOT_MANAGER allows setting the Merkle tree root via setInputDataRoot()
	 */
	uint32 public constant ROLE_DATA_ROOT_MANAGER = 0x0001_0000;

	/**
	 * @notice Enables the airdrop, redeeming the tokens
	 *
	 * @dev Feature FEATURE_CLAIM_ACTIVE must be enabled in order to
	 *      allow user to claim pending reward
	 */
	uint32 public constant FEATURE_CLAIM_ACTIVE = 0x0000_0001;

	/**
	 * @dev Fired in setInputDataRoot()
	 *
	 * @param by an address which executed the operation
	 * @param root new Merkle root value
	 */
	event RootChanged(address indexed by, bytes32 root);

	/**
	 * @dev Fired in claimEthReward()
	 *
	 * @param user user address
	 * @param amount amount of reward transferred
	 */
	event EthRewardClaimed(address indexed user, uint256 amount);

	/**
	 * @dev Fired in claimErc20Reward()
	 *
	 * @param rewardToken erc20 reward token address
	 * @param user user address
	 * @param amount amount of reward transferred
	 */
	event ERC20RewardClaimed(address indexed rewardToken, address indexed user, uint256 amount);

	/**
	 * @dev Fired in the default receive()
	 *
	 * @param value amount received 
	 */
	event PaymentReceived(uint256 value);

	/**
	 * @dev Fired in resetClaimedRewards()
	 *
	 * @param size new size of the claimedRewards array
	 */
	event ClaimedRewardsReset(uint256 size);

	/**
	 * @dev "Constructor replacement" for a smart contract with a delayed initialization (post-deployment initialization)
	 *
	 * @param _erc20RewardToken ERC20 reward token address
	 *      zero address means contract supports ETH reward
	 *      non-zero address means contract supports ERC20 reward
	 */
	function postConstruct(address _erc20RewardToken) public virtual initializer {
		// execute parent initializer
		_postConstruct(msg.sender);

		// zero address is OK meaning we use ETH reward mode
		erc20RewardToken = ERC20(_erc20RewardToken);

		// initialize first storage slot for claimedRewards
		claimedRewards.push();
	}

	// Function to receive Ether. msg.data must be empty
	receive() external payable {
		require(rewardSystemType(), "ETH payments not supported");
		emit PaymentReceived(msg.value);
	}

	/**
	 * @dev Read claimedRewards at the "active" last index for a given address
	 *
	 * @param userAddress address to update the value for
	 * @return total rewards paid or to be paid
	 */
	function claimedReward(address userAddress) public view returns(uint256) {
		// read the data from the "active" last storage slot and return
		return claimedReward(claimedRewards.length - 1, userAddress);
	}

	/**
	 * @dev Read claimedRewards at a given index for a given address
	 *
	 * @param index zero-based storage index
	 * @param userAddress address to update the value for
	 * @return total rewards paid or to be paid
	 */
	function claimedReward(uint256 index, address userAddress) public view returns(uint256) {
		// read the data from the "index" storage slot and return
		return claimedRewards[index][userAddress];
	}

	/**
	 * @dev Update claimedRewards at the "active" last index for a given address
	 *
	 * @param userAddress address to update the value for
	 * @param value the reward value to set
	 */
	function __updateClaimedReward(address userAddress, uint256 value) private {
		// update the data at the "active" last storage slot
		__updateClaimedReward(claimedRewards.length - 1, userAddress, value);
	}

	/**
	 * @dev Update claimedRewards at a given index for a given address
	 *
	 * @param index zero-based storage index
	 * @param userAddress address to update the value for
	 * @param value the reward value to set
	 */
	function __updateClaimedReward(uint256 index, address userAddress, uint256 value) private {
		// update the data at the "index" storage slot
		claimedRewards[index][userAddress] = value;
	}

	/**
	 * @dev Restricted access function to reset claimedRewards mapping;
	 *      technically implemented by moving mapping storage pointer to free space
	 */
	function resetClaimedRewards() public {
		// reset the Merkle root; this also ensures we have "ROLE_DATA_ROOT_MANAGER" role
		setInputDataRoot(bytes32(0));

		// move the claimedRewards storage to the next slot
		claimedRewards.push();

		// emit an event
		emit ClaimedRewardsReset(claimedRewards.length);
	}

	/**
	 * @notice total amount of token `_totalReward` to an address `_to`, verifying the validity
	 *      of a `(_to, _totalReward)` pair via the Merkle proof `_proof`
	 *
	 * @dev Merkle tree and proof can be constructed using the `web3-utils`, `merkletreejs`,
	 *      and `keccak256` npm packages:
	 *      1. Hash the original array data elements (_to, _totalReward) via `web3.utils.soliditySha3`,
	 *         making sure the packing order.
	 *      2. Create a sorted MerkleTree (`merkletreejs`) from the hashed array, use `keccak256`
	 *         from the `keccak256` npm package as a hashing function, do not hash leaves
	 *         (already hashed in step 1); Ex. MerkleTree options: {hashLeaves: false, sortPairs: true}
	 *      3. For any given data element (_to, _totalReward) the proof is constructed by hashing it
	 *         (as in step 1) and querying the MerkleTree for a proof, providing the hashed element
	 *         as a leaf
	 *
	 * @dev Throws is the data or merkle proof supplied is not valid
	 *
	 * @param _to an address to whom reward to be sent
	 * @param _totalReward total reward accumulated by a user across all competitions
	 * @param _proof Merkle proof for the (_to, _totalReward) pair supplied
	 */
	function claimReward(address payable _to, uint256 _totalReward, bytes32[] memory _proof) external {
		// verify airdrop is in active state
		require(isFeatureEnabled(FEATURE_CLAIM_ACTIVE), "redeems are disabled");

		// verify the `(_to, _totalReward)` pair is valid
		require(isClaimValid(_to, _totalReward, _proof), "invalid request");

		// check user has reward to claim
		uint256 claimed = claimedReward(_to);
		require(claimed < _totalReward, "nothing to claim");
		uint256 claimableAmount = _totalReward - claimed;

		// update reward details
		__updateClaimedReward(_to, _totalReward);
		totalClaimedReward += claimableAmount;

		if (rewardSystemType()) {
			// transfer ether to user
			Transfers.transfer(_to, claimableAmount);

			// emit an event
			emit EthRewardClaimed(_to, claimableAmount);
		}
		else {
			// transfer erc20 reward token to user
			erc20RewardToken.transfer(_to, claimableAmount);

			// emit an event
			emit ERC20RewardClaimed(address(erc20RewardToken), _to, claimableAmount);
		}
	}

	/**
	 * @notice Restricted access function to update input data root (Merkle tree root),
	 *      and to define, effectively, the tokens to be created by this smart contract
	 *
	 * @dev Requires executor to have `ROLE_DATA_MANAGER` permission
	 *
	 * @param _root Merkle tree root for the input data array
	 */
	function setInputDataRoot(bytes32 _root) public {
		// verify the access permission
		require(isSenderInRole(ROLE_DATA_ROOT_MANAGER), "access denied");

		// update input data Merkle tree root
		root = _root;

		// emit an event
		emit RootChanged(msg.sender, _root);
	}

	/**
	 * @notice Verifies the validity of a `(_to, _totalReward)` pair supplied based on the Merkle root
	 *      of the entire `(_to, _totalReward)` data array (pre-stored in the contract), and the Merkle
	 *      proof `_proof` for the particular `(_to, _totalReward)` pair supplied
	 *
	 * @dev Merkle tree and proof can be constructed using the `web3-utils`, `merkletreejs`,
	 *      and `keccak256` npm packages:
	 *      1. Hash the original array data elements (_to, _totalReward) via `web3.utils.soliditySha3`,
	 *         making sure the packing order.
	 *      2. Create a sorted MerkleTree (`merkletreejs`) from the hashed array, use `keccak256`
	 *         from the `keccak256` npm package as a hashing function, do not hash leaves
	 *         (already hashed in step 1); Ex. MerkleTree options: {hashLeaves: false, sortPairs: true}
	 *      3. For any given data element (_to, _totalReward) the proof is constructed by hashing it
	 *         (as in step 1) and querying the MerkleTree for a proof, providing the hashed element
	 *         as a leaf
	 *
	 * @param _to an address to whom reward to be sent
	 * @param _totalReward total reward accumulated by a user across all competitions
	 * @param _proof Merkle proof for the (_to, _totalReward) pair supplied
	 * @return true if Merkle proof is valid (data belongs to the original array), false otherwise
	 */
	function isClaimValid(address _to, uint256 _totalReward, bytes32[] memory _proof) public view returns(bool) {
		// construct Merkle tree leaf from the inputs supplied
		bytes32 leaf = keccak256(abi.encodePacked(_to, _totalReward));

		// verify the proof supplied, and return the verification result
		return _proof.verify(root, leaf);
	}

	/**
	 * @notice Reward system type
	 *
	 * @return true if contract supports ETH reward
	 *         false if contract supports ERC20 reward
	 */
	function rewardSystemType() public view returns(bool) {
		// derive from the token address
		return address(erc20RewardToken) == address(0);
	}
}

