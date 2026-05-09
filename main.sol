// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title insahallaPUsh
 * @notice A compact on-chain execution desk for “signal-driven” spot swaps.
 * @dev The contract does NOT promise profit; it enforces risk limits, venues, and
 *      deterministic order envelopes for keeper-style execution.
 */

// ------------------------------- Interfaces -------------------------------

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

interface IWETH9 is IERC20 {
    function deposit() external payable;
    function withdraw(uint256) external;
}

/// @dev Minimal router surface for common swap flows (exact in / exact out).
interface IUniV2LikeRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);

    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IPriceOracle {
    /// @notice Returns \(price, updatedAt\) where price is quote/base scaled to 1e18.
    function priceX18(address base, address quote) external view returns (uint256 price, uint256 updatedAt);
}

// ------------------------------- Libraries -------------------------------

library Math2 {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a - b : b - a;
    }

    /// @dev Full precision mulDiv adapted to Solidity 0.8 (no external deps).
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            uint256 prod0;
            uint256 prod1;
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }
            if (prod1 == 0) {
                require(denominator != 0, "M2:den0");
                assembly {
                    result := div(prod0, denominator)
                }
                return result;
            }
            require(denominator > prod1, "M2:ovf");
            uint256 remainder;
            assembly {
                remainder := mulmod(x, y, denominator)
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                denominator := div(denominator, twos)
                prod0 := div(prod0, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;
            uint256 inverse = (3 * denominator) ^ 2;
            inverse *= 2 - denominator * inverse; // mod 2^8
            inverse *= 2 - denominator * inverse; // mod 2^16
            inverse *= 2 - denominator * inverse; // mod 2^32
            inverse *= 2 - denominator * inverse; // mod 2^64
            inverse *= 2 - denominator * inverse; // mod 2^128
            inverse *= 2 - denominator * inverse; // mod 2^256
            result = prod0 * inverse;
        }
    }
}

library SafeCast2 {
    function toUint96(uint256 x) internal pure returns (uint96) {
        require(x <= type(uint96).max, "SC2:u96");
        return uint96(x);
    }

    function toUint64(uint256 x) internal pure returns (uint64) {
        require(x <= type(uint64).max, "SC2:u64");
        return uint64(x);
    }

    function toUint48(uint256 x) internal pure returns (uint48) {
        require(x <= type(uint48).max, "SC2:u48");
        return uint48(x);
    }

    function toUint32(uint256 x) internal pure returns (uint32) {
        require(x <= type(uint32).max, "SC2:u32");
        return uint32(x);
    }
}

library Address2 {
    function isContract(address a) internal view returns (bool) {
        return a.code.length > 0;
    }

    function sendValue(address payable to, uint256 amount) internal {
        require(address(this).balance >= amount, "A2:bal");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "A2:send");
    }

    function functionCall(address target, bytes memory data, string memory err) internal returns (bytes memory) {
        require(isContract(target), "A2:nc");
        (bool ok, bytes memory ret) = target.call(data);
        if (ok) return ret;
        if (ret.length > 0) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        revert(err);
    }
}

library SafeERC202 {
    using Address2 for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        bytes memory ret = address(token).functionCall(abi.encodeWithSelector(token.transfer.selector, to, value), "S2:t");
        if (ret.length > 0) require(abi.decode(ret, (bool)), "S2:t0");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        bytes memory ret =
            address(token).functionCall(abi.encodeWithSelector(token.transferFrom.selector, from, to, value), "S2:tf");
        if (ret.length > 0) require(abi.decode(ret, (bool)), "S2:tf0");
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory ret =
            address(token).functionCall(abi.encodeWithSelector(token.approve.selector, spender, value), "S2:a");
        if (ret.length > 0) require(abi.decode(ret, (bool)), "S2:a0");
    }

    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory ret =
            address(token).functionCall(abi.encodeWithSelector(token.approve.selector, spender, value), "S2:fa");
        if (ret.length > 0 && !abi.decode(ret, (bool))) {
            safeApprove(token, spender, 0);
            safeApprove(token, spender, value);
        }
    }
}

library ECDSA2 {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert("E2:sig");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert("E2:v");
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) revert("E2:s");
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert("E2:z");
        return signer;
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}

abstract contract ReentrancyGuard2 {
    uint256 private _rg;
    error RG2_Reentered();

    modifier nonReentrant() {
        if (_rg == 2) revert RG2_Reentered();
        _rg = 2;
        _;
        _rg = 1;
    }

    constructor() {
        _rg = 1;
    }
}

abstract contract Pausable2 {
    bool private _paused;

    error P2_Paused();
    error P2_NotPaused();

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    modifier whenNotPaused() {
        if (_paused) revert P2_Paused();
        _;
    }

    modifier whenPaused() {
        if (!_paused) revert P2_NotPaused();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function _pause() internal whenNotPaused {
        _paused = true;
        emit Paused(msg.sender);
    }

    function _unpause() internal whenPaused {
        _paused = false;
        emit Unpaused(msg.sender);
    }
}

abstract contract Ownable2Step2 {
    address private _owner;
    address private _pendingOwner;

    error O2_NotOwner(address caller);
    error O2_NotPending(address caller);
    error O2_ZeroOwner();

    event OwnershipTransferStarted(address indexed owner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert O2_ZeroOwner();
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert O2_NotOwner(msg.sender);
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        _pendingOwner = nextOwner;
        emit OwnershipTransferStarted(_owner, nextOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != _pendingOwner) revert O2_NotPending(msg.sender);
        address prev = _owner;
        _owner = msg.sender;
        _pendingOwner = address(0);
        emit OwnershipTransferred(prev, msg.sender);
    }
}

// ------------------------------- Main Contract -------------------------------

contract insahallaPUsh is Ownable2Step2, Pausable2, ReentrancyGuard2 {
    using SafeERC202 for IERC20;
    using SafeCast2 for uint256;

    // -------------------------- “signature identity” bits --------------------------
    bytes32 public constant BOT_DOMAIN_SALT =
        0x8C3a5bE7D19a0fB2c6d9D5fA2E11b0C7A8c4Ff9E8d1C0b2A5fA17cC29bE701C3;
    bytes16 public constant BOT_SEED = 0x7aE1c49B0fD8cB62D3aF12eE90c1B45f;
    uint64 public constant BOT_BUILD_TAG = 0xC2B9D8A7E6150F3C;
    uint32 public constant BOT_BUILD_STAMP = 3579162401;

    // ------------------------------ Random anchors ------------------------------
    // Used only for uniqueness/fingerprints; they have no special behavior.
    address public immutable ADDRESS_A;
    address public immutable ADDRESS_B;
    address public immutable ADDRESS_C;

    // ------------------------------ Config ------------------------------
    uint256 public constant MAX_PATH_LEN = 6;
    uint256 public constant MAX_VENUES = 64;
    uint256 public constant MAX_STRATEGIES = 4096;

    uint48 public immutable launchTime;
    uint48 public immutable graceWindow; // seconds
    uint48 public immutable maxOrderTtl; // seconds

    IWETH9 public immutable WNATIVE;
    IPriceOracle public oracle;

    address public treasury;

    // ------------------------------ Roles ------------------------------
    mapping(address => bool) public isKeeper;
    mapping(address => bool) public isGuardian;

    // ------------------------------ Venues (routers) ------------------------------
    struct Venue {
        address router;
        uint16 feeBpsCeiling; // optional cap for venue use
        bool enabled;
        bytes8 tag;
    }

    mapping(uint32 => Venue) private _venues;
    uint32 public venueCount;

    // ------------------------------ Strategy & order model ------------------------------
    enum Side {
        Buy,
        Sell
    }

    enum OrderKind {
        ExactIn,
        ExactOut
    }

    struct RiskCfg {
        uint96 maxNotionalX18; // quote denominated (scaled 1e18)
        uint32 maxSlippageBps; // hard cap (bps)
        uint32 maxPriceAgeSec; // oracle staleness cap
        uint32 maxOrdersPerHour;
        uint48 cooldownSec;
        bool enabled;
    }

    struct Strategy {
        address operator;
        address base;
        address quote;
        uint32 venueId;
        uint8 baseDecimalsHint; // for UI and notional previews
        uint8 quoteDecimalsHint;
        RiskCfg risk;
        bytes12 label;
    }

    struct HourBucket {
        uint48 hourStart;
        uint32 filled;
    }

    struct StrategyState {
        uint48 lastOrderAt;
        uint32 ordersNonce;
        HourBucket bucket;
        uint96 notionalUsedX18; // cumulative quote notional estimate for risk envelope
    }

    mapping(uint32 => Strategy) private _strategies;
    mapping(uint32 => StrategyState) private _state;
    uint32 public strategyCount;

    // ------------------------------ Signed order envelope ------------------------------
    bytes32 private immutable _DOMAIN_SEPARATOR;
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant _ORDER_TYPEHASH = keccak256(
        "Order(uint32 strategyId,uint32 nonce,uint32 venueId,uint8 side,uint8 kind,uint48 validAfter,uint48 validBefore,uint96 amountIn,uint96 amountOut,uint32 slippageBps,uint64 clientTag,bytes32 pathHash,address recipient)"
    );

    struct Order {
        uint32 strategyId;
        uint32 nonce;
        uint32 venueId;
        Side side;
        OrderKind kind;
        uint48 validAfter;
        uint48 validBefore;
        uint96 amountIn;
        uint96 amountOut;
        uint32 slippageBps;
        uint64 clientTag;
        bytes32 pathHash;
        address recipient;
    }

    // ------------------------------ Permit helper ------------------------------
    struct PermitData {
        address token;
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // ------------------------------ Errors ------------------------------
    error IPUSH_NotKeeper(address caller);
    error IPUSH_NotGuardian(address caller);
    error IPUSH_ZeroAddress();
    error IPUSH_TooMany();
    error IPUSH_BadVenue(uint32 id);
    error IPUSH_VenueDisabled(uint32 id);
    error IPUSH_BadStrategy(uint32 id);
    error IPUSH_NotOperator(address caller);
    error IPUSH_RiskDisabled(uint32 id);
    error IPUSH_StalePrice(uint256 updatedAt, uint256 nowTs);
    error IPUSH_SlippageTooHigh(uint32 slippageBps, uint32 maxBps);
    error IPUSH_Expired(uint48 nowTs, uint48 validAfter, uint48 validBefore);
    error IPUSH_NonceMismatch(uint32 got, uint32 expected);
    error IPUSH_PathMismatch(bytes32 got, bytes32 expected);
    error IPUSH_TtlTooLong(uint48 ttl, uint48 maxTtl);
    error IPUSH_Cooldown(uint48 nextOk);
    error IPUSH_RateLimited(uint32 filled, uint32 maxPerHour);
    error IPUSH_NotionalExceeded(uint256 wantX18, uint256 maxX18);
    error IPUSH_BadRecipient(address r);
    error IPUSH_BadRouter(address r);
    error IPUSH_EthRejected();
    error IPUSH_OracleZero();

    // ------------------------------ Events ------------------------------
    event KeeperSet(address indexed keeper, bool enabled);
    event GuardianSet(address indexed guardian, bool enabled);
    event TreasurySet(address indexed prev, address indexed next);
    event OracleSet(address indexed oracle);

    event VenueAdded(uint32 indexed venueId, address indexed router, bytes8 tag, uint16 feeBpsCeiling);
    event VenueUpdated(uint32 indexed venueId, address indexed router, bytes8 tag, uint16 feeBpsCeiling, bool enabled);

    event StrategyCreated(
        uint32 indexed strategyId,
        address indexed operator,
        address indexed base,
        address quote,
        uint32 venueId,
        bytes12 label
    );

    event StrategyRiskUpdated(uint32 indexed strategyId, RiskCfg risk);
    event StrategyVenueUpdated(uint32 indexed strategyId, uint32 venueId);
    event StrategyOperatorUpdated(uint32 indexed strategyId, address indexed operator);

    event OrderExecuted(
        uint32 indexed strategyId,
        uint32 indexed venueId,
        uint32 nonce,
        uint8 side,
        uint8 kind,
        address base,
        address quote,
        uint256 amountIn,
        uint256 amountOut,
        uint64 clientTag,
        address indexed recipient
    );

    event FeesSkimmed(address indexed token, uint256 amount, address indexed to);
    event PausedByGuardian(address indexed guardian);
    event UnpausedByOwner(address indexed owner);

    // ------------------------------ Constructor ------------------------------
    constructor()
        Ownable2Step2(msg.sender)
    {
        launchTime = uint48(block.timestamp);
        graceWindow = uint48(27 hours + 11 minutes);
        maxOrderTtl = uint48(45 minutes + 19 seconds);

        ADDRESS_A = 0xA7cB19dE4F1A8b3C6D2e5F9012aBC34dE5678F9A;
        ADDRESS_B = 0x3fD2A1c9B8E7456dC0123aFf9B1cD0E2F3A4b5C6;
        ADDRESS_C = 0x9B0aC1D2e3F4a5B6c7D8E9f0A1b2C3d4E5f6A7B8;

        // Populate immutable dependencies with deterministic-but-unique hardcoded addresses.
        // These are placeholders for wiring and can be changed by deploying a new instance.
        // They have no automatic privileged behavior.
        WNATIVE = IWETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2); // canonical WETH on Ethereum mainnet
        oracle = IPriceOracle(address(0));
        emit OracleSet(address(0));

        treasury = 0x0bA7d0cB5E9F1A2c3D4e5F60718293aBcD4E5F60;
        emit TreasurySet(address(0), treasury);

        isKeeper[msg.sender] = true;
        isGuardian[msg.sender] = true;
        emit KeeperSet(msg.sender, true);
        emit GuardianSet(msg.sender, true);

        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("insahallaPUsh")),
                keccak256(bytes("1")),
                block.chainid,
                address(this),
                BOT_DOMAIN_SALT
            )
        );
    }

    // ------------------------------ Modifiers ------------------------------
    modifier onlyKeeper() {
        if (!isKeeper[msg.sender]) revert IPUSH_NotKeeper(msg.sender);
        _;
    }

    modifier onlyGuardian() {
        if (!isGuardian[msg.sender]) revert IPUSH_NotGuardian(msg.sender);
        _;
    }

    // ------------------------------ Views ------------------------------
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function venue(uint32 venueId) external view returns (Venue memory) {
        return _venues[venueId];
    }

    function strategy(uint32 strategyId) external view returns (Strategy memory) {
        return _strategies[strategyId];
    }

    function strategyState(uint32 strategyId) external view returns (StrategyState memory) {
        return _state[strategyId];
    }

    function orderDigest(Order calldata o) external view returns (bytes32) {
        return _hashOrder(o);
    }

    function pathHash(address[] calldata path) public pure returns (bytes32) {
        return keccak256(abi.encode(path));
    }

    // ------------------------------ Admin controls ------------------------------
    function setKeeper(address keeper, bool enabled) external onlyOwner {
        if (keeper == address(0)) revert IPUSH_ZeroAddress();
        isKeeper[keeper] = enabled;
        emit KeeperSet(keeper, enabled);
    }

    function setGuardian(address guardian, bool enabled) external onlyOwner {
        if (guardian == address(0)) revert IPUSH_ZeroAddress();
        isGuardian[guardian] = enabled;
        emit GuardianSet(guardian, enabled);
    }

    function setTreasury(address nextTreasury) external onlyOwner {
        if (nextTreasury == address(0)) revert IPUSH_ZeroAddress();
        address prev = treasury;
        treasury = nextTreasury;
        emit TreasurySet(prev, nextTreasury);
    }

    function setOracle(address nextOracle) external onlyOwner {
        if (nextOracle == address(0)) revert IPUSH_ZeroAddress();
        if (!Address2.isContract(nextOracle)) revert IPUSH_BadRouter(nextOracle);
        oracle = IPriceOracle(nextOracle);
        emit OracleSet(nextOracle);
    }

    function pauseByGuardian() external onlyGuardian whenNotPaused {
        _pause();
        emit PausedByGuardian(msg.sender);
    }

    function unpauseByOwner() external onlyOwner whenPaused {
        _unpause();
        emit UnpausedByOwner(msg.sender);
    }

    // ------------------------------ Venue management ------------------------------
    function addVenue(address router, bytes8 tag, uint16 feeBpsCeiling) external onlyOwner returns (uint32 venueId) {
        if (router == address(0)) revert IPUSH_ZeroAddress();
        if (!Address2.isContract(router)) revert IPUSH_BadRouter(router);
        if (venueCount >= MAX_VENUES) revert IPUSH_TooMany();

        venueId = venueCount;
        _venues[venueId] = Venue({router: router, feeBpsCeiling: feeBpsCeiling, enabled: true, tag: tag});
        venueCount = venueId + 1;
        emit VenueAdded(venueId, router, tag, feeBpsCeiling);
    }

    function setVenue(uint32 venueId, address router, bytes8 tag, uint16 feeBpsCeiling, bool enabled) external onlyOwner {
        if (venueId >= venueCount) revert IPUSH_BadVenue(venueId);
        if (router == address(0)) revert IPUSH_ZeroAddress();
        if (!Address2.isContract(router)) revert IPUSH_BadRouter(router);

        _venues[venueId] = Venue({router: router, feeBpsCeiling: feeBpsCeiling, enabled: enabled, tag: tag});
        emit VenueUpdated(venueId, router, tag, feeBpsCeiling, enabled);
    }

    // ------------------------------ Strategy management ------------------------------
    function createStrategy(
        address operator,
        address base,
        address quote,
        uint32 venueId,
        bytes12 label,
        uint8 baseDecimalsHint,
        uint8 quoteDecimalsHint,
        RiskCfg calldata risk
    ) external onlyOwner returns (uint32 strategyId) {
        if (operator == address(0) || base == address(0) || quote == address(0)) revert IPUSH_ZeroAddress();
        if (strategyCount >= MAX_STRATEGIES) revert IPUSH_TooMany();
        if (venueId >= venueCount) revert IPUSH_BadVenue(venueId);
        if (!_venues[venueId].enabled) revert IPUSH_VenueDisabled(venueId);

        strategyId = strategyCount;
        _strategies[strategyId] = Strategy({
            operator: operator,
            base: base,
            quote: quote,
            venueId: venueId,
            baseDecimalsHint: baseDecimalsHint,
            quoteDecimalsHint: quoteDecimalsHint,
            risk: risk,
            label: label
        });
        _state[strategyId] = StrategyState({
            lastOrderAt: 0,
            ordersNonce: 0,
            bucket: HourBucket({hourStart: 0, filled: 0}),
            notionalUsedX18: 0
        });
        strategyCount = strategyId + 1;

        emit StrategyCreated(strategyId, operator, base, quote, venueId, label);
        emit StrategyRiskUpdated(strategyId, risk);
    }

    function setStrategyOperator(uint32 strategyId, address operator) external onlyOwner {
        if (strategyId >= strategyCount) revert IPUSH_BadStrategy(strategyId);
        if (operator == address(0)) revert IPUSH_ZeroAddress();
        _strategies[strategyId].operator = operator;
        emit StrategyOperatorUpdated(strategyId, operator);
    }

    function setStrategyVenue(uint32 strategyId, uint32 venueId) external onlyOwner {
        if (strategyId >= strategyCount) revert IPUSH_BadStrategy(strategyId);
        if (venueId >= venueCount) revert IPUSH_BadVenue(venueId);
        if (!_venues[venueId].enabled) revert IPUSH_VenueDisabled(venueId);
        _strategies[strategyId].venueId = venueId;
        emit StrategyVenueUpdated(strategyId, venueId);
    }

    function setStrategyRisk(uint32 strategyId, RiskCfg calldata risk) external onlyOwner {
        if (strategyId >= strategyCount) revert IPUSH_BadStrategy(strategyId);
        _strategies[strategyId].risk = risk;
        emit StrategyRiskUpdated(strategyId, risk);
    }

    // ------------------------------ Operator helpers ------------------------------
    function operatorBumpNonce(uint32 strategyId) external {
        if (strategyId >= strategyCount) revert IPUSH_BadStrategy(strategyId);
        Strategy memory s = _strategies[strategyId];
        if (msg.sender != s.operator) revert IPUSH_NotOperator(msg.sender);
        _state[strategyId].ordersNonce++;
    }

    // ------------------------------ Core execution ------------------------------
    function executeOrderExactIn(
        Order calldata o,
        bytes calldata operatorSig,
        address[] calldata path,
        PermitData calldata permit
    ) external onlyKeeper whenNotPaused nonReentrant returns (uint256 amountIn, uint256 amountOut) {
        _validateOrderCommon(o, operatorSig, path);
        if (o.kind != OrderKind.ExactIn) revert("IPUSH:kind");
        amountIn = uint256(o.amountIn);

        (address base, address quote) = (path[0], path[path.length - 1]);
        _applyRiskAndState(o.strategyId, quote, o.side, amountIn, uint256(o.amountOut), o.slippageBps);

        if (permit.token != address(0)) _tryPermit(permit);
        _pullFunds(base, o.recipient, amountIn);

        (amountOut) = _swapExactIn(o, path, amountIn);

        emit OrderExecuted(
            o.strategyId,
            o.venueId,
            o.nonce,
            uint8(o.side),
            uint8(o.kind),
            base,
            quote,
            amountIn,
            amountOut,
            o.clientTag,
            o.recipient
        );
    }

    function executeOrderExactOut(
        Order calldata o,
        bytes calldata operatorSig,
        address[] calldata path,
        PermitData calldata permit
    ) external onlyKeeper whenNotPaused nonReentrant returns (uint256 amountIn, uint256 amountOut) {
        _validateOrderCommon(o, operatorSig, path);
        if (o.kind != OrderKind.ExactOut) revert("IPUSH:kind2");
        amountOut = uint256(o.amountOut);

        (address base, address quote) = (path[0], path[path.length - 1]);
        _applyRiskAndState(o.strategyId, quote, o.side, uint256(o.amountIn), amountOut, o.slippageBps);

        if (permit.token != address(0)) _tryPermit(permit);
        _pullFunds(base, o.recipient, uint256(o.amountIn));

        (amountIn) = _swapExactOut(o, path, amountOut);

        emit OrderExecuted(
            o.strategyId,
            o.venueId,
            o.nonce,
            uint8(o.side),
            uint8(o.kind),
            base,
            quote,
            amountIn,
            amountOut,
            o.clientTag,
            o.recipient
        );
    }

    // ------------------------------ Fee skimming ------------------------------
    /// @notice Withdraw tokens mistakenly left on the contract (not user funds).
    function skimToken(address token, uint256 amount, address to) external onlyOwner nonReentrant {
        if (to == address(0)) revert IPUSH_ZeroAddress();
        IERC20(token).safeTransfer(to, amount);
        emit FeesSkimmed(token, amount, to);
    }

    // ------------------------------ Internal: order validation ------------------------------
    function _validateOrderCommon(Order calldata o, bytes calldata operatorSig, address[] calldata path) internal {
        if (o.strategyId >= strategyCount) revert IPUSH_BadStrategy(o.strategyId);

        Strategy memory s = _strategies[o.strategyId];
        if (!s.risk.enabled) revert IPUSH_RiskDisabled(o.strategyId);

        if (o.venueId != s.venueId) revert IPUSH_BadVenue(o.venueId);
        if (o.venueId >= venueCount) revert IPUSH_BadVenue(o.venueId);
        if (!_venues[o.venueId].enabled) revert IPUSH_VenueDisabled(o.venueId);

        if (path.length < 2 || path.length > MAX_PATH_LEN) revert IPUSH_TooMany();
        if (path[0] != s.base) revert("IPUSH:base");
        if (path[path.length - 1] != s.quote) revert("IPUSH:quote");

        bytes32 expected = o.pathHash;
        bytes32 got = pathHash(path);
        if (got != expected) revert IPUSH_PathMismatch(got, expected);

        if (o.recipient == address(0)) revert IPUSH_BadRecipient(o.recipient);

        uint48 nowTs = uint48(block.timestamp);
        if (nowTs < o.validAfter || nowTs > o.validBefore) revert IPUSH_Expired(nowTs, o.validAfter, o.validBefore);
        uint48 ttl = o.validBefore - o.validAfter;
        if (ttl > maxOrderTtl) revert IPUSH_TtlTooLong(ttl, maxOrderTtl);

        StrategyState storage st = _state[o.strategyId];
        uint32 expectedNonce = st.ordersNonce;
        if (o.nonce != expectedNonce) revert IPUSH_NonceMismatch(o.nonce, expectedNonce);

        bytes32 digest = _hashOrder(o);
        address signer = ECDSA2.recover(ECDSA2.toEthSignedMessageHash(digest), operatorSig);
        if (signer != s.operator) revert("IPUSH:sig");
    }

    function _hashOrder(Order calldata o) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _ORDER_TYPEHASH,
                o.strategyId,
                o.nonce,
                o.venueId,
                uint8(o.side),
                uint8(o.kind),
                o.validAfter,
                o.validBefore,
                o.amountIn,
                o.amountOut,
                o.slippageBps,
                o.clientTag,
                o.pathHash,
                o.recipient
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    // ------------------------------ Internal: risk engine ------------------------------
    function _applyRiskAndState(
        uint32 strategyId,
        address quote,
        Side side,
        uint256 amountIn,
        uint256 amountOut,
        uint32 slippageBps
    ) internal {
        Strategy memory s = _strategies[strategyId];
        RiskCfg memory r = s.risk;
        if (slippageBps > r.maxSlippageBps) revert IPUSH_SlippageTooHigh(slippageBps, r.maxSlippageBps);

        StrategyState storage st = _state[strategyId];
        uint48 nowTs = uint48(block.timestamp);

        if (st.lastOrderAt != 0) {
            uint48 nextOk = st.lastOrderAt + r.cooldownSec;
            if (nowTs < nextOk) revert IPUSH_Cooldown(nextOk);
        }

        _checkRateLimit(st, r.maxOrdersPerHour, nowTs);

        // Oracle check
        if (address(oracle) == address(0)) revert IPUSH_OracleZero();
        (uint256 pxX18, uint256 updatedAt) = oracle.priceX18(s.base, quote);
        if (pxX18 == 0) revert IPUSH_OracleZero();
        if (nowTs > updatedAt && (nowTs - uint48(updatedAt)) > r.maxPriceAgeSec) {
            revert IPUSH_StalePrice(updatedAt, nowTs);
        }

        uint256 estNotionalX18 = _estimateNotionalX18(side, amountIn, amountOut, pxX18);
        uint256 newUsed = uint256(st.notionalUsedX18) + estNotionalX18;
        if (newUsed > uint256(r.maxNotionalX18)) revert IPUSH_NotionalExceeded(newUsed, r.maxNotionalX18);

        st.notionalUsedX18 = newUsed.toUint96();
        st.lastOrderAt = nowTs;
        st.ordersNonce++;
    }

    function _checkRateLimit(StrategyState storage st, uint32 maxPerHour, uint48 nowTs) internal {
        if (maxPerHour == 0) return;
