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
