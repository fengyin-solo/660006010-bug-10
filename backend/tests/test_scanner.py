"""扫描引擎单元测试：版本判定、行号/上下文、漏报误报、边界输入。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scanner import (  # noqa: E402
    scan,
    mask_comments_and_strings,
    parse_solidity_version,
    build_context,
)

BANK_08 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"""

UNCHECKED_08 = """pragma solidity 0.8.19;

contract C {
    uint public counter;
    function bump(uint n) public {
        for (uint i = 0; i < n; i++) {
            counter += 1;
        }
        unchecked { counter += 1; }
    }
}
"""

LEGACY_07 = """pragma solidity ^0.7.6;

contract Old {
    mapping(address => uint) balances;
    function add(address u, uint v) public {
        balances[u] += v;
    }
}
"""

SAFEMATH_07 = """pragma solidity 0.5.17;
import "@openzeppelin/contracts/math/SafeMath.sol";

contract T {
    using SafeMath for uint;
    mapping(address => uint) balances;
    function deposit(uint v) public {
        balances[msg.sender] = balances[msg.sender].add(v);
    }
}
"""

NO_GUARD = """pragma solidity ^0.8.0;

contract Wallet {
    address public owner;
    mapping(address => uint) balances;

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function sweep(address payable to, uint amount) public {
        to.transfer(amount);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

WITH_GUARD = """pragma solidity ^0.8.0;

contract Wallet {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }

    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
"""

UNGUARDED_KILL = """pragma solidity ^0.8.0;
contract C {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
"""

COMMENT_NOISE = """pragma solidity ^0.8.0;

contract C {
    // use a.call{value: 1}("") later? and x += 1 is fine
    /* selfdestruct(owner);
       balances[o] += 100; */
    string note = "selfdestruct(x) and += 1";
    function f() public pure returns (uint) {
        return 1 + 2;
    }
}
"""

TX_ORIGIN_BAD = """pragma solidity ^0.8.0;
contract C {
    address owner;
    function withdraw() public {
        require(tx.origin == owner);
    }
}
"""

PRECISION = """pragma solidity ^0.8.0;
contract C {
    function bonus(uint a, uint b, uint total) public pure returns (uint) {
        uint x = a / b * total;
        uint y = a / 2;
        return x + y;
    }
}
"""

EDGE_CASES = ["", "   \n  \n", "contract C {", "pragma solidity ^0.8.0;", "\x00" * 10, "{" * 1000, "a" * 200000]


def ids(findings):
    return sorted(f["ruleId"] for f in findings)


class VersionTests(unittest.TestCase):
    def test_caret_08_checked(self):
        self.assertTrue(parse_solidity_version(BANK_08)["builtin_overflow_checked"])
        self.assertEqual(parse_solidity_version(BANK_08)["mode"], "checked")

    def test_exact_08_checked(self):
        info = parse_solidity_version(UNCHECKED_08)
        self.assertTrue(info["builtin_overflow_checked"])

    def test_legacy_range(self):
        info = parse_solidity_version(LEGACY_07)
        self.assertFalse(info["builtin_overflow_checked"])
        self.assertEqual(info["mode"], "legacy")

    def test_range_spanning_08(self):
        code = "pragma solidity >=0.7.0 <0.9.0;"
        self.assertTrue(parse_solidity_version(code)["builtin_overflow_checked"])

    def test_no_pragma_unknown(self):
        info = parse_solidity_version("contract C {}")
        self.assertEqual(info["mode"], "unknown")
        self.assertFalse(info["builtin_overflow_checked"])


class OverflowTests(unittest.TestCase):
    def test_08_safe_arith_not_flagged(self):
        # 用户反馈：0.8 合约中安全的 += / -= 不应被判整数溢出
        result = scan(BANK_08)
        self.assertNotIn("integer-overflow", ids(result.vulnerabilities))

    def test_08_unchecked_is_flagged(self):
        # 内置检查存在，但 unchecked 块内的运算要报
        result = scan(UNCHECKED_08)
        ov = [v for v in result.vulnerabilities if v["ruleId"] == "integer-overflow"]
        self.assertEqual(len(ov), 1)
        # 命中行是 unchecked 所在行
        self.assertEqual(ov[0]["line"], 9)
        self.assertIn("unchecked", ov[0]["code"])

    def test_08_for_loop_incdec_not_flagged(self):
        result = scan(UNCHECKED_08)
        # for 头中的 i++ 不单独报；counter += 1 在 checked 区域也不报
        lines = [v["line"] for v in result.vulnerabilities if v["ruleId"] == "integer-overflow"]
        self.assertEqual(lines, [9])

    def test_legacy_arithmetic_flagged(self):
        result = scan(LEGACY_07)
        self.assertIn("integer-overflow", ids(result.vulnerabilities))

    def test_safemath_not_flagged(self):
        result = scan(SAFEMATH_07)
        self.assertNotIn("integer-overflow", ids(result.vulnerabilities))


class AccessControlTests(unittest.TestCase):
    def test_unprotected_state_changing_function_flagged(self):
        # 用户反馈：关键函数任何人可调却没报
        result = scan(NO_GUARD)
        flagged = [v for v in result.vulnerabilities if v["ruleId"] == "access-control"]
        names = []
        for v in flagged:
            names.append(v["code"])
        self.assertTrue(any("setOwner" in c for c in names))
        self.assertTrue(any("sweep" in c for c in names))

    def test_self_service_not_flagged(self):
        # deposit 只写 balances[msg.sender]，不应被当作未授权
        result = scan(NO_GUARD)
        flagged = [v for v in result.vulnerabilities if v["ruleId"] == "access-control"]
        self.assertFalse(any("deposit" in v["code"] for v in flagged))

    def test_modifier_guarded_not_flagged(self):
        result = scan(WITH_GUARD)
        self.assertNotIn("access-control", ids(result.vulnerabilities))

    def test_bank_withdraw_self_service_not_flagged(self):
        result = scan(BANK_08)
        self.assertNotIn("access-control", ids(result.vulnerabilities))

    def test_selfdestruct_function_not_self_service(self):
        result = scan(UNGUARDED_KILL)
        rule_ids = ids(result.vulnerabilities)
        self.assertIn("access-control", rule_ids)
        self.assertIn("selfdestruct", rule_ids)


class OtherRuleTests(unittest.TestCase):
    def test_reentrancy_line_number(self):
        result = scan(BANK_08)
        ree = [v for v in result.vulnerabilities if v["ruleId"] == "reentrancy"]
        self.assertEqual(len(ree), 1)
        self.assertEqual(ree[0]["line"], 13)  # call{value} 实际所在行

    def test_context_centered_and_aligned(self):
        result = scan(BANK_08)
        ree = [v for v in result.vulnerabilities if v["ruleId"] == "reentrancy"][0]
        self.assertEqual(ree["contextStartLine"], 11)
        self.assertEqual(ree["contextEndLine"], 15)
        # 上下文里必须真的包含命中行原文
        lines = ree["code"].split("\n")
        self.assertTrue(any("call{value: amount}" in ln for ln in lines))

    def test_comments_and_strings_ignored(self):
        result = scan(COMMENT_NOISE)
        self.assertEqual(result.vulnerabilities, [])

    def test_mask_preserves_offsets(self):
        masked = mask_comments_and_strings(COMMENT_NOISE)
        self.assertEqual(len(masked), len(COMMENT_NOISE))
        self.assertEqual(masked.count("\n"), COMMENT_NOISE.count("\n"))

    def test_tx_origin_auth(self):
        result = scan(TX_ORIGIN_BAD)
        self.assertIn("tx-origin-auth", ids(result.vulnerabilities))

    def test_precision_loss_only_div_before_mul(self):
        result = scan(PRECISION)
        p = [v for v in result.vulnerabilities if v["ruleId"] == "precision-loss"]
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["line"], 4)  # a / b * total


class DeterminismTests(unittest.TestCase):
    def test_same_code_same_result(self):
        r1 = scan(BANK_08)
        r2 = scan(BANK_08)
        self.assertEqual(r1.score, r2.score)
        self.assertEqual(
            [(v["ruleId"], v["line"]) for v in r1.vulnerabilities],
            [(v["ruleId"], v["line"]) for v in r2.vulnerabilities],
        )
        self.assertEqual(r1.gas_issues, r2.gas_issues)

    def test_edge_inputs_dont_crash(self):
        for code in EDGE_CASES:
            result = scan(code)
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 100)
            self.assertIsInstance(result.vulnerabilities, list)
            self.assertIsInstance(result.gas_issues, list)

    def test_line_numbers_within_bounds(self):
        total = BANK_08.count("\n") + 1
        result = scan(BANK_08)
        for v in result.vulnerabilities:
            self.assertGreaterEqual(v["line"], 1)
            self.assertLessEqual(v["line"], total)
            self.assertGreaterEqual(v["contextStartLine"], 1)
            self.assertLessEqual(v["contextEndLine"], total)
            self.assertLessEqual(v["contextStartLine"], v["line"])
            self.assertLessEqual(v["line"], v["contextEndLine"])


if __name__ == "__main__":
    unittest.main()
