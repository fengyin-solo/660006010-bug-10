"""扫描引擎判定规则测试：误报、漏报、行号与上下文、确定性。"""
from app.scanner import (
    detect_vulnerabilities,
    extract_functions,
    parse_pragma_version,
    strip_comments,
)

CONTRACT_08_SAFE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

CONTRACT_07_UNSAFE = """pragma solidity ^0.7.0;

contract Counter {
    uint public count;

    function increment() public {
        count += 1;
    }
}
"""

CONTRACT_07_SAFEMATH = """pragma solidity ^0.7.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract Counter {
    using SafeMath for uint;
    uint public count;

    function increment() public {
        count += 1;
        count = count.add(1);
    }
}
"""


def vulns_of_type(vulns, keyword):
    return [v for v in vulns if keyword in v["type"]]


class TestIntegerOverflow:
    def test_safe_addition_in_08_not_flagged(self):
        """0.8 合约中安全的加法赋值不得误报整数溢出。"""
        vulns = detect_vulnerabilities(CONTRACT_08_SAFE)
        assert vulns_of_type(vulns, "整数溢出") == []

    def test_overflow_flagged_pre_08(self):
        """0.7 合约的 += 应报整数溢出（high）。"""
        vulns = detect_vulnerabilities(CONTRACT_07_UNSAFE)
        overflow = vulns_of_type(vulns, "整数溢出")
        assert len(overflow) == 1
        assert overflow[0]["severity"] == "high"

    def test_safemath_usage_not_flagged(self):
        """0.7 合约使用 SafeMath 后不再报溢出。"""
        vulns = detect_vulnerabilities(CONTRACT_07_SAFEMATH)
        assert vulns_of_type(vulns, "整数溢出") == []

    def test_unchecked_block_flagged_in_08(self):
        """0.8 的 unchecked 块内算术绕过内置检查，应提示（medium）。"""
        code = """pragma solidity ^0.8.0;
contract C {
    function f(uint a, uint b) public pure returns (uint) {
        unchecked { return a + b; }
    }
    function g(uint x) public pure returns (uint) {
        uint y = x;
        unchecked { y += 1; }
        return y;
    }
}
"""
        vulns = detect_vulnerabilities(code)
        overflow = vulns_of_type(vulns, "整数溢出")
        assert len(overflow) == 1  # 仅 y += 1，普通 return a + b 不报
        assert overflow[0]["severity"] == "medium"

    def test_no_pragma_conservative(self):
        """未声明版本时按 <0.8 保守判定。"""
        code = "contract C { uint x; function f() public { x += 1; } }"
        vulns = detect_vulnerabilities(code)
        assert len(vulns_of_type(vulns, "整数溢出")) == 1

    def test_arithmetic_in_comment_not_flagged(self):
        """注释里的 += 不得触发误报。"""
        code = """pragma solidity ^0.7.0;
contract C {
    // count += 1; 这是注释
    /* total -= 1; */
    uint public count;
}
"""
        vulns = detect_vulnerabilities(code)
        assert vulns_of_type(vulns, "整数溢出") == []


class TestAccessControl:
    def test_unprotected_function_flagged(self):
        """任何人都可以调用的关键函数必须报出。"""
        code = """pragma solidity ^0.8.0;
contract C {
    address owner;
    function setOwner(address o) public {
        owner = o;
    }
}
"""
        vulns = detect_vulnerabilities(code)
        access = vulns_of_type(vulns, "未授权访问")
        assert len(access) == 1
        assert access[0]["severity"] == "high"

    def test_only_owner_not_flagged(self):
        code = """pragma solidity ^0.8.0;
contract C {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address o) public onlyOwner {
        owner = o;
    }
}
"""
        vulns = detect_vulnerabilities(code)
        assert vulns_of_type(vulns, "未授权访问") == []

    def test_msg_sender_check_not_flagged(self):
        code = """pragma solidity ^0.8.0;
contract C {
    address owner;
    function setOwner(address o) public {
        require(msg.sender == owner, "not owner");
        owner = o;
    }
}
"""
        vulns = detect_vulnerabilities(code)
        assert vulns_of_type(vulns, "未授权访问") == []

    def test_caller_bound_data_not_flagged(self):
        """操作调用者自己数据（balances[msg.sender]）的函数不算未授权。"""
        vulns = detect_vulnerabilities(CONTRACT_08_SAFE)
        assert vulns_of_type(vulns, "未授权访问") == []

    def test_view_function_not_flagged(self):
        code = """pragma solidity ^0.8.0;
contract C {
    uint public total;
    function getTotal() public view returns (uint) {
        return total;
    }
}
"""
        vulns = detect_vulnerabilities(code)
        assert vulns_of_type(vulns, "未授权访问") == []

    def test_payable_and_returns_header_parsed(self):
        """带 payable/returns 的函数头也要能正确解析并判定。"""
        code = """pragma solidity ^0.8.0;
contract C {
    uint total;
    function migrate() external payable returns (bool) {
        total = 0;
        return true;
    }
}
"""
        vulns = detect_vulnerabilities(code)
        assert len(vulns_of_type(vulns, "未授权访问")) == 1


class TestLineAndContext:
    def test_line_number_matches_actual_position(self):
        """行号必须与匹配实际所在行一致。"""
        vulns = detect_vulnerabilities(CONTRACT_07_UNSAFE)
        overflow = vulns_of_type(vulns, "整数溢出")[0]
        lines = CONTRACT_07_UNSAFE.split("\n")
        assert "count += 1;" in lines[overflow["line"] - 1]

    def test_context_centers_on_matched_line(self):
        """上下文必须包含匹配行本身，不错位。"""
        vulns = detect_vulnerabilities(CONTRACT_07_UNSAFE)
        overflow = vulns_of_type(vulns, "整数溢出")[0]
        assert "count += 1;" in overflow["code"]

    def test_multiple_findings_same_line_each_located(self):
        """同一行多个问题，各自行号与上下文都要对得上。"""
        code = 'pragma solidity ^0.7.0;\ncontract C { uint x; function f() public { x += 1; x -= 2; } }\n'
        vulns = detect_vulnerabilities(code)
        overflow = vulns_of_type(vulns, "整数溢出")
        assert len(overflow) == 2
        for v in overflow:
            assert v["line"] == 2
            assert "x += 1;" in v["code"]

    def test_reentrancy_line_correct(self):
        code = """pragma solidity ^0.8.0;
contract Bank {
    mapping(address => uint) balances;
    function withdraw(uint amount) public {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""
        vulns = detect_vulnerabilities(code)
        reentrancy = vulns_of_type(vulns, "重入攻击")
        assert len(reentrancy) == 1
        assert reentrancy[0]["line"] == 5
        assert "call{value: amount}" in reentrancy[0]["code"]


class TestRobustness:
    def test_empty_code(self):
        assert detect_vulnerabilities("") == []

    def test_garbage_input(self):
        assert detect_vulnerabilities("}{)((*&#^%$\n{{{") == []

    def test_unclosed_braces_do_not_crash(self):
        code = "pragma solidity ^0.7.0;\ncontract C { function f() public { uint x = 1; x += 1;"
        vulns = detect_vulnerabilities(code)
        assert len(vulns_of_type(vulns, "整数溢出")) == 1

    def test_deterministic(self):
        """同一份合约重复扫描结论必须一致。"""
        first = detect_vulnerabilities(CONTRACT_07_UNSAFE)
        second = detect_vulnerabilities(CONTRACT_07_UNSAFE)
        assert first == second


class TestHelpers:
    def test_strip_comments_preserves_line_numbers(self):
        code = "line1\n// comment\n/* block\ncomment */\nline5"
        cleaned = strip_comments(code)
        assert cleaned.count("\n") == code.count("\n")

    def test_parse_pragma_versions(self):
        assert parse_pragma_version("pragma solidity ^0.8.0;") == (0, 8, 0)
        assert parse_pragma_version("pragma solidity >=0.6.0 <0.9.0;") == (0, 6, 0)
        assert parse_pragma_version("pragma solidity 0.7.6;") == (0, 7, 6)
        assert parse_pragma_version("contract C {}") is None

    def test_extract_functions_unclosed(self):
        fns = extract_functions("contract C { function f() public { uint x = 1;")
        assert len(fns) == 1
        assert fns[0]["name"] == "f"
