"""API 集成测试：审计、重试、列表/详情一致、历史口径冻结、边界输入。"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 在导入应用前指定临时数据库
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["AUDIT_DB_PATH"] = _tmp.name

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app, run_audit  # noqa: E402
from app import storage  # noqa: E402

BANK_08 = """pragma solidity ^0.8.0;
contract SimpleBank {
    mapping(address => uint) public balances;
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

UNPROTECTED = """pragma solidity ^0.8.0;
contract Wallet {
    address public owner;
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
"""


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage.init_db()
        cls.client = TestClient(app)

    def test_audit_08_no_overflow_false_positive(self):
        r = self.client.post("/api/audit", json={"code": BANK_08, "filename": "Bank.sol"})
        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        rule_ids = [v["ruleId"] for v in data["vulnerabilities"]]
        self.assertNotIn("integer-overflow", rule_ids)
        self.assertIn("reentrancy", rule_ids)
        self.assertTrue(data["solidity"]["builtin_overflow_checked"])
        self.assertEqual(data["rulesVersion"], "2.0.0")

    def test_audit_unprotected_reported(self):
        r = self.client.post("/api/audit", json={"code": UNPROTECTED, "filename": "W.sol"})
        rule_ids = [v["ruleId"] for v in r.json()["data"]["vulnerabilities"]]
        self.assertIn("access-control", rule_ids)

    def test_line_numbers_point_to_real_lines(self):
        r = self.client.post("/api/audit", json={"code": BANK_08, "filename": "Bank.sol"})
        lines = BANK_08.split("\n")
        for v in r.json()["data"]["vulnerabilities"]:
            # 命中行的真实源码必须出现在上下文中
            real_line = lines[v["line"] - 1]
            self.assertIn(real_line.strip(), v["code"].replace("\n", " "))

    def test_list_and_detail_consistent(self):
        r = self.client.post("/api/audit", json={"code": UNPROTECTED, "filename": "W2.sol"})
        audit = r.json()["data"]
        aid = audit["id"]

        detail = self.client.get(f"/api/audits/{aid}").json()["data"]
        lst = self.client.get("/api/audits").json()["data"]
        summary = next(x for x in lst if x["id"] == aid)

        # 列表分数/数量与详情同源
        self.assertEqual(summary["score"], detail["score"])
        self.assertEqual(summary["vulnerabilityCount"], len(detail["vulnerabilities"]))
        # 重复读详情结论稳定
        detail2 = self.client.get(f"/api/audits/{aid}").json()["data"]
        self.assertEqual(detail, detail2)

    def test_history_score_frozen(self):
        # 直接落库一条"旧口径"记录，模拟规则更新前的历史
        old = {
            "id": "legacy-1",
            "filename": "old.sol",
            "score": 45,
            "grade": "Poor",
            "rulesVersion": "1.0.0",
            "solidity": {},
            "vulnerabilities": [],
            "gasIssues": [],
            "timestamp": "2026-09-01 10:00:00",
        }
        storage.save_audit("legacy-1", "old.sol", "// code", old, "1.0.0")
        detail = self.client.get("/api/audits/legacy-1").json()["data"]
        self.assertEqual(detail["score"], 45)
        self.assertEqual(detail["rulesVersion"], "1.0.0")

    def test_empty_code_returns_validation_error(self):
        r = self.client.post("/api/audit", json={"code": "   ", "filename": "x.sol"})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(r.json()["data"]["retryable"])

    def test_oversized_code_rejected(self):
        big = "contract C { uint x; } // " + ("a" * 600_000)
        r = self.client.post("/api/audit", json={"code": big, "filename": "big.sol"})
        self.assertEqual(r.status_code, 400)

    def test_boundary_inputs_do_not_500(self):
        for code in ["\x00" * 32, "{" * 5000, "a" * 100_000, "pragma solidity ^0.8.0;"]:
            r = self.client.post("/api/audit", json={"code": code, "filename": "edge.sol"})
            self.assertEqual(r.status_code, 200, msg=repr(code[:20]))

    def test_retry_endpoint_works(self):
        r1 = self.client.post("/api/audit/retry", json={"code": UNPROTECTED, "filename": "W3.sol"})
        self.assertEqual(r1.status_code, 200)
        r2 = self.client.post("/api/audit/retry", json={"code": UNPROTECTED, "filename": "W3.sol"})
        # 同一份代码重试，结论一致（id/时间戳除外）
        a, b = r1.json()["data"], r2.json()["data"]
        self.assertEqual(a["score"], b["score"])
        self.assertEqual(
            [(v["ruleId"], v["line"]) for v in a["vulnerabilities"]],
            [(v["ruleId"], v["line"]) for v in b["vulnerabilities"]],
        )

    def test_404_for_unknown_audit(self):
        r = self.client.get("/api/audits/nope")
        self.assertEqual(r.status_code, 404)

    def test_patterns_expose_rationale_and_thresholds(self):
        body = self.client.get("/api/patterns").json()["data"]
        self.assertIn("severityWeights", body)
        self.assertIn("scoreGrades", body)
        self.assertTrue(all("rationale" in r for r in body["rules"]))


if __name__ == "__main__":
    unittest.main()
