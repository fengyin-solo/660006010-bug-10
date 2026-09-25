"""API 层测试：边界输入、评分口径、历史一致性、报告生成。"""
import asyncio
import importlib

import httpx
import pytest

from app import report, scoring, storage


class SyncASGIClient:
    """同步 ASGI 测试客户端（venv 中 httpx 0.28 与 starlette TestClient 不兼容）。"""

    def __init__(self, app):
        self.app = app

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async def _do() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.request(method, url, **kwargs)

        return asyncio.run(_do())

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """每个用例使用独立临时数据库与报告目录。"""
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "test_audits.db"))
    monkeypatch.setattr(report, "REPORTS_DIR", str(tmp_path / "reports"))
    import app.main as main_module
    importlib.reload(main_module)
    storage.init_db()  # 与 lifespan 启动逻辑等价
    yield SyncASGIClient(main_module.app)


CONTRACT_08 = """// SPDX-License-Identifier: MIT
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

CONTRACT_07 = """pragma solidity ^0.7.0;
contract Counter {
    uint public count;
    function increment() public { count += 1; }
}
"""


class TestAudit:
    def test_08_contract_no_overflow_false_positive(self, client):
        """0.8 合约：安全加法赋值不误报，评分不被误扣。"""
        res = client.post("/api/audit", json={"code": CONTRACT_08, "filename": "SimpleBank.sol"})
        assert res.status_code == 200
        data = res.json()["data"]
        overflow = [v for v in data["vulnerabilities"] if "整数溢出" in v["type"]]
        assert overflow == []
        # 只有重入 1 个 critical：100 - 25 = 75
        assert data["score"] == 75
        assert data["scoringVersion"] == scoring.SCORING_VERSION

    def test_07_contract_overflow_deducts_score(self, client):
        res = client.post("/api/audit", json={"code": CONTRACT_07, "filename": "Counter.sol"})
        assert res.status_code == 200
        data = res.json()["data"]
        overflow = [v for v in data["vulnerabilities"] if "整数溢出" in v["type"]]
        assert len(overflow) == 1
        # increment 无访问控制（high 15）+ 溢出（high 15）
        assert data["score"] == 100 - 15 - 15

    def test_empty_code_rejected(self, client):
        res = client.post("/api/audit", json={"code": "   ", "filename": "a.sol"})
        assert res.status_code == 400

    def test_missing_fields_rejected(self, client):
        res = client.post("/api/audit", json={})
        assert res.status_code == 422

    def test_garbage_code_does_not_crash(self, client):
        res = client.post("/api/audit", json={"code": "}{)((*&#^%$\n{{{", "filename": "x.sol"})
        assert res.status_code == 200
        assert res.json()["data"]["score"] == 100

    def test_oversized_code_rejected(self, client):
        res = client.post("/api/audit", json={"code": "a" * (1024 * 1024 + 1), "filename": "big.sol"})
        assert res.status_code == 422

    def test_same_contract_same_conclusion(self, client):
        """同一份合约重复审计，漏洞与评分结论一致。"""
        r1 = client.post("/api/audit", json={"code": CONTRACT_08, "filename": "a.sol"}).json()["data"]
        r2 = client.post("/api/audit", json={"code": CONTRACT_08, "filename": "a.sol"}).json()["data"]
        assert r1["score"] == r2["score"]
        assert r1["vulnerabilities"] == r2["vulnerabilities"]
        assert r1["gasIssues"] == r2["gasIssues"]


class TestHistory:
    def test_list_and_detail_consistent(self, client):
        """列表与详情同源，结论一致。"""
        created = client.post("/api/audit", json={"code": CONTRACT_08, "filename": "SimpleBank.sol"}).json()["data"]
        listing = client.get("/api/history").json()["data"]
        assert len(listing) == 1
        assert listing[0]["id"] == created["id"]
        assert listing[0]["score"] == created["score"]

        detail = client.get(f"/api/history/{created['id']}").json()["data"]
        assert detail["score"] == created["score"]
        assert detail["vulnerabilities"] == created["vulnerabilities"]

    def test_detail_not_found(self, client):
        res = client.get("/api/history/nonexistent-id")
        assert res.status_code == 404

    def test_stored_score_stable_under_rule_change(self, client, monkeypatch):
        """历史记录的评分口径稳定：规则调整后，已存记录分数不变。"""
        created = client.post("/api/audit", json={"code": CONTRACT_08, "filename": "a.sol"}).json()["data"]
        original_score = created["score"]

        # 模拟评分规则调整（权重翻倍）
        monkeypatch.setattr(scoring, "SEVERITY_WEIGHTS", {"critical": 50, "high": 30, "medium": 16, "low": 6})

        detail = client.get(f"/api/history/{created['id']}").json()["data"]
        assert detail["score"] == original_score
        listing = client.get("/api/history").json()["data"]
        assert listing[0]["score"] == original_score


class TestScoringRules:
    def test_rules_documented(self, client):
        res = client.get("/api/scoring-rules")
        assert res.status_code == 200
        rules = res.json()["data"]
        assert rules["baseScore"] == 100
        assert rules["severityWeights"] == {"critical": 25, "high": 15, "medium": 8, "low": 3}
        assert rules["grades"][0] == {"minScore": 90, "grade": "Excellent"}
        assert rules["version"] == scoring.SCORING_VERSION


class TestReport:
    def test_generate_and_download_pdf(self, client):
        created = client.post("/api/audit", json={"code": CONTRACT_08, "filename": "SimpleBank.sol"}).json()["data"]
        res = client.post(f"/api/report/{created['id']}")
        assert res.status_code == 200
        url = res.json()["data"]["url"]

        pdf = client.get(url)
        assert pdf.status_code == 200
        assert pdf.content[:4] == b"%PDF"

    def test_report_for_missing_record(self, client):
        res = client.post("/api/report/nonexistent-id")
        assert res.status_code == 404
