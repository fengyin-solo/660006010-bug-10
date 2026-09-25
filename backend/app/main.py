"""FastAPI 入口：合约扫描、历史列表/详情、规则与评分口径。"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import uuid

from . import storage
from .rules import (
    RULES_VERSION,
    VULNERABILITY_RULES,
    SEVERITY_WEIGHTS,
    SEVERITY_CAPS,
    SCORE_GRADES,
    MAX_CODE_BYTES,
)
from .scanner import scan, grade_for_score

app = FastAPI(title="Smart Contract Security Auditor")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    code: str
    filename: str = "contract.sol"


@app.on_event("startup")
def _startup() -> None:
    storage.init_db()


def ok(data) -> dict:
    return {"code": 0, "message": "success", "data": data}


def run_audit(code: str, filename: str) -> dict:
    """执行一次扫描并落库。任何异常都向上抛，由调用方转成可重试的错误响应。"""
    result_scan = scan(code)
    audit_id = str(uuid.uuid4())
    result = {
        "id": audit_id,
        "filename": filename,
        "score": result_scan.score,
        "grade": grade_for_score(result_scan.score),
        "rulesVersion": RULES_VERSION,
        "solidity": result_scan.solidity,
        "vulnerabilities": result_scan.vulnerabilities,
        "gasIssues": result_scan.gas_issues,
        "timestamp": storage.format_timestamp(),
    }
    storage.save_audit(audit_id, filename, code, result, RULES_VERSION)
    return result


def validate_payload(code: str, filename: str) -> Optional[str]:
    if not isinstance(code, str) or not code.strip():
        return "合约代码不能为空"
    if len(code.encode("utf-8", errors="ignore")) > MAX_CODE_BYTES:
        return f"合约过大，请控制在 {MAX_CODE_BYTES // 1024}KB 以内"
    if not filename or not filename.strip():
        return "文件名不能为空"
    return None


@app.get("/")
async def root():
    return ok({"message": "Smart Contract Security Auditor", "version": RULES_VERSION})


@app.get("/api/patterns")
async def list_patterns():
    """对外说明判定标准与评分阈值。"""
    return ok(
        {
            "rulesVersion": RULES_VERSION,
            "rules": VULNERABILITY_RULES,
            "severityWeights": SEVERITY_WEIGHTS,
            "severityCaps": SEVERITY_CAPS,
            "scoreGrades": SCORE_GRADES,
            "maxCodeBytes": MAX_CODE_BYTES,
        }
    )


@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    error = validate_payload(request.code, request.filename)
    if error:
        # 输入问题不可通过重试解决
        return JSONResponse(status_code=400, content={"code": 1, "message": error, "data": {"retryable": False}})
    try:
        result = run_audit(request.code, request.filename.strip())
    except Exception as exc:  # 边界数据导致的意外失败：返回可重试错误，不让请求挂死
        return JSONResponse(
            status_code=500,
            content={"code": 1, "message": f"扫描失败，请重试：{type(exc).__name__}", "data": {"retryable": True}},
        )
    return ok(result)


@app.post("/api/audit/retry")
async def retry_audit(request: AuditRequest):
    """与 /api/audit 相同的扫描路径，供前端失败后一键重试。"""
    error = validate_payload(request.code, request.filename)
    if error:
        return JSONResponse(status_code=400, content={"code": 1, "message": error, "data": {"retryable": False}})
    try:
        result = run_audit(request.code, request.filename.strip())
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"code": 1, "message": f"扫描失败，请重试：{type(exc).__name__}", "data": {"retryable": True}},
        )
    return ok(result)


@app.get("/api/audits")
async def list_audits():
    """历史列表：每条记录的分数/数量直接来自落库结论，与详情同源。"""
    return ok(storage.list_audits())


# 兼容旧路径
@app.get("/api/history")
async def get_history():
    return ok(storage.list_audits())


@app.get("/api/audits/{audit_id}")
async def get_audit_detail(audit_id: str):
    result = storage.get_audit(audit_id)
    if result is None:
        return JSONResponse(status_code=404, content={"code": 1, "message": "审计记录不存在", "data": None})
    return ok(result)


@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """生成 PDF 报告（报告内容同样基于落库的冻结结论）。"""
    if storage.get_audit(audit_id) is None:
        return JSONResponse(status_code=404, content={"code": 1, "message": "审计记录不存在", "data": None})
    return ok({"url": f"/api/reports/{audit_id}.pdf"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
