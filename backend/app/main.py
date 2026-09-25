import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .gas_analysis import compute_gas_issues
from .report import generate_pdf
from .scanner import (
    PATTERN_CATALOG,
    detect_vulnerabilities,
    extract_functions,
    parse_pragma_version,
    strip_comments,
)
from .scoring import SCORING_VERSION, compute_security_score, grade_for, rules_doc
from .storage import get_audit, init_db, list_audits, save_audit

MAX_CODE_SIZE = 1024 * 1024  # 1MB，超出视为异常输入


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Smart Contract Security Auditor", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


class AuditRequest(BaseModel):
    code: str = Field(..., max_length=MAX_CODE_SIZE)
    filename: str = Field(default="contract.sol", max_length=255)


def analyze(code: str, filename: str) -> dict:
    """执行完整审计（纯函数，确定性：同一份合约结论一致）。"""
    vulnerabilities = detect_vulnerabilities(code)
    functions = extract_functions(strip_comments(code))
    gas_issues = compute_gas_issues(code, functions)
    score = compute_security_score(vulnerabilities)
    version = parse_pragma_version(strip_comments(code))

    return {
        "id": str(uuid.uuid4()),
        "filename": filename,
        "score": score,
        "grade": grade_for(score),
        "scoringVersion": SCORING_VERSION,
        "solidityVersion": ".".join(map(str, version)) if version else None,
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}


@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": PATTERN_CATALOG}


@app.get("/api/scoring-rules")
async def scoring_rules():
    """评分口径：判定标准与评分阈值公开可查。"""
    return {"code": 0, "message": "success", "data": rules_doc()}


@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    if not request.code or not request.code.strip():
        raise HTTPException(status_code=400, detail="合约代码不能为空")

    try:
        result = analyze(request.code, request.filename)
    except Exception:
        # 扫描失败不落库，不产生半截记录，客户端可直接重试
        raise HTTPException(status_code=500, detail="扫描失败，请重试")

    try:
        save_audit(result)
    except Exception:
        raise HTTPException(status_code=500, detail="结果保存失败，请重试")

    return {"code": 0, "message": "success", "data": result}


@app.get("/api/history")
async def get_history():
    return {"code": 0, "message": "success", "data": list_audits()}


@app.get("/api/history/{audit_id}")
async def get_history_detail(audit_id: str):
    """审计详情：与列表同源于同一条落库记录，结论一致。"""
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    return {"code": 0, "message": "success", "data": record}


@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """基于已存记录生成 PDF 报告（记录不存在则 404）。"""
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    try:
        generate_pdf(record)
    except Exception:
        raise HTTPException(status_code=500, detail="报告生成失败，请重试")
    return {"code": 0, "message": "success", "data": {"url": f"/api/reports/{audit_id}.pdf"}}


@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    if "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="非法文件名")
    import os
    from .report import REPORTS_DIR
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="报告不存在")
    return FileResponse(path, media_type="application/pdf", filename=filename)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
