"""安全评分口径。

评分规则（SCORING_VERSION = "v2"）：
- 满分 100 分，每个漏洞按严重度扣分：critical 25 / high 15 / medium 8 / low 3
- 扣分累计，最低 0 分
- 等级：>=90 Excellent，>=70 Good，>=50 Fair，<50 Poor

历史记录评分口径保持稳定：评分在审计时计算并随记录落库，
读取历史时直接返回存储值，不随规则调整重算。
"""
from typing import Dict, List

SCORING_VERSION = "v2"
BASE_SCORE = 100
SEVERITY_WEIGHTS: Dict[str, int] = {"critical": 25, "high": 15, "medium": 8, "low": 3}
GRADE_THRESHOLDS = ((90, "Excellent"), (70, "Good"), (50, "Fair"), (0, "Poor"))


def compute_security_score(vulnerabilities: List[dict]) -> int:
    deduction = sum(SEVERITY_WEIGHTS.get(v.get("severity", ""), 5) for v in vulnerabilities)
    return max(0, BASE_SCORE - deduction)


def grade_for(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "Poor"


def rules_doc() -> dict:
    """评分口径说明，供 API 暴露，让判定标准与阈值可查可说明。"""
    return {
        "version": SCORING_VERSION,
        "baseScore": BASE_SCORE,
        "severityWeights": SEVERITY_WEIGHTS,
        "grades": [{"minScore": t, "grade": g} for t, g in GRADE_THRESHOLDS],
        "description": "满分 100 分，每个漏洞按严重度扣分（critical 25 / high 15 / medium 8 / low 3），最低 0 分。",
    }
