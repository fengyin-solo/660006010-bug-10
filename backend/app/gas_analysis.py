"""确定性 Gas 分析。

同一份合约每次扫描得到相同结果（不使用随机数），
保证列表与详情、重复扫描之间结论一致。
"""
import re
from collections import Counter
from typing import Dict, List

# 粗略的 gas 单价（确定性估算，用于横向对比优化空间）
SSTORE_COST = 5000
SLOAD_COST = 800
SLOAD_CACHED_COST = 100
BASE_TX_COST = 21000

WRITE_RE = re.compile(r"[A-Za-z_]\w*(?:\[[^\]\n]+\])?\s*=(?![=<>])")
STORAGE_ACCESS_RE = re.compile(r"[A-Za-z_]\w*\[[^\]\n]+\]")
LOOP_RE = re.compile(r"\b(?:for|while)\b")


def compute_gas_issues(code: str, functions: List[Dict]) -> List[Dict]:
    """逐函数分析 gas 优化空间，只返回有优化空间的函数。"""
    issues = []
    for fn in functions:
        body = fn["body"]
        writes = len(WRITE_RE.findall(body))
        accesses = STORAGE_ACCESS_RE.findall(body)
        duplicated = {expr: n for expr, n in Counter(accesses).items() if n >= 2}
        has_loop = bool(LOOP_RE.search(body))

        current_gas = BASE_TX_COST + writes * SSTORE_COST + len(accesses) * SLOAD_COST
        optimized_gas = current_gas
        suggestions = []

        if duplicated:
            saved = sum((n - 1) for n in duplicated.values()) * (SLOAD_COST - SLOAD_CACHED_COST)
            optimized_gas -= saved
            examples = "、".join(list(duplicated)[:3])
            suggestions.append(f"重复读取同一 storage 槽（{examples}），建议缓存到局部变量")

        if has_loop and writes:
            optimized_gas -= writes * (SSTORE_COST // 2)
            suggestions.append("循环中读写 storage 变量，建议缓存到 memory 后批量写回")

        if suggestions:
            issues.append({
                "functionName": f"{fn['name']}()",
                "currentGas": current_gas,
                "optimizedGas": max(optimized_gas, BASE_TX_COST),
                "suggestion": "；".join(suggestions),
            })
    return issues
