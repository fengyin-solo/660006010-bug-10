"""Solidity 静态扫描引擎。

设计要点：
- 所有检测器都在"脱敏文本"（masked）上匹配：注释与字符串字面量被替换为等长空白，
  既消除误报，又保证字符偏移量与原文一致，行号不会错位。
- 行号一律由字符偏移量换算（offset 之前的换行符数 + 1），上下文窗口以命中行为中心。
- 版本相关判定（整数溢出）依据 pragma 声明解析出的版本区间。
- 纯函数、无外部依赖、无随机数；同一份代码任意时刻扫描结论一致。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .rules import RULE_BY_ID, SEVERITY_WEIGHTS, SEVERITY_CAPS, SCORE_GRADES

# ---------------------------------------------------------------------------
# 输入脱敏
# ---------------------------------------------------------------------------

def mask_comments_and_strings(code: str) -> str:
    """把注释与字符串字面量替换为空白，保留换行，保证偏移量/行号不变。"""
    out = []
    i, n = 0, len(code)
    state = "normal"
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if state == "normal":
            if c == "/" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "line_comment"
                continue
            if c == "/" and nxt == "*":
                out.extend("  ")
                i += 2
                state = "block_comment"
                continue
            if c == '"':
                out.append(" ")
                i += 1
                state = "dstring"
                continue
            if c == "'":
                out.append(" ")
                i += 1
                state = "sstring"
                continue
            out.append(c)
            i += 1
        elif state == "line_comment":
            if c == "\n":
                out.append("\n")
                state = "normal"
            else:
                out.append(" ")
            i += 1
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "normal"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
        elif state in ("dstring", "sstring"):
            quote = '"' if state == "dstring" else "'"
            if c == "\\":
                # 转义对（含 \" \\ \n 等），整体抹掉并保留换行对齐
                out.append(" ")
                if nxt:
                    out.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if c == quote:
                out.append(" ")
                i += 1
                state = "normal"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
    return "".join(out)


def line_of_offset(code: str, offset: int) -> int:
    """字符偏移 -> 1 起始行号。"""
    return code.count("\n", 0, offset) + 1


def build_context(code: str, line_num: int, radius: int = 2) -> Tuple[str, int, int]:
    """以命中行为中心取上下文，返回 (文本, 起始行号, 结束行号)。"""
    lines = code.split("\n")
    total = len(lines)
    start = max(1, line_num - radius)
    end = min(total, line_num + radius)
    text = "\n".join(lines[start - 1:end])
    return text.strip(), start, end


# ---------------------------------------------------------------------------
# pragma / 版本解析
# ---------------------------------------------------------------------------

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _parse_version(token: str) -> Tuple[int, int, int]:
    parts = re.findall(r"\d+", token)
    nums = [int(p) for p in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)  # type: ignore[return-value]


def _bump(v: Tuple[int, int, int]) -> Tuple[int, int, int]:
    return (v[0], v[1], v[2] + 1)


def parse_solidity_version(code: str) -> dict:
    """解析 pragma solidity 约束，得出编译器版本区间与内置溢出检查是否生效。

    返回 {raw, mode, builtin_overflow_checked, pragma_present, has_safemath}
    mode:
      - "checked"   声明区间允许 0.8+：编译器内置 checked 算术
      - "legacy"    声明区间上界 <0.8：无内置检查
      - "unknown"   未声明 pragma：按 legacy 口径处理（保守）
    """
    m = PRAGMA_RE.search(code)
    pragma_present = m is not None
    raw = m.group(1).strip() if m else ""

    low: Tuple[int, int, int] = (0, 0, 0)
    high: Optional[Tuple[int, int, int]] = None

    def intersect_high(h: Optional[Tuple[int, int, int]]) -> None:
        nonlocal high
        if h is not None and (high is None or h < high):
            high = h

    if raw:
        # 例：^0.8.0  >=0.7.0 <0.9.0  =0.5.17  0.4.24  ~0.8.1
        token_re = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+(?:\.\d+)?)")
        for mm in token_re.finditer(raw):
            op = mm.group(1) or "="
            v = _parse_version(mm.group(2))
            specified_parts = mm.group(2).count(".") + 1
            if op == "^":
                low = max(low, v)
                if v[0] > 0:
                    intersect_high((v[0] + 1, 0, 0))
                elif v[1] == 0:
                    # ^0.0.x 仅允许补丁级
                    intersect_high((0, 0, v[2] + 1))
                else:
                    # ^0.8.x：0.x 段次版本不兼容
                    intersect_high((0, v[1] + 1, 0))
            elif op == "~":
                low = max(low, v)
                if specified_parts >= 3:
                    intersect_high((v[0], v[1] + 1, 0))
                else:
                    intersect_high((v[0] + 1, 0, 0))
            elif op == ">=":
                low = max(low, v)
            elif op == ">":
                low = max(low, _bump(v))
            elif op == "<":
                intersect_high(v)
            elif op == "<=":
                intersect_high(_bump(v))
            else:  # "=" 或裸版本
                low = max(low, v)
                intersect_high(_bump(v))

    has_safemath = bool(
        re.search(r"using\s+SafeMath\b", code)
        or re.search(r"import\s+[^;]*SafeMath", code)
    )

    if not pragma_present:
        return {
            "raw": "",
            "mode": "unknown",
            "builtin_overflow_checked": False,
            "pragma_present": False,
            "has_safemath": has_safemath,
            "summary": "未声明 pragma solidity，按 Solidity <0.8（无内置溢出检查）保守处理",
        }

    builtin_checked = high is None or high > (0, 8, 0)
    if builtin_checked:
        mode = "checked"
        summary = f"声明版本 {raw}：允许 Solidity 0.8+，编译器内置溢出检查生效，普通算术安全"
    else:
        mode = "legacy"
        summary = f"声明版本 {raw}：限定 Solidity <0.8，编译器无内置溢出检查"

    return {
        "raw": raw,
        "mode": mode,
        "builtin_overflow_checked": builtin_checked,
        "pragma_present": True,
        "has_safemath": has_safemath,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# 词法/结构辅助
# ---------------------------------------------------------------------------

def _match_pair(text: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    """从 open_idx 处的开括号出发做配对，返回闭括号下标（找不到返回 -1）。文本已脱敏。"""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _spans_for(text: str, header_re: str, open_ch: str, close_ch: str) -> List[Tuple[int, int, int]]:
    """找出所有 (头部起点, 开括号位置, 闭括号位置)。"""
    spans = []
    for m in re.finditer(header_re, text):
        open_idx = text.find(open_ch, m.end() - 1)
        if open_idx == -1:
            continue
        close_idx = _match_pair(text, open_idx, open_ch, close_ch)
        if close_idx != -1:
            spans.append((m.start(), open_idx, close_idx))
    return spans


def _statement_span(masked: str, offset: int) -> Tuple[int, int]:
    """取 offset 所在语句的大致区间：向前回退到最近的 ; { }，向后到下一个 ;。"""
    start = offset
    while start > 0 and masked[start - 1] not in ";{}":
        start -= 1
    end = masked.find(";", offset)
    if end == -1:
        end = len(masked)
    return start, end


# ---------------------------------------------------------------------------
# 函数 / 状态变量解析
# ---------------------------------------------------------------------------

@dataclass
class Function:
    name: str
    params: str
    kw_offset: int
    body_start: int
    body_end: int
    head_text: str          # function ... 之间（可见性/修饰符/returns）
    body_text: str


FUNC_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*"
    r"\(((?:[^()]|\([^()]*\))*)\)"
    r"(.*?)"
    r"([{;])",
    re.DOTALL,
)

CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(")

ACCESS_MODIFIER_RE = re.compile(
    r"only[a-z]*|authorized?\b|hasrole|requireowner|checkrole|_auth\b|restricted",
    re.IGNORECASE,
)
AUTH_CHECK_RE = re.compile(
    r"msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender"
    r"|tx\.origin\s*(?:==|!=)|(?:==|!=)\s*tx\.origin"
    r"|hasrole\s*\(|isauthorized|_checkowner|_checkrole"
    r"|owner\s*\(\s*\)\s*(?:==|!=)|(?:==|!=)\s*owner\s*\(\s*\)",
    re.IGNORECASE,
)
STATE_WRITE_RE = re.compile(
    r"[A-Za-z0-9_\]\)]\s*(?:(?:\+|-|\*|/|%|&|\||\^)?=)(?!=)"
    r"|\+\+|--|(?:^|\W)delete\s+|selfdestruct\s*\("
    r"|\.call\b|\.send\s*\(|\.transfer\s*\(",
)

# 状态变量声明（启发式，按单条语句匹配；外层保证语句长度受限）
STATE_VAR_RE = re.compile(
    r"^\s*(?:constant\s+|immutable\s+|public\s+|private\s+|internal\s+|override\s+)*"
    r"(?:mapping\s*\(.+\)|[A-Za-z_]\w*(?:\s*\[[^\]]*\])?)"
    r"(?:\s+(?:constant|immutable|public|private|internal|override))*"
    r"\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?$"
)
LOCAL_VAR_RE = re.compile(
    r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping\s*\([^)]*\)|[A-Za-z_]\w*)\s+"
    r"([A-Za-z_]\w*)\s*(?:=|,|\)|;)"
)

# 单条语句最大长度，防止病态输入触发正则回溯（正常代码语句远小于此）
MAX_STATEMENT_LEN = 4000


def _iter_statements(text: str):
    """按 ; { } 切分语句片段，并对超长片段做截断，保证正则在线性长度上运行。

    产出 (片段在原文中的起始偏移, 片段文本)；分隔符不包含在片段内。
    """
    buf = []
    start = 0
    pos = 0
    size = 0
    for ch in text:
        if ch in ";{}":
            yield start, "".join(buf)
            pos += 1
            start = pos
            buf = []
            size = 0
        else:
            buf.append(ch)
            pos += 1
            size += 1
            if size >= MAX_STATEMENT_LEN:
                yield start, "".join(buf)
                start = pos
                buf = []
                size = 0
    if buf:
        yield start, "".join(buf)


def parse_functions(masked: str) -> List[Function]:
    funcs: List[Function] = []
    for m in FUNC_RE.finditer(masked):
        name = m.group(1)
        terminator = m.group(4)
        if terminator == ";":
            continue  # 接口 / abstract 函数声明，无函数体
        body_start = m.start(4)
        body_end = _match_pair(masked, body_start, "{", "}")
        if body_end == -1:
            continue
        funcs.append(
            Function(
                name=name,
                params=m.group(2),
                kw_offset=m.start(),
                body_start=body_start,
                body_end=body_end,
                head_text=m.group(0)[: m.start(4) - m.start()],
                body_text=masked[body_start + 1:body_end],
            )
        )
    return funcs


def find_state_variables(masked: str, funcs: List[Function]) -> set:
    """合约级状态变量名集合 = 全部变量样式声明 - 函数内局部变量/参数。"""
    # 把所有函数体挖空，只保留合约级文本
    contract_level = list(masked)
    for fn in funcs:
        for i in range(fn.body_start, fn.body_end + 1):
            if contract_level[i] != "\n":
                contract_level[i] = " "
    level_text = "".join(contract_level)

    candidates = set()
    for _start, stmt in _iter_statements(level_text):
        m = STATE_VAR_RE.match(stmt.strip())
        if m:
            candidates.add(m.group(1))

    locals_: set = set()
    for fn in funcs:
        for _start, stmt in _iter_statements(fn.head_text):
            locals_.update(LOCAL_VAR_RE.findall(stmt))
        for _start, stmt in _iter_statements(fn.body_text):
            locals_.update(LOCAL_VAR_RE.findall(stmt))
    return candidates - locals_


def _function_at(funcs: List[Function], offset: int) -> Optional[Function]:
    for fn in funcs:
        if fn.kw_offset <= offset <= fn.body_end:
            return fn
    return None


# ---------------------------------------------------------------------------
# 各检测器
# ---------------------------------------------------------------------------

REENTRANCY_RE = re.compile(
    r"\.call\s*\{\s*[^}]*\bvalue\s*:[^}]*\}\s*\("   # addr.call{value: x}("")
    r"|\.call\.value\s*\([^)]*\)\s*\("               # 0.4 旧语法 addr.call.value(x)("")
    r"|\.send\s*\(",                                  # addr.send(x)
)
# 原生 ETH 转出（send/transfer 单参数；call 族单独处理）
ETH_TRANSFER_RE = re.compile(r"\.send\s*\(|\.transfer\s*\(|\.call\s*\{\s*[^}]*\bvalue\s*:|\.call\.value\b")

SELFDESTRUCT_RE = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")

UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")

# 算术：复合赋值 / 自增自减 / 二元四则
COMPOUND_RE = re.compile(r"[A-Za-z0-9_\]\)]\s*(?P<op>\+|-|\*)=(?!=)")
INCDEC_RE = re.compile(r"\+\+|--")
BINARY_RE = re.compile(r"[A-Za-z0-9_\]\)]\s*(?P<op>\+|-|\*)(?![\*=])\s*[A-Za-z0-9_\(]")

ASSIGN_LVALUE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\[[^\]]*\])?)*"
    r"\s*(?:\+|-|\*)?=(?!=)"
)

PRECISION_RE = re.compile(
    r"[A-Za-z0-9_\]\)]\s*/\s*[A-Za-z0-9_\(\[]"  # 真正的除法运算（排除 // 与 /*）
)


def _for_header_spans(masked: str) -> List[Tuple[int, int]]:
    spans = []
    for m in re.finditer(r"\bfor\s*\(", masked):
        close = _match_pair(masked, m.end() - 1, "(", ")")
        if close != -1:
            spans.append((m.start(), close))
    return spans


def _unchecked_spans(masked: str) -> List[Tuple[int, int]]:
    spans = []
    for m in UNCHECKED_RE.finditer(masked):
        brace = masked.find("{", m.start())
        close = _match_pair(masked, brace, "{", "}")
        if close != -1:
            spans.append((m.start(), close))
    return spans


def _inside(offset: int, spans: List[Tuple[int, int]]) -> bool:
    return any(a <= offset <= b for a, b in spans)


def detect_reentrancy(masked: str, funcs: List[Function]) -> List[Tuple[str, int]]:
    hits = []
    for m in REENTRANCY_RE.finditer(masked):
        fn = _function_at(funcs, m.start())
        # 已由 nonReentrant / ReentrancyGuard 修饰的函数不再重复报告
        if fn and re.search(r"nonreentrant|reentrancyguard", fn.head_text, re.IGNORECASE):
            continue
        hits.append(("reentrancy", m.start()))
    return hits


def detect_selfdestruct(masked: str) -> List[Tuple[str, int]]:
    return [("selfdestruct", m.start()) for m in SELFDESTRUCT_RE.finditer(masked)]


def detect_tx_origin(masked: str) -> List[Tuple[str, int]]:
    hits = []
    for m in re.finditer(r"tx\.origin", masked):
        s, e = _statement_span(masked, m.start())
        stmt = masked[s:e]
        # 仅当出现在 require/if 的身份比较或角色判断中才视为授权误用
        if re.search(r"require|\bif\b", stmt) and re.search(r"==|!=|hasrole", stmt):
            hits.append(("tx-origin-auth", m.start()))
    return hits


def detect_precision_loss(masked: str) -> List[Tuple[str, int]]:
    hits: List[Tuple[str, int]] = []
    # 按 ; { } 切分表达式，定位"先除后乘"
    for stmt_start, stmt in _iter_statements(masked):
        div = PRECISION_RE.search(stmt)
        if div:
            tail = stmt[div.end():]
            mul_m = re.search(r"\s*\*\s*[A-Za-z0-9_\(]", tail)
            if mul_m and stmt[: div.start()].find("*") == -1:
                hits.append(("precision-loss", stmt_start + div.start()))
    return hits


def detect_integer_overflow(
    masked: str,
    funcs: List[Function],
    state_vars: set,
    builtin_checked: bool,
) -> List[Tuple[str, int]]:
    unchecked = _unchecked_spans(masked)
    for_headers = _for_header_spans(masked)
    hits: List[Tuple[str, int]] = []
    seen_lines: set = set()

    def add(offset: int) -> None:
        if _inside(offset, for_headers):
            return  # for 头里的循环变量自增自减不报
        line = masked.count("\n", 0, offset) + 1
        if line not in seen_lines:
            seen_lines.add(line)
            hits.append(("integer-overflow", offset))

    def touches_state(lo: int, hi: int) -> bool:
        segment = masked[lo:hi]
        return any(re.search(rf"\b{re.escape(name)}\b", segment) for name in state_vars)

    # 复合赋值
    for m in COMPOUND_RE.finditer(masked):
        op_offset = m.start("op")
        in_unchecked = _inside(op_offset, unchecked)
        if builtin_checked and not in_unchecked:
            continue  # 0.8+ 普通算术受编译器保护
        if not builtin_checked:
            # legacy：只报与状态变量相关的运算，局部变量循环计数不打扰
            s, e = _statement_span(masked, op_offset)
            if not in_unchecked and not touches_state(s, e):
                continue
        add(op_offset)

    # ++ / --
    for m in INCDEC_RE.finditer(masked):
        op_offset = m.start()
        in_unchecked = _inside(op_offset, unchecked)
        if builtin_checked and not in_unchecked:
            continue
        if not builtin_checked and not in_unchecked:
            s, e = _statement_span(masked, op_offset)
            if not touches_state(s, e):
                continue
        add(op_offset)

    # 二元 + - *
    for m in BINARY_RE.finditer(masked):
        op_offset = m.start("op")
        in_unchecked = _inside(op_offset, unchecked)
        if builtin_checked and not in_unchecked:
            continue
        if not builtin_checked and not in_unchecked:
            s, e = _statement_span(masked, op_offset)
            if not touches_state(s, e):
                continue
        add(op_offset)

    return hits


LVALUE_RE = re.compile(
    r"((?:[A-Za-z_]\w*(?:\s*\[[^\]]*\])?)(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\[[^\]]*\])?)*)"
    r"\s*(?:\+|-|\*|/|%|&|\||\^)?=(?!=)"
)


def _param_names(params: str) -> set:
    """提取函数参数名（取每个声明的最后一个标识符；未命名参数忽略）。"""
    names = set()
    for part in params.split(","):
        m = re.search(r"([A-Za-z_]\w*)\s*$", part.strip())
        if m:
            names.add(m.group(1))
    return names


def _is_self_service(fn_body: str, params: str) -> bool:
    """判断函数是否只操作"调用者自己的资产"，用于排除存取款/标准转账类自助函数。

    - 映射/数组存储写入的下标只能是 msg.sender 或函数参数；
    - 出现参数下标写入（如 balances[to]）时，必须同时存在对 msg.sender
      槽位的写入（扣款方是调用者本人，符合 transfer/withdraw 模式），
      无对应扣款的 balances[to] += v（铸币/空投）不算自助；
    - 裸状态变量写入（如 owner = x）属于改写全局状态，不算自助；
    - selfdestruct 是全局破坏操作，不算自助；
    - 若向外部地址转出原生 ETH，收款方必须是 msg.sender。
    """
    if SELFDESTRUCT_RE.search(fn_body):
        return False

    param_names = _param_names(params)
    self_slot_written = False
    param_slot_written = False

    for m in LVALUE_RE.finditer(fn_body):
        lvalue = m.group(1)
        idx = re.search(r"\[([^\]]*)\]", lvalue)
        if idx:
            key = idx.group(1).strip()
            if key == "msg.sender":
                self_slot_written = True
            elif key in param_names:
                param_slot_written = True
            else:
                return False
            continue
        if re.match(r"^[A-Za-z_]\w*$", lvalue):
            return False  # 无下标的裸状态变量写入（owner = x; totalSupply = ...;）

    if param_slot_written and not self_slot_written:
        return False

    for m in ETH_TRANSFER_RE.finditer(fn_body):
        s, _e = _statement_span(fn_body, m.start())
        stmt = fn_body[s:]
        receiver_m = re.search(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*(?:send|transfer)\s*\(", stmt)
        if receiver_m:
            if receiver_m.group(1) != "msg.sender":
                return False
            continue
        receiver_m = re.search(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\.\s*call\b", stmt)
        if receiver_m and receiver_m.group(1) != "msg.sender":
            return False

    return True


def detect_access_control(masked: str, funcs: List[Function]) -> List[Tuple[str, int]]:
    hits: List[Tuple[str, int]] = []
    for fn in funcs:
        head = fn.head_text.lower()
        if "view" in head or "pure" in head:
            continue  # 只读函数任何人可调是正常的
        if re.search(r"\b(?:internal|private)\b", head):
            continue  # 链上不可直接调用
        if ACCESS_MODIFIER_RE.search(fn.head_text):
            continue  # 已有访问控制修饰符
        if AUTH_CHECK_RE.search(fn.body_text):
            continue  # 函数体内有 msg.sender / 角色校验
        if not STATE_WRITE_RE.search(fn.body_text):
            continue  # 不改写状态、不转 ETH 的公开函数不算"关键函数"
        if _is_self_service(fn.body_text, fn.params):
            continue  # 只操作调用者自身资产（存取款/标准转账等），不构成未授权风险
        hits.append(("access-control", fn.kw_offset))
    return hits


# ---------------------------------------------------------------------------
# Gas 启发式（确定性）
# ---------------------------------------------------------------------------

def compute_gas_issues(masked: str, funcs: List[Function]) -> List[dict]:
    issues = []
    for fn in funcs:
        body = fn.body_text
        writes = len(ASSIGN_LVALUE_RE.findall(body))
        loops = len(re.findall(r"\bfor\s*\(|\bwhile\s*\(", body))
        external_calls = len(REENTRANCY_RE.findall(body)) + len(
            re.findall(r"\.call\s*\(|\.call\s*\{", body)
        )
        storage_reads_in_loop = 0
        for lm in re.finditer(r"\bfor\s*\(|\bwhile\s*\(", body):
            close_p = body.find(")", lm.end())
            block = body.find("{", lm.end())
            if close_p != -1 and block != -1:
                loop_body = body[block:block + 400]
                storage_reads_in_loop += len(re.findall(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\s*\.", loop_body))

        current = 21000 + writes * 5000 + loops * 3000 + external_calls * 9000 + storage_reads_in_loop * 1500
        suggestions = []
        if storage_reads_in_loop:
            suggestions.append("循环中读取的状态变量缓存到 memory，避免重复 SLOAD")
        if writes > 1:
            suggestions.append("合并重复的状态写入，减少不必要的 SSTORE")
        if loops:
            suggestions.append("固定次数循环可考虑 unchecked 自增并缓存长度，降低循环开销")
        if external_calls:
            suggestions.append("外部调用前整理状态，避免重复的调用与检查")
        optimized = current if not suggestions else int(current * 0.75)
        issues.append(
            {
                "functionName": f"{fn.name}()",
                "currentGas": current,
                "optimizedGas": optimized,
                "suggestion": "；".join(suggestions) if suggestions else "未发现明显优化空间",
            }
        )
    return issues


# ---------------------------------------------------------------------------
# 评分
# ---------------------------------------------------------------------------

def compute_security_score(findings: List[dict]) -> int:
    """按严重等级权重扣分，并对每个等级设扣分上限。"""
    if not findings:
        return 100
    per_severity: dict = {}
    for f in findings:
        per_severity[f["severity"]] = per_severity.get(f["severity"], 0) + 1

    deduction = 0
    for severity, count in per_severity.items():
        weight = SEVERITY_WEIGHTS.get(severity, 0)
        cap = SEVERITY_CAPS.get(severity, weight * count)
        deduction += min(weight * count, cap)
    return max(0, 100 - deduction)


def grade_for_score(score: int) -> str:
    for g in SCORE_GRADES:
        if score >= g["min"]:
            return g["grade"]
    return SCORE_GRADES[-1]["grade"]


# ---------------------------------------------------------------------------
# 扫描入口
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    vulnerabilities: List[dict] = field(default_factory=list)
    gas_issues: List[dict] = field(default_factory=list)
    score: int = 100
    solidity: dict = field(default_factory=dict)


def scan(code: str) -> ScanResult:
    """对合约源码执行完整扫描。对任意输入都不应抛出异常。"""
    # 统一换行，保证前后端按 \\n 切分行号一致
    normalized = code.replace("\r\n", "\n").replace("\r", "\n")
    masked = mask_comments_and_strings(normalized)
    funcs = parse_functions(masked)
    state_vars = find_state_variables(masked, funcs)
    solidity = parse_solidity_version(normalized)

    raw_hits: List[Tuple[str, int]] = []
    raw_hits += detect_reentrancy(masked, funcs)
    raw_hits += detect_integer_overflow(
        masked, funcs, state_vars, solidity["builtin_overflow_checked"]
    )
    raw_hits += detect_access_control(masked, funcs)
    raw_hits += detect_selfdestruct(masked)
    raw_hits += detect_tx_origin(masked)
    raw_hits += detect_precision_loss(masked)

    # 同一规则同一行只保留一条；不同规则落在同一行各自保留，各自取自己的上下文
    dedup = {}
    for rule_id, offset in raw_hits:
        line_num = line_of_offset(normalized, offset)
        dedup.setdefault((rule_id, line_num), offset)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities: List[dict] = []
    for (rule_id, line_num), _offset in sorted(
        dedup.items(), key=lambda kv: (kv[0][1], severity_order.get(RULE_BY_ID[kv[0][0]]["severity"], 9))
    ):
        rule = RULE_BY_ID[rule_id]
        context_text, ctx_start, ctx_end = build_context(normalized, line_num)
        vulnerabilities.append(
            {
                "ruleId": rule_id,
                "type": rule["type"],
                "severity": rule["severity"],
                "line": line_num,
                "description": rule["description"],
                "suggestion": rule["suggestion"],
                "code": context_text,
                "contextStartLine": ctx_start,
                "contextEndLine": ctx_end,
            }
        )

    score = compute_security_score(vulnerabilities)
    return ScanResult(
        vulnerabilities=vulnerabilities,
        gas_issues=compute_gas_issues(masked, funcs),
        score=score,
        solidity=solidity,
    )
