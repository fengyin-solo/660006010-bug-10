"""版本感知的 Solidity 漏洞扫描引擎。

判定原则：
- 按 pragma 声明的实际 Solidity 版本判定：0.8+ 内置溢出检查生效，
  普通算术运算（+=、++ 等）是安全的，不再报整数溢出；
  只有 unchecked 块内的算术会提示（内置检查在该块内不生效）。
- Solidity <0.8 或未声明版本时，未使用 SafeMath 的复合赋值/自增自减
  报整数溢出；已使用 SafeMath（using SafeMath for ...）则不报。
- 未授权访问：public/external 且会修改状态的函数，若没有任何访问控制
  修饰符、函数体内也没有 msg.sender 权限校验、且操作的不是调用者
  自己的数据（balances[msg.sender] 模式），则判定为任何人都可以调用。
- 行号与上下文基于原始代码精确计算：注释先以等长空白替换（保留换行），
  因此注释不会干扰判定，行号也不会错位。
"""
import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 预处理
# ---------------------------------------------------------------------------

def strip_comments(code: str) -> str:
    """移除行注释与块注释，用等长空白替换（保留换行），保证行号不变。"""

    def _blank(m: "re.Match[str]") -> str:
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))

    code = re.sub(r"//[^\n]*", _blank, code)
    code = re.sub(r"/\*.*?\*/", _blank, code, flags=re.DOTALL)
    return code


def parse_pragma_version(code: str) -> Optional[Tuple[int, int, int]]:
    """解析 pragma solidity 版本约束，返回约束下界 (major, minor, patch)。

    支持 ^0.8.0、>=0.6.0 <0.9.0、0.8.0、=0.8.20 等写法；未声明返回 None。
    """
    m = re.search(r"pragma\s+solidity\s+([^;]+);", code)
    if not m:
        return None
    expr = m.group(1)
    versions = re.findall(r"(\d+)\.(\d+)\.(\d+)", expr)
    if versions:
        # 取约束下界（第一个完整版本号），^0.8.0 与 >=0.6.0 的下界都是第一个版本
        return tuple(int(x) for x in versions[0])
    two_part = re.findall(r"(\d+)\.(\d+)", expr)
    if two_part:
        major, minor = two_part[0]
        return (int(major), int(minor), 0)
    return None


def has_builtin_overflow_check(version: Optional[Tuple[int, int, int]]) -> bool:
    """Solidity 0.8.0 起编译器内置溢出检查。"""
    return version is not None and version >= (0, 8, 0)


# ---------------------------------------------------------------------------
# 结构解析
# ---------------------------------------------------------------------------

FUNC_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)\s*([^\{;]*)([\{;])", re.DOTALL)

HEADER_KEYWORDS = {
    "public", "external", "internal", "private",
    "view", "pure", "payable", "virtual", "override",
    "returns", "memory", "calldata", "storage",
}

# ERC20/ERC721 等标准公开接口，本来就不需要 owner 权限
PUBLIC_SAFE_FUNCTIONS = {
    "transfer", "approve", "transferFrom", "balanceOf", "allowance",
    "totalSupply", "name", "symbol", "decimals", "ownerOf", "tokenURI",
    "supportsInterface", "getBalance",
}


def extract_block(code: str, open_brace_idx: int) -> Tuple[str, int]:
    """从 open_brace_idx（'{' 的位置）提取配对块内容，返回 (块内容, 结束位置)。

    花括号不闭合时容错返回到文件末尾，保证扫描不中断。
    """
    depth = 0
    for i in range(open_brace_idx, len(code)):
        ch = code[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return code[open_brace_idx + 1:i], i
    return code[open_brace_idx + 1:], len(code)


def extract_functions(code: str) -> List[Dict]:
    """提取函数定义：名称、参数、头部（可见性/修饰符）、函数体及起始偏移。"""
    functions = []
    for m in FUNC_RE.finditer(code):
        name, params, header, opener = m.group(1), m.group(2), m.group(3), m.group(4)
        if opener == ";":  # 接口/抽象声明，无函数体
            continue
        body, body_end = extract_block(code, m.end() - 1)
        functions.append({
            "name": name,
            "params": params,
            "header": header,
            "body": body,
            "start": m.start(),
            "body_start": m.end() - 1,
            "body_end": body_end,
        })
    return functions


# ---------------------------------------------------------------------------
# 定位工具
# ---------------------------------------------------------------------------

def _line_of(code: str, offset: int) -> int:
    """偏移量对应的 1-based 行号。"""
    return code.count("\n", 0, offset) + 1


def _context(lines: List[str], line_num: int, radius: int = 1) -> str:
    """取匹配行前后各 radius 行作为上下文（line_num 为 1-based）。"""
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    return "\n".join(lines[start:end]).strip("\n")


def _finding(cleaned: str, lines: List[str], offset: int,
             type_: str, severity: str, description: str, suggestion: str) -> Dict:
    line_num = _line_of(cleaned, offset)
    return {
        "type": type_,
        "severity": severity,
        "line": line_num,
        "description": description,
        "suggestion": suggestion,
        "code": _context(lines, line_num),
    }


# ---------------------------------------------------------------------------
# 各检测器
# ---------------------------------------------------------------------------

REENTRANCY_RE = re.compile(
    r"\.call\s*(?:\{[^}]*value\s*:[^}]*\}|\.value\s*\([^)]*\))\s*\("
)

def detect_reentrancy(cleaned: str, lines: List[str]) -> List[Dict]:
    findings = []
    for m in REENTRANCY_RE.finditer(cleaned):
        findings.append(_finding(
            cleaned, lines, m.start(),
            "重入攻击 (Reentrancy)", "critical",
            "使用低级 call() 转移 ETH 存在重入攻击风险。攻击者可部署恶意合约在 fallback 中反复调用提款。",
            "使用 Checks-Effects-Interactions 模式（先更新状态再转账），或引入 ReentrancyGuard。",
        ))
    return findings


ARITHMETIC_RE = re.compile(r"\+=|-=|\*=|/=|%=|\+\+|--")
UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")
SAFEMATH_RE = re.compile(r"\busing\s+SafeMath\s+for\b")

def detect_integer_overflow(cleaned: str, lines: List[str],
                            version: Optional[Tuple[int, int, int]]) -> List[Dict]:
    findings = []
    if has_builtin_overflow_check(version):
        # 0.8+ 内置溢出检查已生效，普通算术安全；仅 unchecked 块内会绕过检查
        for um in UNCHECKED_RE.finditer(cleaned):
            block, _ = extract_block(cleaned, um.end() - 1)
            block_start = um.end()
            for am in ARITHMETIC_RE.finditer(block):
                findings.append(_finding(
                    cleaned, lines, block_start + am.start(),
                    "整数溢出 (Integer Overflow/Underflow)", "medium",
                    "unchecked 块内的算术运算不会触发 Solidity 0.8+ 的内置溢出检查，可能发生溢出。",
                    "确认该处运算在业务上不可能溢出；否则移出 unchecked 块，恢复内置溢出检查。",
                ))
        return findings

    # <0.8 或未声明版本：使用 SafeMath 则不报
    if SAFEMATH_RE.search(cleaned):
        return []

    if version is None:
        description = ("未声明 Solidity 版本，按 0.8 以下保守判定：复合赋值/自增运算可能溢出。")
    else:
        description = ("Solidity %d.%d.%d 未内置溢出检查，复合赋值/自增运算可能发生整数溢出。"
                       % version)
    for m in ARITHMETIC_RE.finditer(cleaned):
        findings.append(_finding(
            cleaned, lines, m.start(),
            "整数溢出 (Integer Overflow/Underflow)", "high",
            description,
            "使用 SafeMath 库，或升级到 Solidity 0.8+（内置溢出检查）。",
        ))
    return findings


ACCESS_MODIFIER_RE = re.compile(r"^(only\w+|adminOnly|\w*[Aa]uth\w*|restricted|governanceOnly)$")
SENDER_CHECK_RE = re.compile(
    r"(?:require|if)\s*\([^)]*(?:msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender|_msgSender\s*\(\)|hasRole\s*\()"
)
SENDER_BOUND_RE = re.compile(r"\[\s*msg\.sender\s*\]")

def _header_modifiers(header: str) -> List[str]:
    """从函数头部提取自定义修饰符（去掉 returns(...) 与关键字）。"""
    header = re.sub(r"returns\s*\([^)]*\)", " ", header)
    tokens = re.findall(r"[A-Za-z_]\w*", header)
    return [t for t in tokens if t not in HEADER_KEYWORDS]

def detect_access_control(cleaned: str, lines: List[str], functions: List[Dict]) -> List[Dict]:
    findings = []
    for fn in functions:
        header = fn["header"]
        if not re.search(r"\b(public|external)\b", header):
            continue  # internal/private 外部不可调用
        if re.search(r"\b(view|pure)\b", header):
            continue  # 只读函数不修改状态
        if fn["name"] in PUBLIC_SAFE_FUNCTIONS:
            continue  # 标准公开接口
        modifiers = _header_modifiers(header)
        if any(ACCESS_MODIFIER_RE.match(mod) for mod in modifiers):
            continue  # 有 onlyOwner 等访问控制修饰符
        if SENDER_CHECK_RE.search(fn["body"]):
            continue  # 函数体内有 msg.sender 权限校验
        if SENDER_BOUND_RE.search(fn["body"]):
            continue  # 操作的是调用者自己的数据（如 balances[msg.sender]）
        findings.append(_finding(
            cleaned, lines, fn["start"],
            "未授权访问控制", "high",
            "关键函数 %s() 缺少访问控制检查，任何人都可以调用。" % fn["name"],
            "添加 onlyOwner 等访问控制修饰符，或在函数体内校验 msg.sender 权限。",
        ))
    return findings


SELF_DESTRUCT_RE = re.compile(r"\bselfdestruct\s*\(|\bsuicide\s*\(")

def detect_selfdestruct(cleaned: str, lines: List[str]) -> List[Dict]:
    return [
        _finding(cleaned, lines, m.start(),
                 "selfdestruct使用", "medium",
                 "selfdestruct 可强制将合约所有 ETH 发送到任意地址，可能被滥用。",
                 "谨慎使用 selfdestruct，确保有正当业务需求并加上权限控制。")
        for m in SELF_DESTRUCT_RE.finditer(cleaned)
    ]


TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")

def detect_tx_origin(cleaned: str, lines: List[str]) -> List[Dict]:
    return [
        _finding(cleaned, lines, m.start(),
                 "tx.origin钓鱼", "high",
                 "使用 tx.origin 进行身份验证可能被钓鱼攻击，攻击者诱导用户触发交易。",
                 "使用 msg.sender 代替 tx.origin 进行身份验证。")
        for m in TX_ORIGIN_RE.finditer(cleaned)
    ]


PRECISION_RE = re.compile(r"/\s*\d+")

def detect_precision_loss(cleaned: str, lines: List[str]) -> List[Dict]:
    return [
        _finding(cleaned, lines, m.start(),
                 "精确度损失", "medium",
                 "除法运算可能导致精度损失，特别是在代币金额计算中。",
                 "先乘后除，使用高精度计算或使用定点数库。")
        for m in PRECISION_RE.finditer(cleaned)
    ]


# ---------------------------------------------------------------------------
# 模式目录（供 /api/patterns 展示，与检测器保持一致）
# ---------------------------------------------------------------------------

PATTERN_CATALOG = [
    {"type": "重入攻击 (Reentrancy)", "severity": "critical",
     "description": "使用低级 call{value:...}() 转移 ETH，未做重入防护。",
     "suggestion": "Checks-Effects-Interactions 模式或 ReentrancyGuard。"},
    {"type": "整数溢出 (Integer Overflow/Underflow)", "severity": "high",
     "description": "Solidity <0.8 且未使用 SafeMath 时，复合赋值/自增运算可能溢出；0.8+ 仅 unchecked 块内存在风险。",
     "suggestion": "使用 SafeMath 库或升级到 Solidity 0.8+。"},
    {"type": "未授权访问控制", "severity": "high",
     "description": "public/external 状态修改函数缺少访问控制，任何人都可以调用。",
     "suggestion": "添加 onlyOwner 等修饰符或校验 msg.sender。"},
    {"type": "selfdestruct使用", "severity": "medium",
     "description": "selfdestruct 可强制将合约所有 ETH 发送到任意地址。",
     "suggestion": "谨慎使用，并加上权限控制。"},
    {"type": "tx.origin钓鱼", "severity": "high",
     "description": "使用 tx.origin 进行身份验证可被钓鱼。",
     "suggestion": "使用 msg.sender 代替 tx.origin。"},
    {"type": "精确度损失", "severity": "medium",
     "description": "除法运算可能导致精度损失。",
     "suggestion": "先乘后除，使用高精度计算。"},
]


def detect_vulnerabilities(code: str) -> List[Dict]:
    """扫描合约代码，返回按行号排序的漏洞列表。扫描过程不会因异常输入中断。"""
    cleaned = strip_comments(code)
    lines = code.split("\n")
    version = parse_pragma_version(cleaned)
    functions = extract_functions(cleaned)

    findings: List[Dict] = []
    findings += detect_reentrancy(cleaned, lines)
    findings += detect_integer_overflow(cleaned, lines, version)
    findings += detect_access_control(cleaned, lines, functions)
    findings += detect_selfdestruct(cleaned, lines)
    findings += detect_tx_origin(cleaned, lines)
    findings += detect_precision_loss(cleaned, lines)
    findings.sort(key=lambda v: (v["line"], v["type"]))
    return findings
