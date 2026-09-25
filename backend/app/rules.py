"""漏洞判定规则与评分口径（单一事实来源）。

规则与评分阈值集中在此处，/api/patterns 直接透出，方便向用户说明
"什么情况算问题、扣多少分、评级阈值是多少"。

RULES_VERSION 随判定/评分逻辑的变化而提升；历史审计记录在落库时保存
当时的 RULES_VERSION 与最终分数，读取历史时原样返回，不因规则更新而改判。
"""

# 判定规则 / 评分口径版本。
# 1.0.0 — 初始正则版本（仅历史记录引用）
# 2.0.0 — 按 Solidity 版本判定溢出、函数级访问控制解析、行号修正
RULES_VERSION = "2.0.0"

# 严重等级 -> 单次扣分权重
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

# 每种严重等级的扣分上限，避免同一类问题在同一行反复命中把分数瞬间扣穿
SEVERITY_CAPS = {
    "critical": 50,
    "high": 45,
    "medium": 24,
    "low": 9,
}

# 综合评分评级阈值（同时供前端展示复用）
SCORE_GRADES = [
    {"min": 90, "grade": "Excellent", "label": "优秀"},
    {"min": 75, "grade": "Good", "label": "良好"},
    {"min": 60, "grade": "Fair", "label": "一般"},
    {"min": 0, "grade": "Poor", "label": "较差"},
]

# 规则定义：id 为稳定标识，description/suggestion 面向用户，
# rationale 说明判定标准（何时报、何时不报）。
VULNERABILITY_RULES = [
    {
        "id": "reentrancy",
        "type": "重入攻击 (Reentrancy)",
        "severity": "critical",
        "description": "使用低级 call{value: ...} / send / transfer 转移 ETH，若在外部调用之后才更新状态，攻击者可在接收回调中反复进入。",
        "suggestion": "遵循 Checks-Effects-Interactions 模式（先记账后转账），或加 ReentrancyGuard / nonReentrant 修饰符。",
        "rationale": "匹配携带 value 的低级 call 调用，或 address.send/transfer；注释与字符串中的内容不参与匹配。",
    },
    {
        "id": "integer-overflow",
        "type": "整数溢出 (Integer Overflow/Underflow)",
        "severity": "high",
        "description": "算术运算可能发生上溢/下溢。",
        "suggestion": "Solidity <0.8 使用 SafeMath；Solidity >=0.8 依赖编译器内置检查，如确需关闭请把 unchecked 块限制在已证明安全的最小范围内。",
        "rationale": (
            "按 pragma 声明的实际版本判定："
            "Solidity >=0.8 编译器内置 checked 算术，普通 += / ++ / 二元运算一律安全、不报告；"
            "仅对 unchecked { ... } 块内的算术运算报告。"
            "Solidity <0.8（且未引入/使用 SafeMath）才对算术运算报告；"
            "使用 .add/.sub/.mul 等 SafeMath 调用时不报告。"
        ),
    },
    {
        "id": "access-control",
        "type": "未授权访问控制",
        "severity": "high",
        "description": "关键（改写合约状态的）函数缺少访问控制，任何人都可以调用。",
        "suggestion": "为仅管理员/合约所有者可调用的函数增加 onlyOwner 等修饰符，或在函数体内用 require(msg.sender == owner) / hasRole(...) 校验。",
        "rationale": (
            "逐函数解析：public/external 且非 view/pure 的函数，"
            "若函数体会改写状态（写入存储变量、selfdestruct、转出 ETH 等），"
            "且既无 onlyOwner/onlyRole/authorized 等访问控制修饰符，"
            "体内也没有 require/if 对 msg.sender/tx.origin 的校验或 hasRole 判断，则报告。"
            "view/pure、构造函数、接口/abstract 中无函数体的声明不报告。"
        ),
    },
    {
        "id": "selfdestruct",
        "type": "selfdestruct 使用",
        "severity": "medium",
        "description": "selfdestruct 可强制销毁合约并转出全部 ETH，缺少权限约束时可被任何人触发。",
        "suggestion": "确认业务上确有必要，并确保触发路径受访问控制保护。",
        "rationale": "匹配 selfdestruct(...) / suicide(...)（旧别名），注释与字符串除外。",
    },
    {
        "id": "tx-origin-auth",
        "type": "tx.origin 钓鱼风险",
        "severity": "high",
        "description": "使用 tx.origin 做身份认证时，用户被诱导调用恶意合约即可通过校验，存在钓鱼风险。",
        "suggestion": "身份认证一律使用 msg.sender；仅在极少数需要区分 EOA 链路上才使用 tx.origin，且不要用于授权判断。",
        "rationale": "仅当 tx.origin 出现在 require/if 的比较或授权条件中才报告；单纯引用（如事件记录）不报告。",
    },
    {
        "id": "precision-loss",
        "type": "精确度损失",
        "severity": "medium",
        "description": "先除后乘的整数运算会因提前取整造成精度损失，代币金额计算中可能被利用。",
        "suggestion": "调整为「先乘后除」，必要时引入精度缩放因子。",
        "rationale": "仅当同一表达式中除法出现在乘法之前（/ ... * ...）才报告；普通整数除法（如平均分摊）不报告，注释中的除号不报告。",
    },
]

RULE_BY_ID = {r["id"]: r for r in VULNERABILITY_RULES}

# 输入边界：防止超大输入拖垮扫描
MAX_CODE_BYTES = 512 * 1024  # 512 KB
