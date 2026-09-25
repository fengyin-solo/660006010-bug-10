# Backend: Python FastAPI

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 模块结构

- `app/rules.py` — 漏洞判定规则、扣分权重/上限、评级阈值（单一事实来源，含 `RULES_VERSION`）
- `app/scanner.py` — Solidity 扫描引擎：注释/字符串脱敏、pragma 版本解析、函数级访问控制、溢出/重入等检测器、确定性 gas 估算、评分
- `app/storage.py` — SQLite 持久化（结论整体落库，历史记录冻结当时的评分口径）
- `app/main.py` — HTTP 接口

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/audit` | 提交合约扫描；输入非法返回 400（`retryable:false`），扫描异常返回 500（`retryable:true`） |
| POST | `/api/audit/retry` | 失败后的重试入口，与 `/api/audit` 同一路径 |
| GET | `/api/audits` | 历史列表（分数/数量取自落库结论） |
| GET | `/api/audits/{id}` | 历史详情（与列表同源，返回冻结的完整结论） |
| GET | `/api/patterns` | 判定规则、扣分权重/上限、评级阈值 |
| GET | `/api/history` | 旧路径，等价于 `/api/audits` |

数据库路径可用环境变量 `AUDIT_DB_PATH` 覆盖（默认 `data/audits.db`）。

## 关键判定口径

- **整数溢出**：按 `pragma solidity` 解析实际版本。Solidity >=0.8 普通算术受编译器内置检查保护，不报告；仅报告 `unchecked { ... }` 块内运算。<0.8 且未使用 SafeMath 才报告；`.add/.sub/.mul` 不报告。
- **未授权访问**：逐函数解析，public/external 且改写状态（写存储/转 ETH/selfdestruct）而无 owner/role 校验才报告；view/pure、构造函数、无函数体声明，以及仅操作 `msg.sender` 自身槽位的存取款/标准转账不报告。
- 注释与字符串字面量不参与任何匹配；行号由字符偏移换算，上下文以命中行为中心，多个问题落在同一行也各自对齐。
- 同一规则同一行只报一条；评分按严重等级扣分并对每级扣分设上限。

## 测试

```bash
python -m unittest discover -s tests
```
