# Backend: Python FastAPI

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## 扫描判定规则

- **整数溢出**：按 `pragma solidity` 声明的实际版本判定。
  - `>=0.8.0`：内置溢出检查生效，普通算术（`+=`、`++` 等）安全，不报；
    仅 `unchecked {}` 块内的算术报 medium（内置检查在该块内不生效）。
  - `<0.8.0` 或未声明版本：未使用 SafeMath（`using SafeMath for ...`）时报 high；
    已使用 SafeMath 则不报。
- **未授权访问**：`public`/`external` 且修改状态的函数，若无访问控制修饰符
  （`onlyOwner` 等）、函数体内无 `msg.sender` 权限校验、且操作的不是调用者
  自己的数据（`balances[msg.sender]` 模式），判定为任何人都可以调用，报 high。
  `view`/`pure` 函数与 ERC20/721 标准公开接口不报。
- **重入 / selfdestruct / tx.origin / 精度损失**：基于去注释后的代码匹配，
  行号与上下文按原始代码精确定位（前后各 1 行）。

## 评分口径（v2）

满分 100，每个漏洞按严重度扣分：critical 25 / high 15 / medium 8 / low 3，最低 0 分。
等级：>=90 Excellent，>=70 Good，>=50 Fair，<50 Poor。
规则可通过 `GET /api/scoring-rules` 查询。历史记录评分在审计时落库，
读取不重算，口径稳定。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/audit` | 扫描合约并落库（空代码 400，失败不落库可重试） |
| GET | `/api/history` | 审计历史列表 |
| GET | `/api/history/{id}` | 审计详情（与列表同源，结论一致） |
| GET | `/api/patterns` | 漏洞模式库 |
| GET | `/api/scoring-rules` | 评分口径说明 |
| POST | `/api/report/{id}` | 生成 PDF 报告 |
| GET | `/api/reports/{file}` | 下载 PDF 报告 |
