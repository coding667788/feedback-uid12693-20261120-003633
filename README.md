# 离线应用执行控制服务（Application Execution Control, Offline）

在 **Windows 原生 Python 3.12 + 标准库 + CPU** 下实现的离线白名单准入服务。
它模拟企业安全代理在启动软件前向本地服务申请准入：服务只把**判定结果**
写入“合成启动清单”，**从不运行任何被申请的程序**（清单中固定
`"execution_performed": false`）。全部输入均由代码自行合成，测试完全离线。

---

## 1. 目录结构

```
.
├── solution/                  # 服务源码包（仅标准库）
│   ├── __init__.py
│   ├── __main__.py            # CLI：python -m solution --input ... --output ...
│   ├── errors.py              # 全部错误码与常量
│   ├── clock.py               # 可注入固定时钟（保证可重放）
│   ├── crypto.py              # SHA-256 + HMAC 合成签发链原语
│   ├── paths.py               # Windows 路径规范化与路径段匹配
│   ├── models.py              # 准入请求/部件模型、身份摘要
│   ├── store.py               # SQLite（WAL）DDL 与数据访问
│   ├── bootstrap.py           # 工作区引导与合成实体装载
│   ├── engine.py              # 策略评估引擎（签发链验证 + 规则匹配）
│   ├── service.py             # 两阶段提交、事务内重核、管理操作、清单原子写
│   ├── replay.py              # 决策表/X-Y-Z/崩溃场景编排、子进程工人
│   ├── worker.py              # 独立工人进程入口（含真实 os._exit 崩溃点）
│   └── flow_process.py        # 两进程逆序测试的进程入口
├── tools/
│   └── make_cases.py          # 确定性生成 cases.json
├── tests/                     # 31 个 unittest 用例（6 个模块）
├── cases.json                 # 可重放合成输入（随仓库交付）
├── result.json                # 最近一次全量重放结果
└── README.md
```

---

## 2. 判定规则

### 2.1 请求绑定的要素

每个启动请求（`LaunchRequest`）绑定：组织 `org_id`、设备及其**代数**
`device_generation`、若干部件（1 个主程序 + 至多 25 个合成依赖）。每个部件绑定：

| 字段 | 含义 |
|---|---|
| `content_digest` | 应用内容 SHA-256 |
| `issuer_id` / `leaf_kid` | 签发者与其叶子密钥（换钥即换 `leaf_kid`） |
| `chain_digest` | 叶子密钥对内容摘要的 HMAC 见证（“经过当前签发链验证的摘要”） |
| `entry_path` | 完整 Windows 入口路径 |

请求身份 `identity_digest = SHA256(规范化(组织 + 每个部件的摘要/签发者/叶子密钥/见证/入口路径))`。
**同一内容摘要移动到不同入口、或签发者换钥，身份必然变化，强制作为新请求重判。**

### 2.2 策略组成

策略 = 组织**基线规则**（`baseline`，全组适用）+ **设备组规则**（`group`，
仅该组适用），按类型分为：

1. **摘要允许** `digest_allow`：按内容 SHA-256 允许；
2. **签发者与路径段联合允许** `issuer_path_allow`：签发者相等 **且**
   规则声明的路径段序列在入口路径中作为**连续整段**出现（整段比较，
   `exact` 不会误匹配 `exactish`）；
3. **明确拒绝** `deny_digest` / `deny_issuer_path`：同形匹配语义。

核心原则：

* **拒绝覆盖一切允许**——只要部件命中在有效期内的拒绝规则即拒绝，
  即使同时命中允许（含临时放宽）；
* **缺少有效授权默认拒绝**（`NO_AUTHORIZATION`）；
* 规则有 `valid_from/valid_to` 窗口，过期规则不再授权；唯一匹配的授权
  过期时返回 `RULE_EXPIRED`。

### 2.3 分代（generation）与收回

下列事件使设备代数 +1（或等效地使旧快照失效）：

* **设备转组**：组规则集合改变；
* **签发者凭据轮换**：旧叶子密钥置 `ROTATED`、新钥 `ACTIVE`，旧钥立即失效；
* **密钥吊销**：叶子密钥置 `REVOKED`。

策略撤回（规则移除）通过**策略版本号 +1** 与状态指纹变化表达，
不改设备代数。

### 2.4 设备组临时放宽

允许规则可被临时放宽给设备组，但必须同时满足：

* 挂在一条**允许**规则上——**明确拒绝规则禁止被放宽**
  （创建即返回 `TEMP_GRANT_INVALID`）；
* `approver1` 与 `approver2` 是**两位不同审批者**；
* 有合法的 `valid_from < valid_to` 窗口，目标设备组真实存在；
* 到期后自动失效（引擎报 `RULE_EXPIRED`）。

### 2.5 部件级与整单判定

主程序与全部依赖在**同一代策略**下逐个判定；**所有部件都允许**才整单
ALLOW，否则整单 DENY（顶层错误码取第一个拒绝部件的码）。仅整单 ALLOW
才在一个 SQLite 事务内写入**一条**持久准入记录与一份清单。

---

## 3. 两阶段提交与事务内重核

1. **prepare（准备阶段）**：读取一次状态快照作为“提示”，计算覆盖证书状态、
   远端状态、全部有效规则与临时授权的**指纹** `fingerprint`，做纯内存预检，
   不写入任何准入数据。
2. **commit（提交阶段）**：在 `BEGIN IMMEDIATE` 写事务内：
   1. 幂等检查：同 `request_id` 已有记录则原样返回固定回执；
   2. 重新核对请求代数 vs 设备当前代数、快照策略版本 vs 当前版本、
      快照指纹 vs 当前指纹；
   3. **从事务内连接重新加载全部受影响状态**（证书/吊销、远端签发者状态、
      当前版本有效规则、规则有效期窗口、临时授权），完整重跑引擎；
   4. 按错误精确度合并结论（见下），ALLOW 才写记录 + 原子写清单
      （临时文件 + `fsync` + `os.replace`）。

错误码优先级：签发链/吊销/远端状态等**安全硬失败** > 设备代数陈旧
`STALE_DEVICE_GENERATION` > 策略版本陈旧 `STALE_POLICY_VERSION` >
指纹不一致 `SNAPSHOT_STALE`。

**幂等回执**固定当时使用的政策版本与每个部件的命中规则；策略撤回后，
同一 `request_id` 重放仍返回原版本回执且不产生重复行，而新请求必须按
新版本重判。

---

## 4. 合成签发链（HMAC 模拟）

离线环境下用 HMAC-SHA256 模拟 X.509 信任链，语义等价：

* 根证书自签，下级证书由父级密钥对规范化字段签名，逐跳验签；
* 每跳证书检查 `ACTIVE` 状态与有效期窗口；外来组织的根不受信；
* 叶子密钥对 `content_digest` 再做 HMAC 得到 `chain_digest`，
  内容摘要被替换/移用即验签失败；
* 远端签发者状态用本地表模拟 OCSP（`GOOD/SUSPENDED/REVOKED`），
  非 GOOD 即拒绝。

---

## 5. 输入与输出

### 5.1 cases.json（输入，确定性可重放）

由 `python -m tools.make_cases` 生成，包含：

* `decision_fixture`：3 个设备组、39 台设备、合成证书链（含已轮换/已吊销/
  外来根）、远端状态表、**62 条规则（编号规则 R01–R36，含 R14B，外加
  R36D01–R36D25 共 25 条依赖规则）**；
* `decision_cases`：**36 条独立决策用例**，每条带
  `expect_decision/expect_error_code`；
* `flow_fixture` + `flow_requests`：X/Y/Z 三个顺序场景；
* `crash_fixture` + `crash_scenarios`：两个真实杀进程崩溃点；
* 两种执行顺序：`XYZ` 与 `ZYX`（含崩溃点逆序）。

### 5.2 result.json（输出）

* `decision_table`：36 条用例的期望/实际判定、错误码、持久记录数；
* `ordered_scenarios`：X/Y/Z 每一步的具体结果；
* `crash_scenarios`：工人退出码、恢复后记录数/清单数、孤儿回收情况；
* `overall_passed`：总判定。

### 5.3 合成启动清单（工作区 `data/manifests/<request_id>.json`）

只含受控部件清单、政策版本、代数、回执 id 与 `"execution_performed": false`，
不含任何可执行动作。

---

## 6. 错误码表

| 错误码 | 含义 |
|---|---|
| `OK` | 判定允许 |
| `DENY_EXPLICIT` | 命中明确拒绝规则（拒绝覆盖一切允许） |
| `NO_AUTHORIZATION` | 无任何有效授权，默认拒绝 |
| `RULE_EXPIRED` | 唯一匹配的规则/临时授权已过有效期 |
| `STALE_DEVICE_GENERATION` | 请求代数与当前代数不一致（转组/轮换/吊销） |
| `STALE_POLICY_VERSION` | 快照策略版本已过期（如规则撤回） |
| `SNAPSHOT_STALE` | 提交事务内重算的状态指纹与快照不一致 |
| `ISSUER_CHAIN_INVALID` | 签发链签名/有效期/内容见证验签失败 |
| `ISSUER_KEY_REVOKED` | 叶子或链上密钥处于 ROTATED/REVOKED 状态 |
| `ISSUER_UNTRUSTED` | 签发者不属于本组织受信根链 |
| `REMOTE_ISSUER_STATUS_BAD` | 远端签发者模拟状态为 SUSPENDED/REVOKED |
| `TEMP_GRANT_INVALID` | 临时授权非法（同人审批/放宽拒绝/窗口非法/组不存在） |
| `TOO_MANY_DEPENDENCIES` | 依赖数超过 25 个上限 |
| `BAD_REQUEST` / `CONTENT_INTEGRITY_FAILED` / `UNKNOWN_SNAPSHOT` | 请求校验错误 |

工人进程退出码：`0` 正常、`2` 业务错误、`3` 工人异常、
`42` 清单写入未提交时崩溃、`43` 提交完成后崩溃。

---

## 7. 运行方式

```bash
# 1. （重新）生成可重放输入
python -m tools.make_cases

# 2. 全量重放并产出结果文件（任务要求命令一）
python -m solution --input cases.json --output result.json

# 3. 自动化测试（任务要求命令二）
python -m unittest discover -s tests -v
```

测试中的崩溃用例会拉起**真实独立工人子进程**并以 `os._exit` 终止；
两进程逆序测试会并发拉起两个 `solution.flow_process` 进程，
各自使用独立工作区与 SQLite 数据库。

---

## 8. 实测结果（Windows 11 + Python 3.12.8，本机实测）

### 8.1 `python -m solution --input cases.json --output result.json`

```
decision table: 36/36 passed; ordered flows: OK; crash: 2/2
overall_passed=True
```

* 决策表 **36/36** 全部与期望一致（覆盖同名路径段、临时权限到期、
  远端签发者状态变化、轮换/吊销/外来根、入口移动重判、25 依赖上限等）；
* 顺序场景：
  * **X（旧策略预检后设备转组）**：预检 ALLOW → 转组后提交被
    `STALE_DEVICE_GENERATION` 拦截（代数 1→2）→ 新代重判 `NO_AUTHORIZATION`，
    持久记录 0 条；
  * **Y（一项依赖许可被吊销）**：首次 ALLOW（1 条记录）→ 吊销依赖密钥
    （代数+1）→ 旧代重提 `ISSUER_KEY_REVOKED` → 轮换新钥后新身份重判
    `NO_AUTHORIZATION`，记录始终 1 条；
  * **Z（先准入后策略撤回）**：v1 准入 → 撤回后版本升至 v2 → 同请求
    幂等重放仍返回 v1 固定回执（无重复行）→ 新请求按 v2 重判
    `NO_AUTHORIZATION`，记录 1 条；
* 崩溃场景：
  * `KILL_PRE_COMMIT`（退出码 42）：清单已写、事务未提交 → 重开库
    0 条记录、0 份清单，孤儿清单被恢复流程清除；
  * `KILL_POST_COMMIT`（退出码 43）：重开库恰好 1 条记录、1 份清单，
    同请求重放命中幂等分支，无重复行。

### 8.2 `python -m unittest discover -s tests -v`

```
Ran 31 tests in 6.5s
OK
```

| 测试模块 | 用例数 | 覆盖内容 |
|---|---:|---|
| `test_decision_table.py` | 13 | 36 条决策表逐条断言、拒绝覆盖、同名段、到期、持久化计数 |
| `test_admission_lifecycle.py` | 5 | 幂等回执、版本/命中规则固定、身份变化、25 依赖上限、Z 场景 |
| `test_temp_grants.py` | 6 | 双审批、禁止放宽拒绝、窗口/组校验、到期失效 |
| `test_crash_recovery.py` | 3 | 两个真实杀进程点、重开库对账、无部分准入/重复行 |
| `test_two_process_order.py` | 1 | 两个独立进程 XYZ vs ZYX 并发逆序，断言完全一致 |
| `test_cli.py` | 2 | CLI 端到端产出 result.json、错误输入处理 |
| 合计 | **31** | 全部通过 |

### 8.3 崩溃安全性说明

SQLite 工作在 WAL 模式，写事务随工人进程死亡自动回滚；清单文件在事务
提交前写入，崩溃后成为孤儿，由 `recover_orphan_manifests()` 按持久记录
对账清除。因此任何崩溃点之后重开数据库，都不会出现部分准入或重复行。
