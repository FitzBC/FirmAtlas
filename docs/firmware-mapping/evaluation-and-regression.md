# 评测与回归体系

## 1. 两套门禁

项目同时维护：

1. **工程回归门禁**：证明每次变更没有破坏 Interface、数据迁移、API 和 UI；
2. **研究评测门禁**：证明方法在隔离数据集上优于基线，并且没有信息泄漏。

工程测试通过不代表论文假设成立；论文离线指标提高也不代表产品可安全发布。

## 2. 标注集设计

### 2.1 最小覆盖矩阵

| 架构 | 必须覆盖的身份难点 |
| --- | --- |
| `/goform/<Action>` | 路径即操作、共享 dispatcher、form 参数 |
| 共享 CGI | selector 拆分、动态 action、query/form 混合 |
| HNAP/SOAP | 单 endpoint、多 SOAPAction、XML namespace |
| PHP/ASP/Lua | 脚本入口、include、页面/动作分离 |
| REST/JSON | method、path variable、JSON schema、auth |
| JSON-RPC | 单 endpoint、method selector、id/state |
| Native route table | 字符串、注册、handler 和 getter 绑定 |
| 前端缺失 | backend-first 发现与覆盖解释 |
| 动态构造 URL | 字符串拼接、模板和 unknown 保留 |

### 2.2 标注单元

每个样本至少标注：

- Firmware Artifact digest 和来源；
- Interface/Operation identities；
- parameters、namespace、direction 和约束；
- frontend request builder；
- route/dispatcher/handler/parser；
- auth/state 条件；
- 关键关系和 Evidence Span；
- 已知缺失/不可判定范围；
- 若为漏洞案例：source-to-sink 路径、根因、补丁差异。

标注允许 `unknown`，并记录两位标注者分歧。不能为了计算 F1 强行补全不可观测真值。

## 3. 数据切分与防泄漏

- **时间切分**：历史知识只使用截止日期前公开案例；
- **固件家族切分**：相同代码谱系不得随机分到训练与测试；
- **设备层切分**：同型号跨版本、同厂商跨型号、跨厂商 OEM 分组报告；
- **制品去重**：按解包文件/函数/代码克隆检测重复打包；
- **信息条件切分**：无 seed、可选普通流量、历史案例、历史 PoC 分别评估；
- **目标后验隔离**：目标 PoC、补丁后验和等价触发样例不进入冷启动上下文。

论文报告应公开切分 manifest、摘要和排除理由；无法公开的固件至少公开标注 schema、评测脚本和可再分发子集。

## 4. 指标

### 4.1 发现与身份

- Interface Precision/Recall/F1；
- Operation split/merge error rate；
- Parameter Precision/Recall/F1；
- namespace/direction/type/requiredness accuracy；
- handler binding F1；
- exposed/internal classification accuracy。

### 4.2 通信架构

- node/edge micro and macro F1；
- external-input-to-handler path accuracy；
- external-input-to-sensitive-behavior path accuracy；
- auth/state guard recovery accuracy；
- graph edit distance（只作为辅助指标）；
- evidence replay success rate。

### 4.3 覆盖与校准

- false-absence rate：失败/未支持被错误解释为不存在的比例；
- status calibration：supported/refuted/unknown/conflict 与真值一致性；
- coverage completeness；
- unresolved obligation resolution rate；
- unsupported/timeout diagnostic accuracy。

### 4.4 架构关联

- Recall@1/5/10；
- MRR、nDCG；
- family/OEM false association rate；
- view-level ablation；
- coverage-stratified performance；
- “为什么关联”证据人工审核一致率。

### 4.5 漏洞机制

- candidate Recall@K；
- mechanism path correctness；
- root cause category accuracy；
- affected/fixed version discrimination；
- analyst review time reduction；
- false confirmation rate。

### 4.6 成本

- files/sec、bytes/sec；
- CPU/RAM/worker time；
- decompiled functions per confirmed relation；
- model tokens per resolved obligation；
- correct graph relations per CPU-hour；
- first useful snapshot latency。

## 5. 基线与消融

基线：

- seed-first 旧工具；
- 全局 regex/string scan；
- frontend-only 和 backend-only；
- path-style clustering；
- binary string/function similarity；
- CPE/版本/CWE 关联；
- 直接 LLM 分析有限文本；
- 全量 Native 深分析资源上界。

消融：

- 移除前端 producer；
- 移除 Native producer；
- 移除状态关系；
- 移除历史案例；
- 移除模型；
- 移除覆盖门控；
- 移除多视图中的每一个视图；
- seed optional evidence 开启/关闭。

## 6. 工程测试金字塔

### 6.1 纯领域测试

- canonical identity；
- evidence capability 晋级；
- relation validation；
- constraint closure；
- fingerprint coverage gating；
- Snapshot determinism。

### 6.2 Producer fixture tests

每个 producer 使用小型真实语法 fixture，断言其 EvidenceAtom，而不是内部 AST 或中间 JSON。包含正常、混淆、损坏、编码和资源预算案例。

Native Deep fixture 还必须同时包含结构化正例与误绑定负例：route literal、注册表项和 executable handler 三段证据缺一不可；普通 `.data`、非可执行 handler、仅字符串/符号共现以及不受信 section 均不得关闭调度义务。真实固件在当前 Profile 不支持时应记录 completed coverage 与 0 binding，不能跨过证据门限猜测关系。

MIPS inline-table Profile 额外要求 dynamic symbol 地址/大小证据、固定宽度 route 字段、零 padding 和 executable handler pointer。回归必须覆盖被篡改的 table-symbol proof、部分坏 entry 的 `partial`、重复注册保留、Frontend-only/Native-only 双向差集，以及真实 X5000R 123/199 selector binding；不能只断言 binding 数量而不逐字重放 EvidenceAtom 和机器报告。

MIPS handler value-flow Profile 必须覆盖 local/global GOT callee、GP 的 stack save/restore、`jalr` delay slot、caller/callee-saved 寄存器差异、参数/状态字符串来源和五段 EvidenceAtom 重放。instruction budget 耗尽不得发布半条 flow；首个条件分支必须成为显式 scope boundary。真实 X5000R 回归固定断言 72 条指令、`0x00420ad8` 边界以及 `lanIp→lan_ipaddr`、`lanNetmask→lan_netmask` 两条映射，不能线性穿越 DHCP 分支。

集合差异归因必须覆盖 Frontend-only 的 wrapper-only / auxiliary-consumer 分离，以及 Native-only 的 frontend-scope-gap / cross-native-exact / token-variant / no-reference 分离。测试必须从公开 Interface 验证 source mismatch、非法文本和预算 fail-closed；特别固定 `loginAuth` 与 `userloginAuth` 的边界负例，禁止 substring 相似性升级成 exact 或 handler binding。真实 X5000R 报告固定为 38/38/3/1/10，并逐字重放代表 EvidenceAtom。

扩展 Frontend Asset Graph 回归必须覆盖 constructor default URL、payload-variable selector、同名变量跨函数隔离、fileUpload payload 门限，以及 multipart URL 的等号型外层 selector / 斜杠型内层 selector。真实 X5000R 固定断言 199→203 operation、3 个 scope gap 全部关闭、差集变为 77/11；不得通过直接修改差集期望值掩盖 Producer 未恢复请求结构。

PIC call-site Profile 还需覆盖：单一二参数调用不足以推断 registrar、错误 relocation type、错误参数寄存器、无法建立 GOT 基址、非 executable symbol、跨调用拼接和篡改 Worker/Result proof。真实样本回归必须同时断言 route、handler、callsite、registrar、同组规模和 Scheduler 精确关闭数量，不能只断言“发现大于零”。

代表性 corpus gate 必须把证据层级作为一等字段：旧 Binwalk 派生目录、合成 fixture 与漏洞线索不得计入 real-firmware verified 数量。每个样本显式声明 required/forbidden Evidence Capability；Artifact SHA 不匹配、coverage 非 completed、能力缺失/越界或任一开放义务都必须降为 coverage gap。未提供任何样本的 required category 也必须出现在报告中并标记 acquisition gap，不能从聚合结果消失。

原始固件 Extraction 另设正负门限：容器命令退出 0 但派生文件数为 0 必须是 `extraction.no_output`，不能计为成功；非零/超时若保留安全派生产物可返回 partial；进程成功但 Inventory 有 symlink、文件数、字节或归档深度诊断时，Extraction 最高为 partial。真实样本记录必须绑定 Artifact SHA、Binwalk 版本、镜像摘要、执行指纹、Inventory SHA 与预算，不能只保存截图或终端文本。

Coverage 必须纵向单调传播：`Extraction/Inventory → Producer → Discovery Catalog → Corpus Report` 任一上游 required scope 非 completed，下游不得仅因选中文件成功而晋级 completed。Catalog identity 必须绑定源 Inventory coverage；同类别同时存在 contract fixture 成功与真实固件 coverage gap 时，类别显示 coverage gap，不能用合同通过掩盖真实样本缺口。

Research Case 合同必须验证内容寻址确定性、Evidence/Coverage 引用完整性、Stage 顺序、Obligation 先创建后关闭，以及 `supported/unresolved/rejected` 状态不会被最终结果回写。论文案例准入至少需要两种独立 evidence kind、一个具体反事实、论文用途和局限；单线 strings 命中不得成为 `paper_ready`。机器可读案例必须能由构建脚本语义一致地重建。

Ghidra Worker 实现后必须分别测试 candidate 产生和核心接受：被篡改的 image base、地址、xref、argument slot、script/tool SHA 或超预算结果不得关闭义务。自由文本反编译输出和 Worker confidence 不能替代原始 ELF 重放。

### 6.3 Module contract tests

所有主要行为通过 `FirmwareMapper` Interface 测试：

- no-seed analyze；
- partial success；
- deepen creates child snapshot；
- explain replays evidence；
- deterministic cache identity；
- producer failure isolation。

测试应允许替换 Ghidra/Model Adapter，但不得 mock Module 内部纯计算步骤。

### 6.4 Persistence/migration tests

- 空库初始化；
- 从当前生产 schema 升级；
- 旧查询兼容；
- Snapshot round trip；
- 写入中断与事务原子性；
- read projection rebuild。

### 6.5 API/UI tests

- 服务端分页、筛选和排序；
- unknown/partial 状态序列化；
- 多级调查栈逐级返回；
- 深层面板无交叉/遮挡；
- Evidence Bundle 可访问；
- 没有 Snapshot 与 0 个接口的视觉区别；
- 关联视图和证据解释。

### 6.6 安全测试

- archive traversal；
- symlink escape；
- decompression bomb budgets；
- malformed parser input；
- tool timeout and kill；
- untrusted HTML/strings escaped in UI；
- dynamic network disabled by default；
- sensitive PoC artifact access control。

## 7. 较大功能回归矩阵

每个里程碑至少执行：

| 检查 | 命令/证据 | 必需 |
| --- | --- | --- |
| 后端全量测试 | `make test` | 是 |
| 前端测试 | `pnpm --dir apps/console test` | 是 |
| 前端生产构建 | `make web-build` | 是 |
| 新模块 contract/fixture tests | 里程碑专用命令 | 是 |
| 本地 API health | `GET /api/health` | 是 |
| 本地行为 API | 覆盖本次行为的 endpoint | 是 |
| 本地浏览器 | 关键用户路径、console/network 无错误 | UI 改动必需 |
| schema migration | production-like database copy | 数据改动必需 |
| benchmark smoke | 固定小样本 + snapshot digest | 分析改动必需 |
| 远端部署验证 | revision/health/frontend/behavior endpoint | 完成状态必需 |

如果一次变更只修改文档，仍需执行文档链接检查、后端基线、前端测试和生产构建；不存在的行为检查在记录中标为不适用并说明理由。

## 8. 发布门限

单个里程碑可以先设工程门限，再在数据集成熟后冻结论文门限。严禁看到测试结果后修改测试集或门限而不记录。

最初建议：

- Snapshot schema/reference validator：100%；
- evidence replay：100%；
- deterministic fixture digest：100%；
- producer crash isolation：100%；
- no false success on unsupported/timeout：100%；
- 新能力的标注指标：先报告置信区间和误差类别，M2 后冻结数值门限；
- 所有旧 FirmAtlas 回归保持通过。

## 9. 进度记录中的回归证据

每次较大功能完成时记录：

```text
Work item:
Revision:
Schema/analyzer versions:
Datasets/fixtures:
Commands:
Passed/failed/skipped:
Performance delta:
Known coverage gaps:
satc_cloud release:
Remote checks:
```

失败结果保留在原记录中；修复后追加新记录并相互链接，不回写历史为“从未失败”。
