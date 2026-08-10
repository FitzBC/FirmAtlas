# R2-21：AC9 历史漏检优先队列与配置键边界

日期：2026-08-11

状态：实现与真实 AC9 双阶段回放完成；本地全量回归、提交和 GitHub 推送见本文末尾交接。

## 1. 本轮目标

R2-20 把 13 条已结构化历史 expectation 叠加到通信图，但 71 条 AC9 产品级漏洞分母中仍有：

- 3 条只有所谓“参数”；
- 9 条已有语义分析、没有结构化通信事实；
- 46 条尚未语义分析。

如果只继续人工挑 CVE，后续会话无法稳定知道先分析什么、为什么分析以及怎样判定完成。本轮因此新增一个确定性深接口：

`HistoricalVulnerabilityAudit + HistoricalSemanticClue + DiscoveryCatalog → HistoricalCoverageQueue`

队列只负责组织证据补全工作，不替代漏洞来源，也不把当前固件中的 route clue 写回历史事实。

## 2. 测试先行的契约

首组失败测试先固定一个公开入口：

`build_historical_coverage_queue(audit, semantic_clues, catalog=None)`

必须满足：

1. 每个未进入接口比较的漏洞都成为一个开放任务；
2. 优先级和排序稳定，queue identity 由完整内容决定；
3. 自然语言误抽取的 `occurs` 必须进入 `repair_parameter_extraction`；
4. `a/b` 只有在两侧均为命名空间状态键时才作为复合字段，不能把 `/goform/...` 当复合参数；
5. Catalog 中 handler→route 命中只能形成 `catalog_route_clue`，不能自动产生 `source_verified_interface`；
6. HTTP request parameter、configuration key、route registration token 和完整 HTTP path 分开建模；
7. 审计范围外 clue、重复 clue 和无效字段分类必须拒绝。

红灯首先表现为新模块不存在；初版实现后，测试又发现 `/goform/GetDdosDefenceList` 会被错误拆成复合参数。规则收紧后，4 个队列合同测试和 CLI 端到端测试全部通过。

## 3. 原始来源核验改变了什么

完整来源、固定 commit、文件 SHA-256 和行号见
[AC9 parameter-only 原始来源核验](../research/2026-08-11-ac9-parameter-only-primary-sources.md)。

### CVE-2021-42659

原语义结果把短语 `list parameter occurs` 中的普通动词 `occurs` 当成参数。固定提交的原始报告直接给出：

- `POST /goform/SetVirtualServerCfg`；
- handler `formSetVirtualSer`；
- HTTP body 参数 `list`。

因此新 supplement 保存这条来源事实，同时保留版本冲突：原始报告写 V1 `15.03.05.19(6318)`，CVE 描述写 `15.03.02.19(6318)`，不能静默选一条覆盖另一条。

### CVE-2026-2191

`security.ddos.map` 是配置文件中的 key，不是已证明的 HTTP 参数。来源证明 `formGetDdosDefenceList` 读取它，但没有披露主 sink 的 path/method。另一个 `GetFirewallCfg → formGetFirewallCfg` binding 属于第二 sink，不能迁移给主 handler。

### CVE-2026-2192

来源证明拼写精确的 registration token `GetSysAutoRebbotCfg → formGetRebootTimer`，以及两个配置键 `sys.schedulereboot.start_time/end_time`。完整 `/goform/...` 只能是框架派生候选，method 未知。

这三条记录证明旧的 `parameter_only` 不是单一原因：它同时混入 NLP 假阳性、HTTP 参数已遗漏、配置键被错分，以及 handler 已知但 ingress 未知四种状态。

## 4. 工具化实现

新增 `firmatlas.mapping.historical_coverage_queue`：

- 版本化、内容寻址的 queue / entry / semantic clue 合同；
- `repair_parameter_extraction`、`verify_source_expectation`、`resolve_handler_to_route`、`recover_interface`、`extract_structured_communication`、`analyze_semantics` 六种动作；
- `source_verified`、`source_partial`、`catalog_clue_only`、`needs_primary_source`、`semantic_analysis_missing` 五种证据状态；
- suspicious parameter、compound sibling、configuration-key misclassification、source route token、Catalog route clue 和候选 analyzer 的独立字段；
- 对所有 clue 与审计分母做闭包校验。

`compare-history` 新增：

- `--semantic-clues`；
- `--coverage-queue-output`；
- 可重复 `--expectations`，允许旧基线加不可变 supplement，而不重写旧的 13 条 manifest。

一次上传固件冷启动分析现在可以同时输出 diff、graph、overlay 和下一轮任务队列。MiniMax 没有参与确定性事实生成；后续它可以在 `model-semantic-analyzer` 任务中提供候选，但候选仍需原始来源和当前制品证据分别晋级。

## 5. 两阶段真实 AC9 回放

样本固定为 Tenda AC9 `15.03.05.19`，原制品 SHA-256：

`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`

两次阶段均从 rootfs 独立执行 `auto-v13`：

- AnalysisRun：`mapping-analysis-run:45eda12627543cee4d50664fb746d5cd05ba99061da1c6a87e6a70a23f3e455b`
- Catalog：`discovery-catalog:e1b1f16da33f8d9ac0725bb3ae917efb80becc4d7b3d6db9305309126862a14a`

### 阶段 A：不修改旧 expectation 基线

13 条旧 expectation 的结果仍是 8 observed / 5 not_assessable。71 条漏洞分母生成 58 个开放任务：

- 3 `repair_parameter_extraction`；
- 9 `extract_structured_communication`；
- 46 `analyze_semantics`。

当前制品 Catalog 精确提供三个重要 clue：

| CVE | 来源状态 | 当前制品 clue | 队列解释 |
| --- | --- | --- | --- |
| CVE-2021-42659 | 完整 path/method/handler/body | `SetVirtualServerCfg` | 修复 `occurs` 后可进入 expectation replay |
| CVE-2026-2191 | config sink，主 path/method 未知 | `GetDdosDefenceList → formGetDdosDefenceList` | 只作 catalog clue；配置 ingress 仍开放 |
| CVE-2026-2192 | route token/handler/config keys | `GetSysAutoRebbotCfg → formGetRebootTimer` | token 双边一致；完整 path/method 仍未知 |

### 阶段 B：加入单条不可变 supplement

新 supplement 只增加 CVE-2021-42659，不改旧 manifest。最终 diff 为：

- 14 条 expectation：9 observed / 5 not_assessable；
- exact-artifact 从 2 条增至 3 条，3/3 observed；
- CVE-2021-42659 的 POST、`list` 和 handler 都由当前 Catalog 观察到，missing parameters 为 0；
- 开放队列从 58 降至 57；`repair_parameter_extraction` 从 3 降至 2。

剩余两个最高优先任务均为“语义字段类型修复 + 配置 ingress 未闭合”，而不是“当前固件没找到 route”。这一区分避免为现成 native sink 伪造直接 HTTP 参数边。

## 6. 机器产物与中间输出

- [原始来源核验](../research/2026-08-11-ac9-parameter-only-primary-sources.md)
- [语义 clue 输入](../samples/r2-21-vendor-tenda-ac9-historical-semantic-clues.json)
- [CVE-2021-42659 expectation supplement](../samples/r2-21-vendor-tenda-ac9-historical-expectation-supplement.json)
- [14 条 expectation 的真实 AC9 replay](../samples/r2-21-vendor-tenda-ac9-historical-replay.json)
- [57 条开放任务队列](../samples/r2-21-vendor-tenda-ac9-historical-coverage-queue.json)

关键身份：

- replay：`historical-expectation-diff:1da592c4319fac221a11e19f2117ea6014c72a88ce27d329f00133fca5577231`
- queue：`historical-coverage-queue:2b84180a4aaccf9b19d3efca5cf7e5e0c2f67336c84843b00a219782adeb778e`
- replay 文件 SHA-256：`a59c9a911bea8483a471a2c2ec43f541c300e70f2310fe154ee58bf3e7ebae42`
- queue 文件 SHA-256：`f284fd35d355afd1d2e229b7e34460d338e58ec7e2a81ac5987433846922d5f5`

## 7. Research casebook 评估

本轮接受进入既有 `tenda-ac9-split-web-stack-goform-ownership` 案例，新增第六阶段 `historical-coverage-priority-queue` 和开放义务 `configuration-ingress`。

应保留的认识时间线是：

1. R2-20 只知道 3 条 parameter-only；
2. 原始来源核验发现其中一条其实已有完整 HTTP 结构，另外两条不是 HTTP 参数；
3. 当前 Catalog 又证明两个 native route/handler clue；
4. 这些证据仍不能闭合“恶意配置如何从 HTTP ingress 写入配置存储”。

反事实失败是把 `security.ddos.map` 直接画成请求参数，或把 registration token 自动扩写成来源声称的 `/goform` path。机器 case corpus 已重新生成并通过 14 个 casebook 回归。

## 8. 验证记录

局部验证：

- historical queue 合同：4 passed；
- CLI diff/graph/overlay/queue 端到端：passed；
- R2-21 冻结报告：passed；
- research casebook：14 passed；
- `git diff --check`：passed。

最终验证：

- Python unittest 全量：490 passed / 128.301s；
- Console Vitest：9 files / 22 tests passed；
- Console TypeScript check 与 Vite production build：通过；
- 第二次独立 AC9 进程的 replay 与 queue 均通过 `cmp` 逐字节一致；
- 第二次 SHA-256 仍分别为 `a59c9a...ae42` 与 `f284fd...d5f5`；
- research case corpus 两份生成目标由同一 builder 重建，14 个 casebook 测试通过；
- `git diff --check`：通过。

## 9. 下一轮

优先实现 `configuration-ingress` producer/obligation：从备份恢复或配置上传前端开始，追踪 multipart/blob field、upload handler、配置解析/持久化写入点，再连接到 `formGetDdosDefenceList` 和 `formGetRebootTimer` 的读取 sink。

并行但次优先的队列动作是：先处理 9 条 `no_structured_communication`，再按稳定 CVE 顺序处理 46 条 `not_analyzed`。模型可以提出字段/接口候选，但 source type、版本冲突、artifact applicability 和 EvidenceAtom 晋级必须由确定性门控制。

## 10. 交接与部署

- 主样本继续固定为 Tenda AC9；其他样本只作为通信类别或阳性/阴性对照。
- 本轮只修改 `firmatlas.mapping`、mapping 测试、脚本和 `docs/firmware-mapping`，适用 mapping research exception。
- 按用户明确要求，不执行 SSH 远程部署；本地验证后提交并通过已配置 SSH 密钥推送 GitHub。
- 功能提交：`aaaeed83c28477b1e941a0fdd452831801c3e296`（`feat(mapping): prioritize AC9 historical coverage gaps`）。
- SSH 部署：N/A（用户明确排除本研究轨道，且仓库 `Firmware mapping research exception` 明确适用）。
- 后续会话从 queue 的两个 priority 95 配置 sink 开始，不要把 native route 命中误写为已恢复配置上传入口。
