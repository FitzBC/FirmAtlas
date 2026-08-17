# R2-29：AC9 历史漏洞完整覆盖账本与收敛门

> 日期：2026-08-14
> 主样本：Tenda AC9 `15.03.05.19`
> Profile / Registry：`auto-v20` / `builtin-v20`

## 1. 本轮为何是收敛项

R2-20 已把结构化历史接口投影到通信图，R2-21 又生成剩余漏洞的研究队列，但产品页面只展示
14 条 expectation。漏洞库分母是 71，因此用户仍无法逐项回答“找到了什么、哪些没找到、为何
没找到”。继续人工挑选 CVE 会增加分析轮次，却不会关闭这个产品断点。

本轮冻结一个深模块 seam：

`HistoricalGraphOverlay + HistoricalCoverageQueue → HistoricalCoverageLedger`

Overlay 负责已结构化、可关联 Catalog/graph 的历史期望，Queue 负责尚缺来源、语义或 ingress 的
记录。Ledger 只连接两个互补集合，不重新分析固件，不从漏洞文本创建接口、参数或图边。

## 2. 测试先行合同

公开 seam 固定为四层：

1. `build_historical_coverage_ledger(overlay, queue)` 必须恰好覆盖审计分母且每个 CVE 唯一；
2. SQLite 发布必须校验 graph、Catalog 与 overlay 身份，重复发布幂等；
3. HTTP `/api/mappings/graphs/<id>/historical-coverage` 支持 CVE、接口、参数、配置键和原因检索；
4. Console 历史视图显示完整分母，并且无 graph reference 的记录不得产生图焦点。

红灯依次表现为模块、Repository query、HTTP route 和 71 条页面文案不存在。每个切片实现后均
独立回归，再进入下一层。

## 3. 真实 AC9 结果

本轮从 AC9 rootfs 独立执行 auto-v20，结果身份与 R2-28 稳定一致：

- AnalysisRun：`mapping-analysis-run:32487fbbff90766cebcab7f1170cfe90ff1b22c08d4a5defdf3952ded0f65f2d`
- Catalog：`discovery-catalog:928b9884ac447fcb5e677edc76f39bb872eec9be3486e37f04ad9d233154ca57`
- Graph：`communication-graph:cbc905a860d6027093579c5cb430bd352303e2cd47465c961554d2dac7d779b8`
- Ledger：`historical-coverage-ledger:81e7e2bc5297d1433573cc96037e30ff79c2fc1c1336a147ebc4c2e8a0e5bd68`

71 条分母闭包如下：

| 状态 | 数量 | 含义 |
| --- | ---: | --- |
| observed | 9 | 当前制品 Catalog 观察到历史来源声明的通信结构；不等于漏洞存在 |
| partial | 2 | 有配置 sink、handler 或 route token 线索，但 HTTP ingress/字段类型未闭合 |
| not_assessable | 60 | 5 条结构化期望属于其他版本，9 条缺结构化通信来源，46 条尚无语义分析 |

集合也满足 `14 structured expectations + 57 queue entries = 71`。精确制品 expectation 为 3 条，
三条均 observed：`CVE-2025-22946`、`CVE-2025-22949`、`CVE-2021-42659`。

两个 partial 记录继续保持证据边界：

- `CVE-2026-2191`：`security.ddos.map` 是配置键；存在 native handler/route clue，但没有来源确认的主 HTTP ingress；
- `CVE-2026-2192`：两个 `sys.schedulereboot.*` 是配置键；来源确认 route token 与 handler，但 method 和完整 HTTP path 仍未知。

机器报告见 [R2-29 AC9 历史覆盖账本](../samples/r2-29-vendor-tenda-ac9-historical-coverage-ledger.json)。

## 4. 工具与页面固化

- 新增版本化、内容寻址、可回放的 `HistoricalCoverageLedger`；
- 新增 SQLite 不可变发布和按 graph 查询；
- 新增 HTTP endpoint 与 status/category/evidence-state facets；
- `compare-history` 新增 `--coverage-ledger-output`，用户上传固件的独立分析可一次生成 diff、graph、overlay、queue 和完整 ledger；
- Console 历史页展示 71 条分母、9/2/60 状态摘要、原因、下一动作、配置键边界和 graph reference 数；
- 配置键记录明确显示“不是已证明的 HTTP 参数”，且没有 graph reference 时不会触发图查询。

MiniMax 未参与任何确定性事实生成。后续只能在 `model-semantic-analyzer` 中补充 46 条
`semantic_analysis_missing` 的候选结构，候选仍须经过来源类型、版本适用性和 Catalog 证据门。

## 5. 案例时间线与反事实

本轮作为 `tenda-ac9-split-web-stack-goform-ownership` 第 14 阶段进入 casebook。必须保留：

1. R2-20 页面只能看到 13 条结构化期望；
2. R2-21 通过来源 supplement 增至 14 条，并留下 57 条队列；
3. R2-29 才把两组互补状态作为一个完整产品读模型发布。

反事实失败是只显示 14 条并在旁边写“总计 71”，这会隐藏 57 条不可判定原因；另一失败是把
Queue 中的 handler、配置键或模型线索画成接口节点。本轮实现同时拒绝这两种路径。

## 6. 收敛判断

AC9 的“历史漏洞逐项可解释性”在产品层已经收敛：71 条均有稳定状态和原因，不再通过逐 CVE
人工追踪来无限迭代。60 条 not_assessable 主要是来源/语义输入缺口，不是继续逆向同一固件即可
自动消除的 mapper 漏检。

下一阶段应转向平台级完成条件：用户上传入口到统一 AnalyzeRun、代表性 corpus gate 收敛，以及
有证据晋级门的 MiniMax 业务 Adapter。只有新的原始来源或明确 mapper 假阴性，才重新打开 AC9
单 CVE 深挖。

## 7. 验证与交接

- 真实 AC9 冷启动、报告生成与 71 条不变量：通过；
- Ledger module、Repository、HTTP 和 CLI 相关回归：通过；
- 全量 Python 回归：`533 tests`，`1384.050s`，通过；
- Console：`27 tests` 通过；TypeScript 检查和 production build 通过；
- 本地服务/API：真实 AC9 `auto-v20` 冷启动成功；health 与完整 ledger endpoint 均通过；
- 页面交互：历史页显示 71 条与 `9 / 2 / 60`；`CVE-2026-2191` 明确无图焦点且标示配置键边界；`CVE-2021-42659` 成功恢复 11 nodes / 9 edges 子图；浏览器控制台无 warning/error；
- SSH 部署：N/A，本轮属于 mapping research exception，且用户明确暂不远程部署。

后续会话从本文“收敛判断”开始，不应把 60 条 not_assessable 重新解释为 60 个固件 mapper bug。
