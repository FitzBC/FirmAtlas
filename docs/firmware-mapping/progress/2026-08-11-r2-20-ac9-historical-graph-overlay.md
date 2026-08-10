# R2-20：AC9 历史漏洞通信图覆盖层

日期：2026-08-11

状态：本轮实现完成，真实 AC9 双进程回放一致，全量本地回归通过，已提交并推送 GitHub。

## 1. 本轮问题

R2-04 已经能把 13 条历史漏洞接口期望与 AC9 Discovery Catalog 比较，但结果仍主要是离线 JSON：

- 用户无法在通信图上直接看到某条 CVE 对应的接口、参数和 handler 证据；
- “当前目录观察到结构”和“历史漏洞是否适用于这个固件版本”容易在展示层被混成一个结论；
- 未发现接口只有原因码，尚未形成可持久化、可检索、可复用的产品能力；
- 71 条产品级漏洞分母与 13 条结构化接口期望没有进入同一只读视图。

因此本轮不增加新的启发式发现器，而是补齐一条深接口：

`HistoricalExpectationDiff + RouteBindingReport + VulnerabilityAudit + CommunicationGraph → HistoricalGraphOverlay`

## 2. 设计边界

覆盖层遵守以下不变量：

1. graph 与 diff 必须来自同一个 `catalog_id`；
2. 只通过 Catalog candidate ID、route binding ID 和 `accepts_parameter` / `binds_handler` 精确语义边链接；
3. 不使用接口 label 模糊匹配，不创建图节点或图边；
4. `status` 与 `applicability` 是正交维度；
5. `observed + out_of_scope` 只表示跨版本结构重合，不表示当前固件存在漏洞；
6. 未映射的 Catalog 引用或 EvidenceAtom 进入 diagnostics，不静默丢失；
7. 覆盖层、查询结果和发布内容均为内容寻址身份；
8. MiniMax 不参与确定性事实生成。本轮没有调用、保存或回显用户提供的 API key。

覆盖层固定携带声明边界：历史漏洞声明只是上下文期望，图链接不能断言漏洞存在或版本适用性。

## 3. 工具化结果

### 3.1 确定性投影

新增 `firmatlas.mapping.historical_graph_overlay`：

- 每条 expectation 保存 CVE、接口、method、handler、期望/已观察/缺失参数；
- 保存 status、gap reason、自然语言解释、applicability、claimed versions 和适用性依据；
- 链接精确 graph node/edge、Catalog candidate/EvidenceAtom；
- 合并 route→handler 状态；
- 可选嵌入 71 条漏洞分母审计；
- JSON 可往返验证，篡改 `overlay_id` 会被拒绝。

### 3.2 独立固件分析入口

`python -m firmatlas.mapping compare-history` 新增：

- `--graph-output`
- `--overlay-output`
- `--vulnerability-scope`

因此一次新的 rootfs 冷启动分析可以同时产生 diff、通信图和历史覆盖层，不依赖 AC9 预制 Catalog。

### 3.3 持久化、CLI 与 HTTP

SQLite 新增不可变 `mapping_historical_graph_overlays`：

- 发布前验证源 graph、catalog 和所有 graph node/edge 引用；
- 重复发布相同内容幂等；
- 支持 status、applicability、gap reason、route status 和文本查询。

CLI：

- `firmatlas mapping publish-history-overlay`
- `firmatlas mapping query-history-overlay`

HTTP：

- `GET /api/mappings/graphs/{graph_id}/historical-overlay`

### 3.4 Console

通信图左侧新增“接口索引 / 历史漏洞对照”切换：

- CVE 卡片同时显示“已发现/部分发现/未发现/不可判定”和版本适用性；
- 显示 71 条漏洞全集分母，而不是只展示已经结构化的 13 条；
- 选择 CVE 后按覆盖层提供的精确 node IDs 聚焦图谱；
- 右侧显示期望与已观察参数、缺失参数、handler、gap explanation、版本依据和 claim boundary；
- 非 exact-artifact 条目固定提示“跨版本结构存在，不代表当前固件存在该漏洞”。

## 4. 测试先行记录

第一组失败测试先固定以下契约：

- 精确 Catalog/graph 引用链接；
- missing expectation 不产生伪图链接，并解释 `interface_not_observed`；
- 跨 Catalog 输入拒绝且不修改 graph/diff。

实现后 3/3 通过。

第二组失败测试固定持久化和查询契约：

- graph 未发布时拒绝 overlay；
- 发布幂等；
- status 与 applicability 联合过滤；
- graph 中不存在的 node/edge 引用拒绝；
- CLI 可发布并查询覆盖层；
- HTTP 特定子路由优先于普通 graph-id 路由。

第三组失败测试固定 Console 行为：

- 历史漏洞入口可见；
- CVE 可聚焦精确图节点；
- 版本边界、handler 和 71 条漏洞分母可见；
- 跨版本结构不会以当前漏洞事实展示。

局部验证结果：

- 后端/CLI/HTTP/AC9 报告相关测试：41 passed；
- Console：22 passed；
- TypeScript check：通过；
- Console production build：通过。
- 修复 Console 旧的 `communication_topology`/`communication_components` preset ID 漂移，并加入真实契约回归；“通信组件”按钮现在复用后端已发布的稳定 preset。

最终回归结果：

- Python unittest 全量：485 passed；
- Console Vitest 全量：9 files / 22 tests passed；
- TypeScript check 与 Vite production build：通过；
- R2-20 真实 AC9 报告：两次独立进程逐字节一致；
- R2-19 旧 AC9 HTTP/Console 报告：更新源码摘要后两次独立进程逐字节一致，原有图谱与 DLNA 断言未回归。

## 5. 真实 AC9 中间结果

样本：Tenda AC9，原制品 SHA-256
`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`。

本轮从 rootfs 独立执行 `auto-v13`，没有复用旧 Catalog：

- AnalysisRun：`mapping-analysis-run:45eda12627543cee4d50664fb746d5cd05ba99061da1c6a87e6a70a23f3e455b`
- Catalog：`discovery-catalog:e1b1f16da33f8d9ac0725bb3ae917efb80becc4d7b3d6db9305309126862a14a`
- Graph：5,674 nodes / 7,212 edges，completed
- Overlay：`historical-graph-overlay:b549a5351a7a3ea7d9642299e99599652fca040af627c1fba541616b0cb1c944`
- 13 条 expectation：8 observed / 5 not_assessable
- 适用性：2 exact_artifact / 11 out_of_scope
- exact-artifact：2/2 observed
- 路由结果：5 verified_expected_handler / 4 verified_route_binding / 1 handler_mismatch / 3 binding_not_observed
- overlay diagnostics：0

代表案例：

| CVE | 结构状态 | 版本适用性 | 结果解释 |
| --- | --- | --- | --- |
| CVE-2025-22946 | observed | exact_artifact | `SetOnlineDevName` 及 `mac/devName` 均链接到当前图谱证据 |
| CVE-2025-22949 | observed | exact_artifact | `SetSambaCfg` 与参数、路由线索均观察到 |
| CVE-2025-5836 | observed | out_of_scope | `SetIPTVCfg` 和 `list` 等结构存在，但历史声明属于另一 AC9 版本 |
| CVE-2025-5847 | observed | out_of_scope | `SetRemoteWebCfg` 的 POST 与参数已观察到，但不能据此断言当前版本漏洞 |
| CVE-2026-6015 | not_assessable | out_of_scope | 只有图中 Native 线索，`PPPOEPassword` 未观察到；版本本身也不属于当前制品 |

与 R2-04 相比，8/5 的接口结构总结没有改变，但 auto-v13 的原生深化把路由对照从早期 3 条已验证 binding 推进到 9 条 route/expected-handler 验证。这说明工具改进真实关闭了历史线索中的 Native owner 缺口；它仍没有改变漏洞适用性结论。

## 6. 确定性与产物

机器报告：

[`r2-20-vendor-tenda-ac9-historical-graph-overlay.json`](../samples/r2-20-vendor-tenda-ac9-historical-graph-overlay.json)

两次独立进程输出逐字节一致：

`6b86bb559df2388e6acdac32ca9bf5974a54ad8b738f8839ecc9017f83a9e15e`

报告包含真实 HTTP 查询 ID、不可变发布与重复发布结果、Console 源码摘要和代表 CVE 的精确图引用。

## 7. 反思与下一轮

本轮解决的是历史 ground truth 的产品化与证据边界，不是扩大漏洞语义覆盖率。当前 71 条产品漏洞中仍有：

- 13 条具有结构化接口，可直接比较；
- 3 条只有参数；
- 9 条已有语义分析但没有结构化通信信息；
- 46 条尚未完成语义分析。

下一轮优先做“漏检归因队列”：把 parameter-only / no-structured / not-analyzed 三类转成可调度义务，选择对 mapper recall 最有价值的 AC9 漏洞进行证据补全；大模型只负责受约束的历史文本结构化和解释建议，确定性 Producer、EvidenceAtom、版本边界与验证门仍由工具控制。

## 8. 交接与部署

- 主样本继续固定为 Tenda AC9；其他固件只做类别或家族对照。
- 本轮属于 firmware communication-mapping research/productization 范围。
- 按用户明确要求，本轮不执行 SSH 远程部署；本地验证后提交并推送 GitHub。
- GitHub `main` 已推送；远端 revision 由本轮最终 Git 记录固定。
- 后续会话应从本记录、机器报告及 research casebook 的 historical-interface-overlay stage 继续，不要把跨版本 observation 改写成漏洞事实。
