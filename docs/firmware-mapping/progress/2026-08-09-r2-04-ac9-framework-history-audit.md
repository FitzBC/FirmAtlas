# R2-04：AC9 跨资源框架语义、漏洞全集与路由绑定审计

> 主样本：Tenda AC9 V15.03.05.19 / FirmEmuHub `BM-2024-00012`
> 制品 SHA-256：`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`

## 本轮目标与结论

本轮继续以 AC9 为首要典型样本，处理 R2-03 留下的三个问题：页面文件不能单独证明
`R.pageModel.setUrl` 使用 POST；13 条结构化历史记录不能代表漏洞全集；接口字符串存在也不等于
已恢复 route→handler 绑定。

`auto-v2` 引入跨资源 Frontend Asset Graph。只有框架函数体内观察到精确
`$.post(pageModel.setUrl, ...)`，页面候选才从 unknown method 晋级为 POST，并同时引用页面与
框架两个 EvidenceAtom。真实回放证明 31 个 page-model 接口为 POST，历史 expectation 从
R2-03 的 7 observed / 1 partial / 5 not-assessable 变为 8 / 0 / 5。

## 分母与版本关联

数据库中按规范化 vendor/product 得到 71 条 AC9 产品级漏洞：13 条有接口事实、3 条只有参数、
9 条有语义分析但无结构化通信、46 条未分析。完整分母保存在
[vulnerability scope](../samples/r2-04-vendor-tenda-ac9-vulnerability-scope.json)，不可只汇报可比较的
13 条。

平台另有三个 AC9 固件候选：当前 `BM-2024-00012` 有 30 条 high-confidence、curated-evidence
的 `reproduced_on` 关联；原厂 `V15.03.05.15` 和 `V15.03.06.62` 候选当前均为 0。数据库候选的
`firmware_version` 字段对 BM 样本仍是文件名，因此本轮以已冻结的 benchmark evidence 与制品
SHA-256 确定 `.19`，并保留该数据质量限制。产品级 71 与样本级 30 是两个不同集合。

## 路由绑定与中间输出

新增 `compare_historical_route_bindings(catalog, expectations)`，要求精确 route identity，并在
历史记录声明 handler 时验证预期 handler，而不是接受任意绑定。13 条结果为：

| 状态 | 数量 |
| --- | ---: |
| verified expected handler | 2 |
| verified route binding | 1 |
| native clue only | 5 |
| binding not observed | 5 |

当前精确版本的 `SetOnlineDevName → formSetDeviceName` 已绑定；`SetSambaCfg` 已恢复接口与参数，
`bin/httpd` 也含 route clue，但尚无验证过的 handler binding。字符串 `formSetSambaConf` 只是一条
stripped binary 线索，不晋级为 symbol 或绑定事实。完整机器输出见
[R2-04 framework/history report](../samples/r2-04-vendor-tenda-ac9-framework-history.json)。

## TDD 时间线与反事实

1. RED：跨文件页面 method 无公共 seam；GREEN：`discover_frontend_asset_graph` 生成双来源证据。
2. RED：旧报告会随默认 Profile 漂移；GREEN：冻结 `auto-v1/builtin-v1`，默认升级为 v2。
3. RED：只统计 13 条可比较漏洞会产生选择偏差；GREEN：71 条全部进入 audit denominator。
4. RED：同 route 的错误 handler 也会算命中；GREEN：route-binding report 验证声明 handler。
5. 真实回放：method gap 关闭，但 `SetSambaCfg` binding obligation 保持开放。

反事实是：只看页面局部文件会永久留下 method unknown；只看 13 条会声称“历史接口完整覆盖”；
只搜 `formSetSambaConf` 会伪造 route-handler 关系。本例继续保留阶段性失败，适合论文展示
history-guided producer 改进、denominator guard 与 evidence promotion gate。

## 结果与下一轮

最新 Catalog 为 3461 candidates、130 parameters、4056 EvidenceAtom、89 open obligations；45 条
ARM route binding 与 45 个 handler 已验证。下一轮优先追踪 `SetSambaCfg` 的替代注册模式，并为
46 条未分析 AC9 记录自动回填结构化通信 expectation；随后在 DAP-3520/X5000R 复用相同审计。

## 验证记录

- Frontend、AnalyzeRun、historical expectation 定向测试全部通过；
- `make test`：390 项通过；Console Vitest：9 个文件、19 项通过；TypeScript 与 production build 通过；
- R2-01、两份 R2-02、R2-03、两份 R2-04 报告由脚本重放并逐字段相等；
- framework/history 报告 SHA-256：`90b5599e683b1c5563f27ce048c331e407fde456b360930cd761f2137664182c`；
- vulnerability scope SHA-256：`1089699ba41bfa72742d298150e74e4bbb38720b23fcc9bc598458b464996ea4`；
- Python/JSON 检查、凭据片段扫描和 `git diff --check` 通过。

本轮属于 firmware mapping research，SSH 部署不适用。
