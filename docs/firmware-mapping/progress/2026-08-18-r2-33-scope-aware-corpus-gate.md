# R2-33：候选范围感知的代表性语料门禁

> 日期：2026-08-18
> 状态：本地实现与回归完成，待本轮 Git 发布
> 范围：`firmatlas.mapping`、Console、测试与 `docs/firmware-mapping`；SSH 部署不适用

## 1. 本轮问题与结论

本轮从 M1-11 的 `partial` 出发，先核查缺失类别究竟是分析能力缺口、样本获取缺口，还是报告编排缺口。结果发现三者不能混为一谈：

1. DAP-3520 的 completed Catalog 已包含真实脚本后端证据；
2. X5000R 的 completed Catalog 已包含 10 个没有已观察前端引用的 Native registration；
3. 旧 Corpus Report 只能验收整个混合 Catalog，不能声明“只用某一架构候选验收某一类别”，因此会把其他架构的 capability、obligation 和 coverage 混进结果；
4. DAP-2695 与 FRITZ!Box 4040 是更强的独立 holdout，但目前只有 producer 级实测，还没有 retained rootfs → AnalyzeRun → Catalog 的完整发布链，不能借它们抬高门禁。

因此本轮修复的是一个真实的 taxonomy/orchestration 缺陷：`CorpusSampleInput.scope_candidate_ids` 明确限定当前样本可使用的候选。候选、EvidenceAtom 和以候选为 target 的开放义务都按同一范围投影；未知候选、重复候选和没有 Catalog 的范围声明都会拒绝。报告契约升为 `firmatlas.mapping.corpus-report/v1alpha2`。

## 2. 状态变化时间线

| 阶段 | 状态 | 证据与解释 |
| --- | --- | --- |
| R2-33 开始 | `partial` | `script_backend=coverage_gap`，`native_only=acquisition_gap` |
| 一手来源审计 | 仍为 `partial` | DAP-2695 `__action.php` 与 FRITZ 4 个 rpcd plugin 可作为独立 holdout；均未形成完整 Catalog |
| 混合 Catalog 复核 | 发现编排缺陷 | DAP-3520 已有 268 个脚本候选；X5000R 已有 10 个 scope-aware native-only 候选 |
| 范围合同红灯 | 测试失败 | 公开 Interface 不接受 `scope_candidate_ids`，证明能力尚不存在 |
| 范围合同绿灯 | 单元测试通过 | 范围内 capability/计数/义务独立计算，未知 ID 拒绝 |
| 不可变发布/API 红灯 | 测试失败 | Repository 无 corpus 发布，HTTP 返回 404 |
| 持久化/API/Console 绿灯 | `passed` | 五个 required category 均有真实固件 `verified` 样本；报告可内容寻址发布、查询和可视化 |

这条时间线不会把早期 unresolved 状态重写成“从一开始就已完成”。

## 3. 当前机器可读结果

报告：[m1-11-representative-corpus-report.json](../samples/m1-11-representative-corpus-report.json)

生成与发布：

```bash
PYTHONPATH=src python scripts/build_mapping_corpus_report.py > /tmp/corpus-report.json
PYTHONPATH=src python -m firmatlas mapping publish-corpus-report \
  --database var/mapping-work/firmatlas.db /tmp/corpus-report.json
PYTHONPATH=src python -m firmatlas mapping query-corpus-report \
  --database var/mapping-work/firmatlas.db
```

当前报告 `gate_status=passed`，五个 required category 均为 `verified`。关键新晋级样本：

| 样本 | 范围 | 结果 |
| --- | --- | --- |
| DAP-3520 script backend | `www/home_sys.php` 与 `www/__action.php` 来源的 268 个候选 | 276 EvidenceAtom，`reads_parameter`/`writes_configuration` 满足，禁止的 `constructs_request` 未出现 |
| X5000R native-only | `difference_side=native_only` 且 `attribution_kind=native_registration_no_frontend_reference` 的 10 个候选 | 40 EvidenceAtom，`mentions_endpoint`/`binds_handler` 满足，禁止的 `constructs_request` 未出现 |

`script_backend` 类别仍保留旧 D-Link DSL 的 coverage gap 记录。类别状态取“是否至少存在一个真实 verified 样本”，不会删除同类别的缺口；Console 同时显示 `real` 和 `gap` 计数。

## 4. 独立 holdout 与泛化边界

一手来源记录：[R2-33 representative corpus primary sources](../research/2026-08-18-r2-33-representative-corpus-primary-sources.md)。

- D-Link DAP-2695 Rev.A 1.20B20 RC101：官方 ZIP SHA-256 `5a1a4e7f45b0a6fa2d58da0142a76dc153f3e3d3fe99bc1fdf99ecc0aae77f8e`，内层 BIN SHA-256 `11479c2dcce46af141954a067a0c0355d76bd49ed1793894b1d5960ac5300609`。真实 `www/__action.php` producer 实测 completed，356 evidence、338 state accesses，但尚未保留 rootfs/发布 Catalog。
- OpenWrt 19.07.10 FRITZ!Box 4040：官方 image SHA-256 `cc34c5449138fd2f247cbd448922df01093b754ed0b9ca02150f302e044c0f00`。4 个 ARM rpcd plugin 恢复 4 objects、24 methods、60 evidence，但当前缺少 direct Native registration result → Catalog Adapter。

所以 `passed` 只表示五个代表类别已有满足门限的真实样本，不等于所有厂商、ISA、脚本语言和 dispatcher 子类型均已泛化验证。DAP-2695 与 FRITZ 是下一轮独立 holdout，而不是本轮门禁的隐含证据。

## 5. 工程与 UI 结果

- SQLite 新增不可变 `mapping_corpus_reports`，相同内容幂等发布，身份冲突拒绝；
- CLI 支持 `publish-corpus-report` 与 `query-corpus-report`；
- HTTP `GET /api/mappings/corpus-report` 返回最新报告，无报告时明确 404；
- Console 新增“语料门禁”视图，展示五类状态、真实样本、范围候选数、证据数与开放义务；
- 页面固定展示解释边界，避免把类别覆盖通过误读为全面泛化；
- MiniMax 不参与门禁事实生成或晋级。

## 6. TDD、回归与下一出口

本轮保留三组红—绿证据：scope Interface、Repository/CLI、HTTP/Console。

- Python 全量回归：555 项通过，耗时 1265.012 秒；
- Console：9 个测试文件、29 项通过；
- TypeScript app/node 两套检查通过；Vite production build 通过，1801 modules；
- 3 份既有 AC9 Console acceptance 报告按最终 source SHA 重生成并通过绑定测试；
- Corpus 报告重放与 checked-in JSON 逐字节一致；全部样本 JSON 可解析；Python compileall、secret 前缀扫描、`git diff --check` 通过；
- SQLite 首次发布 `created=true`，CLI 查询返回同一 report ID；
- 最终本地服务 `GET /api/health`、`GET /`、`GET /api/mappings/corpus-report`、`GET /api/mappings/graphs` 均返回 200；Corpus API 为 `passed`、5 categories；
- 真实浏览器先验收门禁页：`5/5`、DAP-3520 `268/276`、X5000R `10/40`、scope 数和 holdout 边界可见；交互中发现旧 category key 未中文化，修正为“表单处理链 / HNAP-SOAP / 共享 CGI 网关”后重新构建和复验；
- 浏览器再切回 AC9 图谱，仍显示 1,665 nodes、2,273 edges、partial coverage，并成功聚焦 `ubus://luci/getFeatures`。

本轮服务继续运行于 `127.0.0.1:18789`，供后续检查。通信测绘专项按用户明确范围不执行 SSH 部署；本轮必须提交并通过 GitHub SSH 推送。

下一出口为 R2-34：优先实现 Native registration result → Catalog Adapter，并对 FRITZ!Box 4040 做独立 holdout；随后受控重取 DAP-2695，走 raw artifact/rootfs → AnalyzeRun → Catalog，验证门禁能否在不复用 DAP-3520/X5000R 的情况下保持通过。
