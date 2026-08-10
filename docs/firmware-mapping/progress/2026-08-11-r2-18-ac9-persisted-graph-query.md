# R2-18：AC9 通信架构图持久化与统一查询

> 日期：2026-08-11
> 范围：`firmatlas.mapping`、mapping CLI/脚本/测试/文档
> 主样本：Tenda AC9 `15.03.05.19`
> 部署：不适用；用户明确排除 SSH，且本轮符合 mapping research exception

## 1. 问题与 seam

R2-17 生成了可用于 UI 的确定性图，但 JSON 仍是一次性文件。如果 HTTP、CLI 和 Console 各自
读取 JSON 并实现筛选，会产生三套焦点、预算、EvidenceAtom 与 obligation 语义。本轮冻结两个
公开 Interface：

```text
CommunicationArchitectureGraph.from_dict / to_dict
DiscoveryCatalogRepository.publish_communication_graph
DiscoveryCatalogRepository.query_communication_graph(graph_id, query)
```

第一个 Interface 负责文档 schema、enum、稳定 edge identity、重复身份和引用闭包；第二个深
Module 隐藏 SQLite 表、内容摘要、索引、preset、精确焦点、语义 BFS、文本/证据选择、预算、
facet 和源 Catalog EvidenceAtom 回填。查询不重新分析固件，不产生新的固件或漏洞事实。

## 2. TDD 迭代记录

1. **文档恢复红灯**：图只有 `to_dict`，持久化内容无法安全恢复；增加 `from_dict` 与悬空边、
   稳定 edge identity、schema/enum/重复身份验证。
2. **发布红灯**：repository 不认识 graph；新增 graph/node/edge 三层 SQLite 表。发布前要求源
   Catalog 已存在，firmware、coverage 和全部 EvidenceAtom ID 一致；写入在一个事务内完成。
3. **不可变红灯**：同 graph identity 重复发布改为幂等 `created=false`，不同内容冲突拒绝。
4. **查询红灯**：初版只是整图回传，`parameter_state` preset 仍出现 artifact；实现 preset 允许
   集合、精确 node/canonical identity 种子、语义 BFS、文本/EvidenceAtom/status 过滤与预算。
5. **结果完整性**：预算先截节点，再只保留两端仍在结果中的边；缺失焦点或预算截断为 partial。
6. **证据下钻**：查询从源 Catalog 回填选中节点/边引用的完整 EvidenceAtom，而不是复制一份
   无来源的摘要。
7. **耐久性**：SQLite 关闭并重开后再次查询；CLI 用 AnalyzeRun JSON + graph JSON 一次发布，
   后续 `query-graph` 复用同一 `CommunicationGraphQuery`。
8. **审阅修正**：查询返回顺序最初沿原图而非焦点距离；现按 hop/node identity 稳定排序，并把
   `total_edge_count` 固定为预算前匹配数。
9. **确定性修正**：双进程回放最初只在 SQLite `published_at` 不同；该字段保留为 repository
   审计元数据，但从可复现样本清单投影中剔除。修正后两次报告逐字节相同。

## 3. AC9 实证

机器报告：
[`r2-18-vendor-tenda-ac9-graph-query.json`](../samples/r2-18-vendor-tenda-ac9-graph-query.json)

同一个 `auto-v13` AnalyzeRun 发布：

- Catalog：`completed`；
- 完整图：5,674 节点、7,212 边，projection `completed`；
- 第一次 Catalog/graph 发布均 `created=true`；
- 同图重复发布 `created=false` 且内容 SHA 相同；
- repository 关闭并重开后 `list-graphs.total=1`。

五类查询均为 `completed`：

| 查询 | 节点/边 | 解释 |
|---|---:|---|
| `interface_structure` + 4 个 DLNA 精确接口 | 36 / 35 | 接口、参数、调用状态、feature gate、response contract 与 4 条开放义务 |
| `parameter_state` | 16 / 12 | 4 接口、6 参数、6 parameter clue；不混入 artifact |
| `completeness` | 62 / 63 | 加入 association、feature pivot、literal xref、route/handler 邻接，但不迁移 owner |
| text=`minidlna` | 3 / 1 | absent component、`time_check` command handler、`httpd→minidlna` candidate relation |
| `dlnaEn` EvidenceAtom | 4 / 5 | 请求、参数、参数线索与来源 artifact，回填 3 条原始 EvidenceAtom |

`dlnaEn` 下钻的三条证据分别定位：

- `webroot_ro/js/dlna.js:22`：`constructs_request`；
- `webroot_ro/js/libs/public.js:1335`：`resolves_transport_method=POST`；
- `webroot_ro/js/dlna.js:45`：`serializes_parameter=dlnaEn`。

这个结果说明查询可以把接口、参数、通信组件和证据分维度展示，同时仍保持 AC9 四条 DLNA
Web owner 义务开放；`minidlna` 组件链不会被查询层画成 `/goform` handler。

最终机器报告 SHA-256：
`de397b6b843f6f9343ef731cf834371c45df5b5deea8fa16ab4d88725e9f33e0`。

## 4. CLI 工作流

```bash
PYTHONPATH=src python3 -m firmatlas.cli mapping publish-graph \
  --database var/firmatlas.db \
  --catalog-document mapping-analysis-run.json \
  communication-graph.json

PYTHONPATH=src python3 -m firmatlas.cli mapping query-graph \
  --database var/firmatlas.db <graph-id> \
  --preset parameter_state \
  --focus-identity goform/SetDlnaCfg \
  --max-hops 2
```

`list-graphs` 返回 source catalog、firmware、coverage、projection、node/edge count 和发布时间。

## 5. 验证门

- graph projection/document/repository/catalog focused tests：36 passed；
- R2-18 repository 独立合同：8 passed；
- 报告双进程回放：逐字节相同；
- research case rebuild：14 passed，两个 corpus 文件逐字节相同；
- mapping 全量回归：408 passed；
- Console 回归：19 passed，production build 成功；
- py_compile/JSON/diff-check/secret scan：通过；
- MiniMax 未进入事实、存储或查询层，用户 key 未写入任何产物。

## 6. 下一轮交接

1. 在现有本地产品服务增加只调用 repository Interface 的 HTTP Adapter；
2. Console 实现 preset 切换、精确焦点、类型/状态过滤、证据抽屉和 coverage/obligation overlay；
3. 对 DAP-3520 HNAP、X5000R shared-CGI/nested dispatch、OpenWrt ubus 重放持久化查询；
4. 历史 expectation 作为独立 overlay，通过 candidate/evidence identity 连接，不写入事实图；
5. MiniMax 后续只对查询结果生成解释或下一步义务建议，必须引用返回的稳定 ID。
