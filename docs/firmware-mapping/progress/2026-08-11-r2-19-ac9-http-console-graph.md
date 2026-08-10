# R2-19：AC9 产品 HTTP 与 Console 通信图谱

> 日期：2026-08-11
> 主样本：Tenda AC9 `15.03.05.19`
> 范围：mapping graph HTTP Adapter、Console graph workspace、AC9 实证与研究案例
> 部署：未执行；用户明确要求当前通信测绘工作不做 SSH 远程部署

## 1. 本轮问题

R2-18 已经证明完整通信图可以不可变保存和统一查询，但产品仍只能通过 CLI 读取。若 Console
下载完整 JSON 后自行筛选、遍历和回填证据，浏览器会成为第二套推理器：相同文件里的无关
接口可能被带入，预算和 partial 状态可能丢失，开放义务也可能被视觉上误画成 owner。

本轮固定两个产品 seam：

```text
GET /api/mappings/graphs
GET /api/mappings/graphs/{graph_id} + CommunicationGraphQuery parameters

CommunicationGraphWorkspace
  graph list → bounded interface index → exact interface focus → preset subgraph
```

HTTP Adapter 只翻译参数；节点选择、语义 BFS、预算、EvidenceAtom 回填和无悬空边仍由
`DiscoveryCatalogRepository.query_communication_graph` 负责。Console 只展示返回事实。

## 2. 红灯—绿灯记录

1. **HTTP 红灯**：真实 `ThreadingHTTPServer` 对 `/api/mappings/graphs` 返回 404；增加 graph list
   和 single graph route，重复 kind/status/focus 参数保持 tuple，未知 graph 返回 404。
2. **客户端红灯**：Console client 没有 `mappingGraph`；测试证明调用为 `not a function`。增加完整
   TypeScript query/result contract，并验证重复 `node_kind`、`focus_node` 不被折叠。
3. **交互红灯**：测绘页面没有“架构图谱”；增加独立 `CommunicationGraphWorkspace`，只在进入
   图谱视图后加载图和接口索引，避免影响现有目录/隐藏接口/版本对比工作流。
4. **证据下钻**：聚焦接口后，图按入口、参数/契约、分发/绑定、执行主体、义务分层；点击节点
   显示属性、相邻语义边和源 Catalog EvidenceAtom，不把 edge tooltip 当证据。
5. **类型修正**：前端测试通过后，`tsc` 发现 mock options 可能为 undefined；修正测试合同后
   TypeScript 检查通过。
6. **视觉验证限制**：真实浏览器 DOM 和点击路径成功；截图传输通道超时。保留该失败记录，
   不把它倒写成截图验证成功；生产构建、可访问 DOM 和真实交互结果不受影响。

## 3. AC9 独立产品回放

机器报告：
[`r2-19-vendor-tenda-ac9-http-console-graph.json`](../samples/r2-19-vendor-tenda-ac9-http-console-graph.json)

生成器不读取 R2-18 查询结果作为事实输入，而是重新执行：

```text
AC9 rootfs → auto-v13 AnalyzeRun → completed Catalog
           → CommunicationGraphPolicy → 5,674 nodes / 7,212 edges
           → temporary SQLite publish → real HTTP server → production Console
```

HTTP 实测结果：

| 检查 | 结果 |
|---|---|
| `/api/health` | `ok` |
| graph list | 1 个图，projection `completed` |
| `q=dlna&node_kind=interface` | 4 个接口，稳定 query ID |
| `SetDlnaCfg + interface_structure` | `completed`，23 节点 / 22 边 / 6 维度 |
| `SetDlnaCfg + parameter_state` | 7 节点 / 6 边，`deviceName/dlnaEn/scanList` |
| `dlnaEn` EvidenceAtom | `serializes_parameter`，`webroot_ro/js/dlna.js:45` |
| owner 状态 | 4 条 `registers_route` obligation 仍为 open |

真实浏览器从“通信测绘 → 架构图谱”搜索 `dlna` 后观察到：

- `GetDlnaCfg`、`SetDlnaCfg`、`expandDlnaFile?`、`refreshDLNA` 四个精确接口；
- 聚焦 `SetDlnaCfg` 后显示 invocation、interface、parameter、response contract、feature gate、
  obligation 六类节点；
- 点击 `dlnaEn` 能看到 `serializes_parameter`，没有生成 handler owner；
- 四个 preset 可以在同一精确焦点上重新查询，不在浏览器中拼图。

机器报告双进程逐字节一致，SHA-256：
`faaabafc83a6ac2a5d55949a15a1936ac731b3cc57fb66265aea8f5648490609`。

R2-20 增加历史漏洞覆盖层交互后，本报告按同一 AC9 分析与 HTTP 查询重新执行两次；图谱、DLNA 查询和义务断言未变化，仅 Console 源码摘要与由其决定的报告摘要更新。

## 4. UI 设计说明

页面使用响应式三栏：左侧是可搜索接口索引，中间是可横向滚动的证据关系图，右侧是节点证据。
小屏按索引、图、证据顺序堆叠；大图不会压缩成不可读缩略图。颜色只表示结构角色：cyan 为
暴露接口，violet 为参数，signal 为执行主体/组件，amber 为 binding/handler，ember 为开放义务。

查询状态、节点/边数量、维度、diagnostic、固件摘要和 Catalog coverage 始终可见。布局不会用
动画或视觉邻近替代关系；真实边仍来自返回的稳定 edge identity。

## 5. 当前验证

- HTTP graph focused test：通过；
- Console 用户交互合同：通过；
- 后端全量回归：474 passed；
- Console 全量回归：21 passed；
- Console TypeScript check 与 production build：通过；
- AC9 真实 HTTP、生产文档和浏览器交互：通过；
- AC9 报告双进程确定性：逐字节相同；
- Python compile、JSON、diff-check 与敏感信息扫描：通过；
- MiniMax 未参与事实、查询或图布局，用户 key 未保存。

## 6. 下一轮交接

1. 将历史漏洞 expectation 作为独立 overlay 连接到 interface/parameter identity，绝不写入事实图；
2. 用 AC9 历史 transport-method gap 验证 framework semantics 与漏检归因；
3. 对 DAP-3520 HNAP、X5000R shared-CGI/nested dispatch、OpenWrt ubus 重放同一 HTTP/Console
   合同，确认分层布局不是 Tenda 特化；
4. 增加用户上传固件后的 AnalyzeRun/graph 发布任务状态与制品去重入口；
5. 后续 MiniMax 只读取 query result，生成引用稳定 ID 的解释或义务建议。
