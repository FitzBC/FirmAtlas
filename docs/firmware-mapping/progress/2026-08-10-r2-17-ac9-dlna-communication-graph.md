# R2-17：AC9 主样本通信架构图投影

> 日期：2026-08-10
> 范围：`firmatlas.mapping`、mapping 脚本/测试/文档
> 样本角色：Tenda AC9 为主样本；官方 AC18 `V15.03.05.19(6318)` 仅为同家族正向对照
> 部署：不适用；用户明确排除 SSH，且符合仓库 mapping research exception

## 1. 本轮问题

R2-16 已能从完整 rootfs 恢复请求、参数、功能开关、静态调用状态、响应契约和 Native
binding，但这些事实仍分散在 Catalog 的不同集合中。产品 UI 如果自行按名称拼接，容易把
AC18 handler 迁移到 AC9，或把旧 obligation 与后到达的深层证据同时展示为互相矛盾的状态。

本轮冻结一个纯函数边界：

```text
project_communication_architecture_graph(Catalog, Policy)
  -> CommunicationArchitectureGraph
```

投影不扫描 rootfs、不调用模型、不运行固件、不产生新的漏洞或 owner 事实。所有语义节点和边
必须回指 Catalog candidate、parameter、association、EvidenceAtom、coverage 或 obligation。

## 2. 实现结果

- 新增 `firmatlas.mapping.communication-architecture-graph/v1alpha1`；
- 覆盖接口、参数、调用状态、功能开关、路由、handler、跨进程关系、ubus 主体/ACL、响应契约、
  nested dispatch、保护范围、服务装配、literal xref、feature pivot、参数线索、关联、覆盖和义务；
- 内建 `interface_structure`、`communication_components`、`parameter_state`、`completeness` 四个
  UI view preset，合同测试强制全部节点/边类别至少属于一个视图；
- 支持精确 canonical identity 焦点、语义 hop、节点/边预算；artifact 只作为归属叶子加入，
  不借共享制品把焦点扩展到整个固件；预算截断保持 partial 且不产生 dangling edge；
- `analyze-root` 新增 `--graph-output`、可重复 `--graph-focus` 和图预算参数；运行与图输出路径冲突、
  无 graph output 却传 focus、非法预算都会在写入前失败；
- 默认 Profile/Registry 继续冻结为 `auto-v13`，图投影不是 `auto-v14` 分析能力。

## 3. 迭代与失败记录

1. 首个图合同先覆盖 request→parameter→invocation，随后逐类加入 route/handler、Native relation、
   ubus 和 completeness overlay；每次扩展都运行焦点测试。
2. 初版把 `NATIVE_ROUTE_BINDING.target_ref` 当作唯一上游。真实 AC18 registrar inventory 的
   target 是 `native-registrar:*`，因此图中存在 route/handler，却无法从 frontend request 到达。
3. 修正没有改写原生 proof target 或冻结 Catalog。纯图投影只对 `native-registrar:*` binding
   使用大小写敏感的 endpoint 最后一段与 route token 精确相等规则，边依据标为
   `projection.exact_endpoint_operation`；图同时保留 request→binding 和 registrar→binding 两条
   可审计边，association-target binding 继续使用 Catalog 已有显式引用。
4. 第二次真实回放恢复了三条 AC18 owner，但 `expandDlnaFile` 仍带旧 correlation obligation。
   根因是 registrar 全量枚举晚于浅层 Scheduler 固定点。把关闭状态写回 Catalog 会破坏冻结的
   R2-16/`auto-v13` 身份，因此最终由纯图投影保留原 obligation 节点，并用 `SUPPORTED` route
   binding 的精确 request refs 产生 `satisfies_obligation` 边；AC9 没有这种绑定，所以义务不变。
5. CLI 评审还发现非法图参数可能在 run JSON 写出后才失败；计算与校验已移到任何输出写入之前，
   并以测试固定“不产生半份运行结果”。

这段时间线刻意保留“先出现矛盾、后修复状态”的过程，没有把早期阶段倒写成一次成功。

## 4. AC9 主样本中间输出

机器可读报告：
[`r2-17-vendor-tenda-ac9-ac18-dlna-communication-graph.json`](../samples/r2-17-vendor-tenda-ac9-ac18-dlna-communication-graph.json)

AC9 焦点图为 69 个节点、121 条边，Catalog 与图投影均为 `completed`：

| 操作 | 静态调用状态 | 参数 | 功能门 | route/handler | 开放义务 |
|---|---|---|---|---|---|
| `GetDlnaCfg` | `top_level_declaration` | 无显式请求参数 | disabled | 0 / 0 | `registers_route` |
| `SetDlnaCfg` | `top_level_declaration` | `deviceName, dlnaEn, scanList` | disabled | 0 / 0 | `registers_route` |
| `expandDlnaFile` | `active_call_path` | `filePath, folderGrade` | disabled | 0 / 0 | `registers_route` |
| `refreshDLNA` | `declared_but_unreached` | `action` | disabled | 0 / 0 | `registers_route` |

这说明“接口与参数测到”不等于“执行 owner 已定位”。AC9 图仍显示响应 fixture、相邻
`GetUSBStatus`/feature pivot 等线索，但不会把这些相邻事实画成四条 DLNA route binding。

## 5. AC18 正向对照

AC18 焦点图为 92 个节点、183 条边；图投影 `completed`，源 Catalog 因其他覆盖项为 `partial`：

| 操作 | route | handler | obligation |
|---|---|---|---|
| `GetDlnaCfg` | `GetDlnaCfg` | `bin/httpd@0x000b0e70` | closed |
| `SetDlnaCfg` | `SetDlnaCfg` | `bin/httpd@0x000b1fdc` | closed |
| `expandDlnaFile` | `expandDlnaFile` | `bin/httpd@0x000b1984` | closed |
| `refreshDLNA` | 无 | 无 | open |

同一个投影规则同时保留 AC9 的 0 owner 和 AC18 的 3 owner，证明图层没有按家族名称补全事实。
AC18 的 Catalog partial 也被原样保留，不能因焦点子图完整就宣称整固件 completed。

## 6. 验证门

- 图投影/CLI 合同：16 passed；mapping 全量回归：399 passed；
- R2-16 冻结回放 SHA：`3b02d663706b1c7ea44d96ae0518371c34b146b73664bf3f406bcdfdba7b41f2`，
  与已提交基线逐字节一致；
- R2-17 两个独立进程输出 SHA 均为
  `928dcd99a53952aaaa7abb49e005f95f58399fdecb6b8e4fa06a4033499bd1cd`，逐字节一致；
- Console：9 files / 19 tests passed；TypeScript check 与 Vite production build passed；
- 提交前继续执行 `git diff --check`、JSON/py_compile 和敏感信息扫描；
- MiniMax 未接入本轮确定性事实层；用户给出的 key 未写入代码、文档、报告或提交。

## 7. 下一轮交接

1. 持久化 AnalyzeRun 与图 JSON，提供按 graph id、preset、kind、focus、evidence id 查询的 HTTP API；
2. Console 使用同一 graph schema 实现图谱/表格双视图、证据抽屉、coverage 与 obligation overlay；
3. 用 DAP-3520 HNAP、X5000R shared-CGI/nested dispatch 和 OpenWrt ubus 回归全部 view preset；
4. 历史 expectation 只作为独立 comparison overlay，不写入固件事实图；
5. MiniMax 后续仅用于解释、线索排序和报告辅助，输出必须引用稳定 graph/candidate/evidence id。
