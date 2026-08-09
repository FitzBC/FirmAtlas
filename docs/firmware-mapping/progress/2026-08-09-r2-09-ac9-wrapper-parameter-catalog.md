# R2-09 — AC9 前端包装器恢复与参数线索 Catalog

## 结果

本轮把 R2-08 的两个已知漏检作为 RED 契约完成修复，并把参数线索作为正式 producer 接入默认 `auto-v6` AnalyzeRun 与 Discovery Catalog。`auto-v5/builtin-v5` 被显式冻结，R2-07 的 handler-first 基线不会被新默认配置偷偷改名。

AC9 完整重放为 `completed`：前端恢复 119 个请求候选和 135 个参数；参数线索阶段扫描 451 个非 Web 客户端制品，发布 135 个逐参数 assessment；集合差异恢复 `completed`；潜在隐藏接口从 110 降到 107。

机器可读报告：[r2-09-vendor-tenda-ac9-parameter-clue-catalog.json](../samples/r2-09-vendor-tenda-ac9-parameter-clue-catalog.json)。

## RED → GREEN 时间线

1. **RED 1**：公共 `discover_frontend_requests` 对 `$.post("/goform/refreshDLNA", "action=1", ...)` 只返回请求，不返回参数。
2. **GREEN 1**：恢复 form-urlencoded 字面量中的参数名、字面值、命名空间与精确证据；AC9 得到 `refreshDLNA|action=1`。
3. **RED 2**：同一公共接口无法识别 `$.GetSetData.setData("goform/expandDlnaFile?" + Math.random(), subData, ...)`。
4. **GREEN 2**：将 URL 保守表示为 `literal_prefix`，恢复 `folderGrade/filePath`，不伪造动态随机后缀。
5. **RED 3**：`assemble_discovery_catalog` 没有参数线索 producer；阳性与阴性 assessment 无法查询。
6. **GREEN 3**：新增 `parameter_clue` producer 与 `parameter_clue_assessment` candidate，保留目标参数、状态、命中制品和全部证据引用。
7. **二阶回归**：新恢复的 `action=1` 被集合差异误当作 Native 路由 token，泛化匹配导致命中预算耗尽与 partial。
8. **修正并回归**：参数事实继续保留，但没有字母的低熵 selector 不进入路由身份比较；独立契约验证 `1` 不再污染集合差异。

## AC9 中间结果解释

新恢复的 Tenda wrapper 请求包括：

- `goform/expandDlnaFile?`，参数 `folderGrade/filePath`；
- `goform/setUsbUnload`；
- `goform/setNotUpgrade`；
- `goform/setPptpUserList`；
- `goform/setThundercfg`。

前三个先前属于“有 Native 注册、未见前端引用”的候选；恢复真实前端调用后，`setUsbUnload`、`setNotUpgrade`、`setPptpUserList` 从潜在隐藏集合移除。因此 110→107 是覆盖提升，不是简单改变阈值。`expandDlnaFile` 和 `setThundercfg` 仍为 Frontend-only，后端归属义务保持开放。

DLNA 参数外部线索：

| 参数身份 | 状态 | 解释 |
|---|---|---|
| `SetDlnaCfg|deviceName` | 外部线索 | `bin/httpd` 一份代表性精确 span；仍非处理器/状态绑定 |
| `SetDlnaCfg|dlnaEn` | 无外部线索 | 451 个非 Web 制品覆盖完成下的阴性结果 |
| `SetDlnaCfg|scanList` | 无外部线索 | 同上 |
| `expandDlnaFile|folderGrade` | 无外部线索 | 参数只由客户端包装器观察到 |
| `expandDlnaFile|filePath` | 无外部线索 | 参数只由客户端包装器观察到 |
| `refreshDLNA|action` | 高频弱线索 | `action` 在大量 BusyBox/ELF 制品共现，不能用于 DLNA 归属 |

线索索引采用“每参数、每制品一个最小代表 span”，既保留制品级分布，又避免高频名称重复占满证据账本。Web 客户端目录整体排除，防止模拟响应和 CSS 被误称为后端线索。

## 历史漏洞对比

R2-09 报告继续嵌入 13 条结构化历史 expectation 与 71 条产品漏洞范围审计。此次新增的 wrapper 接口没有被现有 13 条 expectation 覆盖，因此历史命中数不会凭空增加；其价值是证明“历史漏洞列表不是完整性真值”，工具仍必须从固件自身调用和注册结构发现额外接口。报告保留 expectation-vs-catalog 的证据引用与未发现原因，产品同名漏洞不自动升级为当前版本受影响事实。

## 反事实、限制与下一轮

- 若把动态 URL 截断结果当 exact endpoint，会错误声称随机 query 已完整恢复；本轮使用 `literal_prefix`。
- 若扫描所有 Web 资源作为“外部线索”，模拟响应会让 `dlnaEn/scanList` 产生自证循环；本轮按客户端范围整体排除。
- `action` 的 143 个制品级命中说明“字符串越多证据越强”是错误排序，需要下一轮加入信息增益/稀有度与角色权重，但不能删除原始证据。
- `folderGrade/filePath` 的阴性结果提示真实后端可能使用位置编码、结构体字段、别名或动态转换；下一轮应从 `expandDlnaFile` 的 route binding/handler 入手，而非继续全局模糊搜索。
- 参数线索已进入 Catalog，但尚未自动生成针对 handler value-flow 的调度义务；这是下一轮统一深分析链的首要工作。

本轮限于 mapping 研究范围，SSH 部署不适用。

## 验证记录与跨会话交接

- 新增纵切契约：jQuery 字面表单、Tenda wrapper、Catalog 阳性/阴性 assessment、低熵 selector 隔离，全部通过。
- Mapping 全量回归：339/339 通过。
- Console：Vitest 19/19 通过；TypeScript check 与 Vite production build 通过。首次因当前 shell 找不到 `node` 未启动测试，切换工作区内置 Node 后通过，属于环境诊断而非测试失败。
- AC9 报告连续两次独立分析与重建得到相同 SHA-256：`c88ef541aff4262b0372554345050530ad53f905501bc38308446d6587b6280f`。
- 全量回归曾因全局提升 Frontend producer 版本导致旧 Profile 的证据 ID 改写；没有更新旧 golden 掩盖问题，而是以 `auto-v6` 功能门隔离新增语法，旧 Profile 精确重放测试恢复通过。

下一轮从 `expandDlnaFile` 开放归属义务开始：以 route token 定位 Native 注册/handler，再将 `folderGrade/filePath` 作为 handler 内 value-flow 的有界分析目标；同时为高频参数线索加入可解释的信息增益排序。所有功能必须继续通过通用 `analyze-root` 独立运行，不得依赖 AC9 专用 seed。
