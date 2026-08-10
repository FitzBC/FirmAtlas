# R2-16：AC9 DLNA 前端静态调用可达性

日期：2026-08-10

状态：completed（本地全量验证通过；mapping 研究例外不做 SSH 部署）

主样本：Tenda AC9 `V15.03.05.19` 现有 benchmark rootfs

阳性对照：Tenda 官方 AC18 `V15.03.05.19(6318)`

## 1. 本轮问题

此前工具能证明 `dlna.js` 声明四条请求，并能证明 AC9 的 UI 功能链被
`CONFIG_DLNA_SERVER=n` 禁用，但“脚本里存在请求”仍混合了顶层初始化、事件活动路径、
仅有函数声明和注释绑定。本轮新增证据优先的前端调用可达性层，回答：请求在哪里声明，
当前有界静态调用图是否能从可信根到达它，以及哪些结论仍必须保持开放。

## 2. 冻结接口与深模块边界

核心接口是：

```python
discover_frontend_invocation_reachability(
    source, content, frontend_result, policy
)
```

模块只消费单一前端资源及已有 Frontend request 结果，输出版本化 invocation、coverage、
diagnostic 和内容寻址 EvidenceAtom。它不读取 Catalog、不调度 Native 深化，也不推断运行时
事件是否触发。`AnalyzeRun` 负责逐资源调用，Catalog 只做稳定投影；默认 Profile/Registry
升级为 `auto-v13/builtin-v13`，`auto-v12` 被显式冻结供 R2-15 重放。

v1 可信根包括顶层直接调用、具名 jQuery/DOM 事件 callback 和
`R.moduleView({initEvent: ...})`；调用边只在精确 executable token span 上建立。函数使用
source token offset 作为内部身份，避免同名函数合并。method call、重名定义、未注册匿名函数、
缺失同源 request span 和预算耗尽均保守降级或标记 partial。

## 3. TDD 迭代记录

每个切片均先写失败测试，再实现最小行为并回归：

1. 注释事件绑定不产生活动根，同时保留注释引用证据；
2. 顶层直接请求归为 `top_level_declaration`；
3. `moduleView initEvent → delegate anonymous callback → getMoreFolder` 固定点传播；
4. Catalog batch 与 AnalyzeRun stage 投影；
5. 禁用 asset graph 的自定义 Profile 不产生编排崩溃；
6. `$.post` 不与本地 `post` 函数误关联；
7. assigned function expression 和具名事件 callback；
8. 未注册匿名函数与重复函数名保持 `unresolved`；
9. 缺失同源 request span 发布 partial diagnostic，不伪装空成功；
10. 活动路径必须引用精确 call-edge EvidenceAtom。

## 4. 真实样本输出

机器报告：
[`r2-16-vendor-tenda-ac9-ac18-dlna-reachability.json`](../samples/r2-16-vendor-tenda-ac9-ac18-dlna-reachability.json)

报告 SHA-256：`3b02d663706b1c7ea44d96ae0518371c34b146b73664bf3f406bcdfdba7b41f2`

两份样本的 reachability stage 均为 completed，输入 130 个 Frontend 结果，输出 134 个
invocation；状态分布相同：77 `top_level_declaration`、9 `active_call_path`、32
`declared_but_unreached`、16 `unresolved`。

| 操作 | AC9/AC18 静态分类 | 路径或注释 | AC9 Native | AC18 Native |
|---|---|---|---:|---:|
| `GetDlnaCfg` | 顶层声明 | page-load 声明 | 0 | 1 |
| `SetDlnaCfg` | 顶层声明 | page-load 声明 | 0 | 1 |
| `expandDlnaFile` | 活动路径 | `initEvent → getMoreFolder` | 0 | 1 |
| `refreshDLNA` | 已声明但未达 | 1 条注释绑定 | 0 | 0 |

AC9 整体 Catalog 为 completed；AC18 整体 Catalog 仍受其他 producer coverage 影响为 partial，
但本轮 reachability stage 自身 completed。不能用局部 completed 覆盖整体 coverage。

## 5. 历史漏洞线索边界

`CVE-2024-10661 / SetDlnaCfg / scanList` 与
`CVE-2022-38325 / expandDlnaFile / filePath` 在两份前端资产中均被当前 producer 观察到；
AC18 还存在对应 Native owner，AC9 没有。它们只用于家族/版本调查排序，不构成 AC9 的
运行时可达、受影响或可利用性声明。

## 6. 反思与下一轮

- 本轮修复了报告参数投影使用 Catalog `owner_ref` 的字段错误；真实双样本重放覆盖该路径。
- 一次失败来自把 AC18 下载/解包工作目录误传为 rootfs，已改用精确 squashfs-root；这再次
  说明 artifact acquisition 与 rootfs AnalyzeRun 应保持独立、显式的输入契约。
- v1 仍缺跨资源调用边、动态 property dispatch、页面加载资格与运行时事件观测；这些必须
  继续作为 coverage/obligation，而不能把 `declared_but_unreached` 写成死代码。
- 下一轮优先把四态及证据路径投影到通信图谱 UI，并为跨资源 module wiring 设计 v2 producer。

## 7. 交接与复现

```bash
PYTHONPATH=src python scripts/build_vendor_tenda_ac9_ac18_dlna_reachability_report.py \
  --ac18-root /path/to/official-ac18-15.03.05.19/squashfs-root \
  --output docs/firmware-mapping/samples/r2-16-vendor-tenda-ac9-ac18-dlna-reachability.json

PYTHONPATH=src pytest -q tests/test_mapping_frontend_reachability.py
PYTHONPATH=src pytest -q tests/test_mapping_analysis_run.py
PYTHONPATH=src python scripts/build_mapping_research_cases.py \
  --output docs/firmware-mapping/research-cases.json
```

研究轨道按仓库例外不做 SSH 部署；完成标准是本地全量 mapping 回归、前端测试/生产构建、
确定性报告校验、提交并通过 GitHub SSH 推送。

最终本地验证：mapping `382 passed`；案例库 `14 passed`；Console `19 passed`；TypeScript
检查和 Vite 生产构建通过；R2-16 双生成逐字节一致；R2-15 冻结重放 SHA-256 仍为
`59d3eb937d8754e0cb2c39177d0023470f99a51e00a9c6efe1f06e7851a57fca`。
