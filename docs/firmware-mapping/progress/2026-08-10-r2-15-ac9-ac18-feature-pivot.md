# R2-15 — AC9 主样本的功能 Pivot 与 AC18 家族阳性对照

> 日期：2026-08-10
> 范围：`firmatlas.mapping`、mapping 脚本/测试、`docs/firmware-mapping`
> 部署：不适用；依据仓库 `AGENTS.md` 的 Firmware mapping research exception

## 1. 本轮问题与边界

R2-14 已证明 AC9 的 `CONFIG_DLNA_SERVER=n` 确实控制 DLNA 页面链，但没有回答二进制中
残留的 `dlna.en`、`dlna` 等字面量属于哪个已注册 handler。本轮以 AC9 为主样本，新增一个
通用且有界的 ARM feature pivot：从已证明的前端功能 target 提取功能词，在同一 ELF 中寻找
精确 PIC/GOT 字面量引用，再只与已经验证的 registrar binding 按函数入口相交。

输出严格为 `candidate`。它回答“下一个应调查哪个已注册 handler”，不回答 route alias、运行时
可达或漏洞。官方 AC18 只作为启用 DLNA 的同家族阳性对照，不把地址、handler 或漏洞状态迁移
给 AC9。

## 2. 实现

- 默认 Profile/Registry 升级为 `auto-v12/builtin-v12`；`auto-v11/builtin-v11` 冻结重放。
- 新 producer：`native-arm-feature-pivot@0.1.0`。
- 输入 anchor 仅来自已证明的 UI target 段，过滤短词和通用词；分析受既有 source、anchor、xref
  预算约束。
- 每条候选必须同时引用精确 ARM PIC literal xref 与已验证 route registration/binding；Catalog
  保留 `feature_token`、literal、函数/指令地址、route、handler 和 binding ref。
- AnalyzeRun 在 registrar 完成后自动运行该阶段；tail-merged/anchored binding 会先规范到 Catalog
  最终 binding 身份，避免悬空引用。

TDD 时间线：先冻结公共 API 导入失败，再实现 producer；再冻结 Catalog binding ref 失败并将
跨 batch 验证延迟到全部 batch 组装后；最后冻结 AnalyzeRun 缺阶段的失败，完成 auto-v12 编排。
真实 AC9 测试随后固定阶段 `completed` 和 21 条总 pivot。

## 3. AC9 主样本结果

制品 SHA-256：`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`。

| 指标 | R2-15 |
|---|---:|
| Catalog candidates | 4,393 |
| Evidence atoms | 12,221 |
| Open obligations | 64 |
| Feature pivots（全部功能） | 21 |
| DLNA pivots | 3 |
| DLNA 配置 route bindings | 0 |

三条 DLNA pivot 全部来自 `bin/httpd` 的 `formGetUSBStatus@0xa62d0`：一条 `dlna.en`、两条
`dlna`，route 均为 `GetUSBStatus`。这把 R2-13 的手工深化固化为自动功能，但没有把共享状态
访问重命名为 `GetDlnaCfg`、`SetDlnaCfg` 或 `expandDlnaFile`。

同一 AC9 内的 Samba 与 Printer 是阳性控制：启用功能词能够命中各自专用配置 handler；因此
DLNA 只落到 USB 状态 handler 不是“producer 对所有功能都只会找到状态页”的退化结果。

## 4. 官方 AC18 阳性对照

研究技能从 Tenda 官方发布页/CDN取得并哈希 AC18 `V15.03.05.19(6318)`：ZIP SHA-256
`359d2feac6a7d28bd45a11e60a7062945152f516978deb7d54daea84d9211410`。独立 auto-v12
分析结果为 1,942 candidates、5,409 evidence、35 条总 pivot，其中 17 条与 DLNA 相关。

| route | handler | 地址 |
|---|---|---:|
| `GetDlnaCfg` | `getDLNAserverCfg` | `0xb0e70` |
| `SetDlnaCfg` | `formDLNAserver` | `0xb1fdc` |
| `expandDlnaFile` | `formExpandDlnaFile` | `0xb1984` |

AC9/AC18 的 `dlna.js` 仅规范化 cache-buster 后相同，三个 response fixture 则原始字节相同；
与此同时 feature gate 从 `n` 变为 `y`、`minidlna`/配置和三条 binding 从 absent 变为 present。
这支持“共享产品族模板 + build 裁剪”候选解释，但 AC9 是 repacked rootfs，核心 owner 义务仍 open。

`refreshDLNA` 是关键阴性：AC18 启用 build 中也保持 Frontend-only，点击绑定在脚本中被注释；
因此不能因为它与前三条操作位于同一页面就虚构第四条同型 handler。

原始来源、第二个 AC18 版本复核、文件/ELF hash 与精确 Evidence locator 见
[AC9/AC18 DLNA owner 原始来源研究](../research/2026-08-10-ac9-dlna-owner-primary-sources.md)。机器报告见
[R2-15 AC9/AC18 feature pivot](../samples/r2-15-vendor-tenda-ac9-ac18-dlna-feature-pivot.json)，
SHA-256 为 `59d3eb937d8754e0cb2c39177d0023470f99a51e00a9c6efe1f06e7851a57fca`。

## 5. 历史漏洞与研究案例

CVE 中的 `/goform/expandDlnaFile:filePath`、`/goform/SetDlnaCfg:scanList` 只用于选取官方
AC18 版本和核对接口参数；结果不声明 AC9 存在这些漏洞。R2-14 的历史审计报告保持冻结并由
R2-15 记录其 SHA。

研究案例新增第八阶段和 supported 的 family-variant-positive-control claim，同时把 AC9
`obligation:dlna-handler-owner` 保持 open。该时间线保留了“残留前端 → 相邻状态 handler →
禁用 feature → 邻近启用 build”的逐轮证据演进，没有把早期 unresolved 改写成事后成功。

## 6. 验证与下一步

本轮要求并记录：producer/Catalog/AnalyzeRun 单元测试、真实 AC9 回归、官方 AC18 阳性/阴性
对照、报告双次生成字节一致、冻结 R2-14 报告不变、研究案例双次生成一致、全量 mapping 回归、
console 测试与 production build、`py_compile`、JSON 校验、`git diff --check` 和密钥扫描。

最终本地结果：mapping `368 passed`；console `19 passed`，TypeScript check 与 Vite production
build 通过；R2-15 报告双次独立生成字节一致；R2-14 冻结重放 SHA-256 仍为
`b02c346ba6615402f4bb8c9361ee71325fda7941df77238eb3fbfcf410bce9a5`；研究案例双次生成
一致；静态/JSON/diff 检查通过。仓库中只保留 MiniMax base URL 和环境变量说明，未保存用户 key。

下一轮最高信息增益：取得官方 AC9 raw image 做分区级差分；实现保守的前端活动调用边以区分
`refreshDLNA` 这种 declared-but-unreached 操作；再实现独立 `family-variant-diff` producer，明确
输出 family candidate 而不关闭目标样本 owner。
