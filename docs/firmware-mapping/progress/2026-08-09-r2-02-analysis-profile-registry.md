# R2-02：版本化 Analysis Profile、Analyzer Registry 与 Tenda AC9 自动深化

## 1. 动机与主样本

R2-01 已将已解包 rootfs 统一编排为 AnalyzeRun，但所有运行只到 Native shallow，Scheduler
即使生成义务也没有 eligible analyzer。R2-02 把**原厂 Tenda AC9**确定为首要典型样本，
用它验证 `/goform + ARM PIC registrar + nginx/FastCGI 分裂架构`；OpenWrt Tenda AC9 只作为
同硬件 LuCI/ubus 控制面对照。DAP-3520 与 X5000R 继续承担跨架构验证。

## 2. 深模块 Interface

`MappingAnalysisRequest` 新增版本化 `MappingAnalysisProfile`，AnalyzeRun 同时记录
`profile_id` 和 `analyzer_registry_id`：

- `base-v1`：冻结 R2-01 的 Frontend、Web configuration、Script backend、Native shallow；
- `auto-v1`：在 base 上启用 ARM PIC callsite、Native ubus registration 和 ubus backend；
- `builtin-v1` Registry：把稳定 analyzer name 解析到 source Adapter，并在 Profile 请求不存在
  的 analyzer 时 fail fast。

CLI 默认为 `--profile auto`，也允许 `--profile base` 重放旧基线。Expanded Profile/Registry
身份进入 run content address；R2-01 base run ID 保持兼容。

## 3. 原厂 Tenda AC9 全根分析

Auto Profile 不接收已知接口 seed。它从 1038 个 Inventory 节点自动选择 418 个输入，先由
Frontend/Native correlation 产生 association 和义务，再按 association 的 Native source
与 route token 自动构造 `NativeRouteAnchor`。ARM PIC applicability gate 要求 ARM32 little-endian
ELF 具有可界定 section table，只有满足前置条件的 `bin/httpd` 进入 Validator。

| 指标 | 结果 |
| --- | ---: |
| Frontend requests | 114 |
| Native shallow hints | 3187 |
| Frontend/native associations | 65 |
| ARM PIC route→handler bindings | 45 |
| Native handler candidates | 45 |
| Scheduler 输入 / 已关闭 / 保留 | 179 / 90 / 89 |
| Catalog candidates / parameters / evidence | 3461 / 130 / 4025 |

代表性确定链包括：

- `SetOnlineDevName → formSetDeviceName → bin/httpd@0x00060ee8`；
- `setBlackRule → formAddMacfilterRule → bin/httpd@0x000c1bd8`；
- `delBlackRule → formDelMacfilterRule → bin/httpd@0x000c3278`；
- `getOnlineList → formGetOnlineList → bin/httpd@0x0005ecf4`；
- `getBlackRuleList → formGetMacfilterRuleList → bin/httpd@0x000c483c`。

完整紧凑报告见
[原厂 Tenda AC9 Auto Profile](../samples/r2-02-vendor-tenda-ac9-auto-profile.json)。

## 4. 样本驱动的两次修正

### 4.1 空 page-model URL

原厂 AC9 的 `parental_control.js`、`status_usb.js`、`system_log.js` 含空字符串
`getUrl/setUrl`。旧 Producer 试图为其捕获零长度 EvidenceSpan，导致整次 AnalyzeRun 异常。
空 URL 实际表示未配置/禁用的操作，不是暴露接口；Producer 现在跳过空值，整根 Frontend
阶段为 completed，也不创造空 identity。

### 4.2 sectionless ARM 不触发 section-based Adapter

OpenWrt AC9 的相关 ARM ELF 没有 section table。ARM PIC Adapter 依赖 section/symbol/relocation
证据，因此 Auto Profile 在 ELF header 层判定其不适用，不再制造 `malformed_elf`。同一批
sectionless rpcd plugin 由专门的 Native ubus ABI Validator 处理：4 个 plugin、31 条 verified
Native binding、25 条 Lua static binding、0 条 registration-table obligation、17 条 runtime
owner obligation。对照报告见
[OpenWrt Tenda AC9 Auto Profile](../samples/r2-02-tenda-ac9-auto-profile.json)。

## 5. 边界与下一步

- `coverage=completed` 表示声明的 Profile/范围执行完成，不表示 89 条义务均已解决；
- ARM PIC 自动深化目前只接受现有 `arm32-pic-r0-r1-bl/v1` 证据形态；其他 registrar、ISA、
  stripped/sectionless generic binary 仍需不同 Adapter；
- Auto Profile 尚未自动接入 MIPS inline/nested/value-flow、service assembly、request protection；
- 历史漏洞接口/参数 expectation diff、原始固件 extraction、持久化 job 和图谱 UI 仍待接入；
- MiniMax 不参与 Profile 选择和事实晋级，后续只在有界 Evidence Bundle/Obligation seam 使用。

下一轮继续围绕原厂 Tenda AC9 的 89 条剩余义务做类别化：先实现历史漏洞 expectation-vs-catalog
差异报告，区分 artifact mismatch、scope/syntax/dispatcher/parameter gap，再选择下一个通用
Analyzer，而不是为单一路径增加特例。

## 6. 回归验证记录

- 三份 AC9 报告由构建脚本重新生成并逐字段比较，均与版本库文档一致；
- 原厂 Tenda AC9 Auto 报告在 R2-03 参数语法扩展后重放更新，SHA-256：`465462a274c0c47eae7d0ea46a98731b8d4ad9415d4276ba2ce14bb2c885c3b7`；
- OpenWrt Tenda AC9 Auto 对照报告 SHA-256：`16704d301ec64c58b3ff663f4fbc5ea2d872071999193bf6f48fb4676d85fcfc`；
- R2-01 Base 回放报告 SHA-256：`5f128a404a94a137579eddb842cdc71b0d124856f887d05ec97bdab6be578750`；
- 后端：`make test`，373 项通过；
- 前端：Vitest 9 个文件、19 项通过；TypeScript 检查及 Vite production build 通过；
- 前端首次命令因过期的 Node runtime 路径失败，定位为验证环境问题；改用工作区实际 bundled
  runtime 后完整重跑通过；
- `git diff --check` 通过；仓库密钥扫描不保存或回显用户提供的 MiniMax 凭据。

本轮是固件通信测绘研究，SSH 部署按用户要求不适用。
