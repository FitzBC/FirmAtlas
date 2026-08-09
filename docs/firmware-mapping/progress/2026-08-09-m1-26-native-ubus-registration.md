# M1-26：Native rpcd/ubus 注册表与 handler 绑定

## 1. 本轮问题

M1-25 只能把 `usr/lib/rpcd/*.so` 中的 object/method 字符串共现发布为
`native_plugin_candidate`，真实 OpenWrt AC9 因而保留 30 条
`resolve_ubus_registration_table` 义务。字符串共现不足以证明 object、method、handler
属于同一注册表，更不能关闭后端 owner 义务。

本轮也完成了[第一轮全局基线审计](./2026-08-09-round-01-baseline-research.md)。审计确认
当前最大产品断点已从单个 producer 转向统一 AnalyzeRun 编排；本轮先完成工作区中已开始的
Native ubus Validator，避免留下无法重放的半成品。

## 2. 深模块 Interface 与证据门

`discover_native_ubus_registrations(source, content, profile, policy)` 隐藏 ELF32 ARM、
dynamic symbol、REL PLT、ARM literal/PIC、libubus object/type/method ABI 和资源预算。
只有以下链条全部成立才发布确定性注册：

```text
rpc_plugin dynamic symbol
→ executable init
→ verified ubus_add_object PLT call
→ object/type method table agreement
→ bounded object/method strings
→ executable handler pointer
```

`discover_ubus_backend_graph(..., native_registrations=...)` 是第二个 seam。它只接受
`completed` 且 source 位于本次 artifact scope 的 Validator 结果，将匹配的 LuCI logical
operation 晋级为 `verified_native_registration`，公开 handler identity，并关闭精确 operation
的 registration obligation。partial/unsupported、范围外结果和动态 runtime object 均 fail closed。

## 3. 真实样本中间结果

OpenWrt Tenda AC9 19.07.8 的 4 个 sectionless ARM32 rpcd 插件均通过原始字节重放：

| 指标 | M1-25 | M1-26 |
| --- | ---: | ---: |
| Native candidate binding | 30 | 0 |
| Verified Native binding | 0 | 31 |
| Native registration obligation | 30 | 0 |
| Runtime owner obligation | 18 | 17 |
| rpcd principal | 4 | 5 |

31 而不是 30，是因为注册表恢复比先前保守的字符串候选先验多证明了一个前端 operation。
代表链包括 `ubus://file/read → usr/lib/rpcd/file.so@0x00001b4c` 和
`ubus://luci-rpc/getBoardJSON → usr/lib/rpcd/luci.so@0x00002a80`；
`ubus://hostapd.{dynamic}/del_client` 仍只有 ACL grant，owner 未被伪造。

机器报告见 [M1-26 AC9 Native ubus registration](../samples/m1-26-openwrt-ac9-native-ubus-registration.json)。
Console 的后端执行链直接显示 handler identity，并保持操作、principal、handler、ACL 的
既有工业化信息层级。

## 4. 验证记录

- TDD 红灯：图模块最初拒绝 `native_registrations` 参数；
- 专项合同 12/12 通过，包含同路径不同 artifact SHA 的篡改负例；
- 后端全量 `make test`：366/366 通过；
- 前端全量：Vitest 9 files / 19 tests 通过；
- TypeScript 检查与 Vite production build 通过；
- 真实报告连续两次 SHA-256 均为
  `3e48e2712e8798c6749779818a1a425e6702a2569be512be5de5648546aed74b`；
- 文档报告与生成报告 JSON 语义相等；`git diff --check` 通过。

首次直接运行 pytest 因 shell 未设置 `PYTHONPATH=src` 在 collection 阶段未执行；首次前端
命令因 shell 缺少 Node 未执行。两者均使用仓库 Makefile/桌面 bundled runtime 纠正后通过，
没有把环境入口失败误记为断言失败。

## 5. 反思、边界与下一轮

本轮证明在稳定 ABI/Profile 下，小型原始字节 Validator 比引入 Ghidra 更深、更可重放；
Ghidra 仍只用于复杂控制流、未知 ISA 或跨函数 value-flow 的 candidate 枚举。当前结果不证明
运行时可达、认证结果、漏洞存在或可利用性。

下一轮进入 R2：实现统一 `AnalyzeRun` 纵向编排，先支持 extracted root 的自动 source plan、
全 producer 执行、partial failure、阶段事件和不可变 Catalog 输出；随后再接上传/API、历史漏洞
expectation diff、MiniMax Reasoner Adapter 与通信图 read model。用户提供的模型凭据未写入任何
文件、日志或提交，并应在使用前轮换。

本轮属于 `firmatlas.mapping` 研究及对应研究 UI/文档，按用户明确要求 SSH 部署不适用。
