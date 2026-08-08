# M1-10B：ARM PIC 共同调用点 Adapter

> 工作项：M1-10B
> 日期：2026-08-09
> 状态：已验证

## 1. 当前问题

M1-10A 在 Tenda AC9 `bin/httpd` 中正确保留了 0 binding：该制品没有受信命名 route-table，却使用 ARM32 PIC 指令在初始化函数中逐条调用注册器。仅有 route 字符串和导出 handler 名称仍不足以确认绑定。

本轮要求证明 route 指针与 handler 函数引用被装入同一次注册调用的参数寄存器，并验证 PIC 基址、GOT relocation、可执行 handler 与重复 registrar 形态。

## 2. 冻结的 seam

```text
discover_arm_pic_callsite_bindings(source, bytes, anchors, profile, policy)
  -> NativeDeepResult
```

外部反编译 Worker 后续只负责枚举候选；核心 Validator 必须从原始 ELF 字节重新验证候选。实际分析表明 AC9 的 PIC 注册形态可由小型确定性解码器直接验证，因此首个 Adapter 不执行外部反编译器，也不信任工具生成的自由文本。这减少了一个工具信任面；复杂控制流和其他 ISA 再引入第二个 Adapter，而不是让简单 Profile 预先承担 Worker 合同。

Scheduler 与 Discovery Catalog 继续消费 M1-10A 的 `NativeDeepResult`，调用方不需要理解 PIC、GOT 或 relocation。

## 3. 计划证据门限

一条 supported binding 至少要求：

1. route token 的直接字节 span；
2. 初始化函数内可证明为 `.got` 的 PIC base；
3. handler GOT slot 的 `R_ARM_GLOB_DAT` relocation 与动态符号；
4. 同一基本直线片段把 route 放入 `r0`、handler 放入 `r1`；
5. 随后的 ARM `BL` 调用同一 registrar；
6. 同一 registrar 至少出现两个独立 route/handler 对，避免把任意二参数调用误判成注册器；
7. handler 动态符号地址位于 executable ELF section。

缺少任一条件时保持义务开放，并发布明确 Coverage/Diagnostic，不按名称补全。

## 4. AC9 已定位的原始事实

| 事实 | 地址/位置 |
| --- | --- |
| `.got` 基址 | `0x000fd3b8` |
| `SetOnlineDevName` | VMA `0x000dd858`，file offset `0x000d5858` |
| handler GOT slot | `0x000fdbf0`，`R_ARM_GLOB_DAT` |
| handler | `formSetDeviceName @ 0x00060ee8` |
| PIC base 建立 | `0x00042160..0x00042168` |
| route/handler 参数装载 | `0x00042ad4..0x00042aeb` |
| registrar call | `0x00042aec -> 0x00017134` |

这张表是逆向定位记录，不是最终发布结果；只有 Adapter 从原始字节重放并通过负例后才能进入 Catalog。

## 5. 验证结果

合成 ARM32 PIC fixture 已完成首个红—绿纵向切片。真实 AC9 `online_list.js` 的 5 个 frontend candidate 与 `httpd` 的 354 个 shallow hint 形成 5 个 association；Adapter 恢复 5 个 call-site binding，Scheduler 将 10 个 route/handler 义务全部关闭。

| Route | Handler | Callsite | Registrar group |
| --- | --- | --- | --- |
| `getOnlineList` | `formGetOnlineList @ 0x5ecf4` | `0x42788` | `0x17134` / 131 pairs |
| `SetOnlineDevName` | `formSetDeviceName @ 0x60ee8` | `0x42aec` | `0x17134` / 131 pairs |
| `setBlackRule` | `formAddMacfilterRule @ 0xc1bd8` | `0x42b78` | `0x17134` / 131 pairs |
| `delBlackRule` | `formDelMacfilterRule @ 0xc3278` | `0x42b94` | `0x17134` / 131 pairs |
| `getBlackRuleList` | `formGetMacfilterRuleList @ 0xc483c` | `0x42bb0` | `0x17134` / 131 pairs |

机器可读中间结果见 [M1-10B AC9 样例](../samples/m1-10b-ac9-arm-pic-callsite-summary.json)。Catalog 投影已保留 `handler_symbol`、`registrar_address`、`registrar_pair_count`、call-site 与 relocation evidence；Console 候选详情新增“架构与分析属性”。

代码审查发现并修复了三个可信性边界：动态符号必须由 `st_shndx` 与地址共同证明位于可执行 section；handler symbol 元数据必须被 relocation 证据对象绑定；同一 handler 被多个 route 复用时，Catalog 使用 binding-scoped 投影 ID，保留共同的 canonical handler identity，避免身份冲突或错误合并。

发布门禁结果：

- Python 全量回归：217 项通过；
- Native Deep / Catalog 相关回归：39 项通过；
- Console：9 个测试文件、17 项测试通过；
- TypeScript 检查与 Vite 生产构建通过，1800 modules；
- Python 编译、样例 JSON 解析、`git diff --check` 通过；
- 真实 AC9 Catalog：374 candidates、5 associations、0 open obligations；
- 浏览器验收确认 `SetOnlineDevName -> formSetDeviceName @ 0x60ee8`、registrar `0x17134`、131 pairs 以及 PIC/call-site/relocation 原始证据均可见；控制台无 warning/error。

临时浏览器验收目录为 `discovery-catalog:a3e7a97f9000950b30bd5f9781c66bca44ee4189214116f61c1165011773cb72`。通信测绘功能按用户明确范围不执行 SSH 部署；实现修订在 Git 封版后追加。

## 6. 下一步

进入 M1-11 代表性架构出口门：把现有 `/goform`、共享 CGI selector、HNAP/SOAP、脚本后端和 Native-only 基线统一为可重复的 corpus report，明确每类候选、证据能力、覆盖缺口与误绑定对照；复杂控制流、间接调用或其他 ISA 出现后，再以候选 Worker Adapter 扩展 Native Deep Module。
