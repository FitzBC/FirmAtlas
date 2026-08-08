# M1-06A：Native Shallow Evidence Producer

> 工作项：M1-06A  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地实现、真实样本回放、GitHub；按用户当前测绘范围不部署 SSH

## 1. 为什么先做 M1-06A

M1-05 证明 AC9 nginx 只解释 `/cgi-bin/luci/` 与独立 FastCGI 服务，不能解释 M1-04 的 `/goform/*`。rootfs 中仅有一个前后端混合的 `simple_upgrade.asp`，而 `bin/httpd` 中直接存在关键 action 字符串与可读动态符号。因此先增加受控 Native shallow pass，用于选择深分析目标；M1-06B 再覆盖 PHP/ASP/Lua 等文本后端。

## 2. 公开 Interface

```text
discover_native_hints(source_entry, source_bytes, policy)
  -> NativeProducerResult
```

schema 为 `firmatlas.mapping.native-result/v1alpha1`。当前能力：

- 内建读取 ELF32/ELF64、大小端、machine 与 section table，不调用宿主 `strings/nm`；
- 从非字符串表范围恢复 endpoint literal、route token 与 server hint；
- 从 `.dynsym` 及其链接字符串表恢复受控 symbol hint；
- 所有 hint 使用 binary EvidenceAtom 保存精确 offset、excerpt digest 与 artifact digest；
- 重复字符串合并 hint identity，但保留多个 EvidenceAtom；
- source/hint budget、未知格式、损坏 ELF 与源不匹配有不同 Coverage/Diagnostic。

Producer 只支持 `mentions_endpoint`、`declares_symbol`、`server_hint`，不发布 `registers_route` 或 `binds_handler`。

## 3. TDD 与误报修复

8 条公开 Interface 测试覆盖 ELF32、ELF64 大端 AArch64、metadata、字符串与符号分离、重复证据、普通字符串隔离、未知格式、损坏 ELF、预算和 AC9 完整二进制回放。

首版真实回放把 `.dynstr` 中的 `getpid/setsockopt/opendir` 识别为 route token。修复后，普通字符串扫描排除 ELF `SHT_STRTAB` 范围；动态字符串只能通过 `.dynsym` 规则成为 symbol hint。AC9 hint 从 409 降至 354，已检查的链接符号噪声不再进入 route-token 类别。

## 4. AC9 实证

机器可读摘要见 [M1-06A Native Shallow JSON](../samples/m1-06a-native-shallow-summary.json)。

| Artifact | SHA-256 | bytes | hints | evidence | selected action components |
| --- | --- | ---: | ---: | ---: | ---: |
| `bin/httpd` | `2fd5c9…702b` | 982,880 | 354 | 357 | 6/6 |
| `bin/dhttpd` | `df31d8…79b` | 212,948 | 17 | 18 | 0/6 |

`httpd` 精确包含 `GetStaticRouteCfg`、`SetStaticRouteCfg`、`SetOnlineDevName`、`getOnlineList`、`setBlackRule`、`delBlackRule`，并包含独立符号 `formGetRouteStatic`、`fromSetRouteStatic`、`formSetDeviceName`。

正确解释是：

- `httpd` 是 `/goform/*` 深分析的高优先级候选制品；
- 6 个前端 action component 获得第二来源的 exact string corroboration；
- symbol 名称仍是独立 hint，不能按相似名字写成 handler binding；
- `dhttpd` 未命中不等于运行时不参与，只降低当前优先级。

## 5. 当前验证证据

| 门禁 | 结果 |
| --- | --- |
| Native Shallow contract | 8/8 通过 |
| AC9 `httpd` Evidence replay | 357/357 通过 |
| Mapping 组合回归 | 80/80 通过 |
| JSON summary | `python3 -m json.tool` 通过 |
| 后端全量 | `make test`，140/140 通过 |
| 前端测试与构建 | Vitest 16/16、TypeScript 与 Vite build 通过 |
| 本地 API/UI smoke | 临时 SQLite 下 health、overview、构建首页均 HTTP 200 |
| 实现修订 | `d05119a` |
| GitHub push | 随本里程碑关闭提交一并验证 |
| SSH deployment | 不适用（用户当前测绘范围） |

## 6. 已知边界与下一动作

- 当前 route-token 规则用于 clue recall，不能作为 route truth；
- 不解析静态 symbol table、relocation、literal xref、函数边界或调用图；
- 不执行 Ghidra/反编译；这应由隔离 Native Deep Adapter 定向处理；
- stripped 且无 `.dynsym` 时仍可发布字符串 hint，但 symbol 覆盖明确为空；
- 下一步建立 frontend component 与 Native hint 的候选关联/义务合同，再由 xref/decompile 解析 route→handler→parameter。
