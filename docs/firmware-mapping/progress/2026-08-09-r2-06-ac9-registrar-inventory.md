# R2-06：Tenda AC9 registrar 全量枚举与潜在隐藏接口

> 主样本：Tenda AC9 V15.03.05.19 / `BM-2024-00012`
> 核心问题：前端或历史漏洞没有提供 anchor 时，能否仍完整恢复已验证 registrar？

## 设计变化

R2-05 的 59 条 binding 都由前端/历史 route anchor 触发，不能代表 registrar 全貌。本轮新增公共
`discover_arm_pic_registrar_bindings(source, content, profile)`：它先确认共享 registrar 至少存在
两对独立 route/handler，再枚举所有同时满足 route literal、PIC base、GOT relocation、可执行
动态符号和 registrar callsite 的注册项。普通字符串、单对偶然调用和非执行符号仍不能晋级。

Catalog 新增 `native_registrar` 节点，使无上游 anchor 的 binding 不产生悬空 target；默认
AnalyzeRun 升为 `auto-v4/builtin-v4`，R2-05 固定在 `auto-v3/builtin-v3`。

## TDD 时间线

1. RED：最小 ELF 有两个验证注册，但公共 API 必须依赖外部 anchor；GREEN：无 anchor 枚举两对；
2. RED：route-aware set difference 只认识 selector，不认识 `/goform/SetSambaCfg` action；GREEN：
   版本化 v0.2 策略从声明的 `/goform/` 与 `goform/` scope 提取末段 action；
3. RED：AC9 同时有 `httpd` 与 `dhttpd` registrar，单 inventory API 无法完整比较；GREEN：差集接受
   多个 completed Native inventory，并合并证据而不合并 handler 身份；
4. Catalog coverage gate：Inventory、Frontend 与 Set Difference 任一不完整时，潜在隐藏接口索引
   只能 partial 且不发布 item。

## AC9 整根结果

| 指标 | 结果 |
| --- | ---: |
| `httpd` / `dhttpd` 验证注册 | 183 / 2 |
| registrar inventory | 185 |
| Catalog candidates / parameters / EvidenceAtom | 3995 / 130 / 4821 |
| Native-only / Frontend-only | 110 / 5 |
| 潜在隐藏接口 | 110 |
| open obligations | 61 |

五条 Frontend-only 是 `GetDlnaCfg`、`GetSySLogCfg`、`GetUpnpCfg`、`SetDlnaCfg`、`refreshDLNA`，
它们需要继续检查其他 dispatcher、版本差异或未覆盖后端。110 条 Native-only 中包括：

- `QuickIndex → formQuickIndex`；
- `WizardHandle → fromWizardHandle`；
- `MfgTest`、`telnet`、`ate`、`write`；
- `GetNetErrInfo → bin/dhttpd@0x00034a38`。

“潜在隐藏”只表示在本次 completed 前端 scope 中无引用且 Native 注册已证明。它仍可能属于直接
请求、其他客户端、条件页面、旧代码或死代码，不证明运行时可达、认证状态、后门或漏洞。

## 历史漏洞反馈

13 条历史 route expectation 的后端状态现在为：5 条 expected-handler verified、4 条 route
binding verified、1 条 handler mismatch、3 条 binding not observed。`QuickIndex` 虽属于其他
版本漏洞声明，却在当前制品观察到同名 route/handler；这只能证明架构线索跨版本存在。
`WizardHandle` 的历史 expected handler 与当前动态符号 `fromWizardHandle` 不同，必须保留 mismatch，
不能用近似拼写静默归一化。

完整机器报告见
[R2-06 registrar inventory](../samples/r2-06-vendor-tenda-ac9-registrar-inventory.json)。

## 下一轮

- 对 110 条候选建立认证/服务装配/运行时可达的分层优先级，不按名称直接判定风险；
- 深化五条 Frontend-only，判断是 dispatcher gap、版本残留还是其他执行主体；
- 使用当前 185 条目录辅助回填 46 条尚未语义分析的 AC9 漏洞 expectation；
- 在其他 ARM goform 样本复用无 anchor 枚举，验证 registrar 模式的跨厂商边界。

## 验证记录

- registrar、set difference、hidden index、AnalyzeRun 定向回归 36 项通过；
- `make test`：394 项通过；Console Vitest：9 个文件、19 项通过；TypeScript 与 production build 通过；
- R2-04/R2-05 冻结报告逐字段不变，R2-06 独立重放逐字段相等；
- R2-06 SHA-256：`0f8c11ec3e577dd66217b9586f1ddde0e676e0531f398a42d86f9368d633bfb1`；
- Python/JSON、凭据片段扫描及 `git diff --check` 通过。

本轮属于 firmware mapping research，SSH 部署不适用。
