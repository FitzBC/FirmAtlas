# M1-01：版本化 Firmware Mapping Snapshot 合同

> 工作项：M1-01
> 状态：已验证
> 日期：2026-08-08
> 发布状态：Git 修订已推送；SSH 部署按当前用户范围不适用

## 1. 结果与范围

本轮建立 `firmatlas.mapping.snapshot/v1alpha1` 外部合同，使后续 Analyzer 可以向同一个不可变发布边界写入：

- 固件与源清单的 SHA-256 身份；
- 分析策略、预算和 Analyzer 版本；
- 带精确来源和观察类型的 `EvidenceAtom`；
- Interface、Parameter、Handler candidate 等实体及语义关系；
- 覆盖账本、诊断与未决分析义务。

本轮不实现自动文件清单、JS/Native Analyzer、数据库持久化或 UI。Tenda AC9 输出是真实制品的人工证据重放，不是自动 mapper 性能结果。

## 2. 合同不变量

- schema 版本、固件摘要和 inventory 摘要必须可验证；
- Evidence、Entity、Relation 和 Obligation 身份在快照内唯一；
- 所有引用必须指向已发布实体或证据；
- 模型建议不能成为 `supported` 实体或关系的唯一证据；
- `success` 必须完成所有 required coverage；
- partial、failed、unsupported 和 policy skip 必须说明原因；
- failed Snapshot 必须提供诊断，失败不能伪装成空结果。

## 3. TDD 证据

合同在每条不变量上先运行失败测试，再实现最小修复。已建立的红—绿用例包括：

1. 缺失 mapping 模块→最小序列化合同；
2. Entity 悬空 Evidence 引用→引用完整性检查；
3. 纯模型证据支持事实→模型证据门限；
4. required coverage 不完整仍声称 success→发布状态校验；
5. Relation/Obligation 悬空引用→图与义务完整性检查；
6. 非法摘要、重复身份、置信度越界和缺失诊断→基础合同校验；
7. Dictionary 往返与 CLI 校验器→可持久、可重放的对外 seam。

目标测试为 15 条，并已随后端全量 75 条回归用例一起通过。

## 4. 代表样本和中间输出

机器可读样例是 `tests/fixtures/mapping/tenda_ac9_m1_snapshot.json`，重放说明是 [`Tenda AC9：M1 Snapshot 中间过程`](../samples/tenda-ac9-m1-walkthrough.md)。

| 输入 | SHA-256 |
| --- | --- |
| 固件制品 | `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296` |
| 选定三文件 inventory | `84747a51473b826ea2207396f5677dc39786cfc5bd0603f515ae135c923513f0` |
| `static_route.js` | `9bd1ff64ac59189812d29fefe565984c7f58ac68358003e15a1e3fa71a15482b` |
| `online_list.js` | `dd06a5b73cfd64686e5faaf497784190ac5b06801d9f6beb3fb8d90b7bf5cf87` |
| `bin/httpd` | `2fd5c92e15f8c9c0b45047c77af080539237d7b99a9b35fe43dc2a9d5a57702b` |

快照发布 2 个 Interface、3 个 Parameter、2 个未确认 Handler candidate、3 条 `accepts` 关系和 3 个开放义务。由于 Native 绑定尚未证明，它不发布 `binds_to` 事实。

## 5. MiniMax 边界

当前设计和初始实现由 GPT 主导。MiniMax 只作为未来业务运行时 `EvidenceReasoner` Adapter，仅处理已枚举的未决义务，且只能输出 `model_suggested`。设计见 [`大模型与 MiniMax 接入`](../model-reasoning.md)。

密钥只允许通过 `MINIMAX_API_KEY` 运行时环境变量注入，不写入代码、fixture、日志、cache 或 Snapshot。本轮没有调用外部模型。

## 6. 反思与下一步

本轮证明“部分成功+覆盖账本+未决义务”比空列表更能表达真实分析边界。同时确认下一轮必须：

- M1-02 生成完整、安全、可复现的 rootfs inventory；
- M1-03 将来源定位升级为类型化 text/binary/AST locator；
- 后续版本区分 Exposed Interface 与共享 endpoint 内 Operation；
- 增加 Message Shape、binding 轴、父快照、分析时间和 cache fingerprint；
- 对代表语料保持 development / validation / holdout 隔离。

## 7. 发布证据

| 门禁 | 结果 |
| --- | --- |
| Mapping contract tests | 15/15 通过；`make mapping-example` 输出与 fixture 一致 |
| 后端全量测试 | `make test`，75/75 通过 |
| 前端测试与生产构建 | Vitest 16/16 通过；TypeScript 检查与 Vite build 通过 |
| 本地 API/前端烟雾 | 临时 SQLite 下 health 200、FirmAtlas HTML 200、overview 200 |
| Git revision / push | `8aa790e`，已推送 `main` |
| `satc_cloud` release / health / frontend / behavior | 不适用；后续用户将通信测绘相关功能明确调整为暂不需要 SSH 部署 |

曾尝试部署该修订，脚本因远端 linger 未启用而安全拒绝，之后 SSH 连接在密钥交换前关闭。该失败保留为历史证据；本记录最终依据用户后续明确范围将远端标为不适用。
