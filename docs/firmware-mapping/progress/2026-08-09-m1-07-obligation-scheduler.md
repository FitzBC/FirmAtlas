# M1-07：义务调度与固定点终止

> 工作项：M1-07  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地实现、真实义务回放、GitHub；按用户当前测绘范围不部署 SSH

## 1. Interface 与不变量

```text
run_obligation_scheduler(initial_obligations, analyzers, policy)
  -> ObligationSchedulerResult
```

结果 schema 为 `firmatlas.mapping.scheduler-result/v1alpha1`。调度器接受 Snapshot `UnresolvedObligation`、M1-06C `CorrelationObligation` 或已规范化 `SchedulerObligation`，但不读取源文件、不执行固件、不调用模型，也不自行选择 Binwalk。

核心不变量：

1. 调度身份是 `(obligation_id, analyzer_name)`，每一对最多尝试一次；
2. 队列按 priority 降序、identity 升序稳定选择；
3. Adapter 异常或非法输出被结构化为失败尝试，并允许同一义务尝试下一个候选；
4. 新义务稳定去重，身份相同但内容冲突视为 Analyzer 失败；
5. `fixed_point` 只表示当前策略下没有可执行组合，不表示所有义务已解析；
6. step/obligation 任一预算耗尽均返回 `partial + budget_exhausted`，不返回假完成。

## 2. TDD 记录

13 条公开 Interface 测试覆盖：异构合同规范化、优先级、无 Adapter 固定点、义务派生、异常/unchanged fallback、重复与冲突身份、step/obligation 预算、初始高优先级截断、已解析输入不重跑、输入和 registry 顺序稳定性、JSON 输出及 AC9 摘要约束。

红绿过程中修正了两项重要问题：初始预算最初按 ID 截断而不是按优先级；Analyzer 生成的冲突义务最初会逃逸出调度 Seam，现已作为失败尝试隔离。

## 3. AC9 discover 固定点

机器可读摘要见 [M1-07 Scheduler JSON](../samples/m1-07-obligation-scheduler-summary.json)。M1-06C 的 7 个 candidate association 产生 14 个义务：7 个 `registers_route` 和 7 个 `binds_handler`。

discover 策略不注册高成本 `native-deep/runtime` Adapter，因此结果是：

| 项目 | 数量/状态 |
| --- | ---: |
| 输入义务 | 14 |
| Analyzer attempts | 0 |
| Resolved | 0 |
| Open | 14 |
| Termination | `fixed_point` |
| Diagnostic | `no_eligible_analyzer` |

这是一个合法的“部分知识固定点”：调度覆盖已完成，但 route/handler 知识未完成。14 个开放义务会原样进入后续 Native Deep 或授权 runtime pass。

## 4. 下一动作

完成全量门禁和封版后进入 M1-08：把 Producer 结果、Coverage Ledger、Candidate Association 和 Scheduler 固定点组装为首个无 seed 候选目录。Native Deep 仍作为 Adapter seam，不在 M1-07 中伪实现。

## 5. 当前验证证据

| 门禁 | 结果 |
| --- | --- |
| Scheduler contract | 13/13 通过 |
| Mapping 组合回归 | 116/116 通过 |
| 后端全量 | `make test`，176/176 通过 |
| 前端测试与构建 | Vitest 16/16、TypeScript 与 Vite build 通过 |
| JSON / Python validation | `json.tool`、`py_compile`、`git diff --check` 通过 |
| 本地 API/UI smoke | 临时 SQLite 下 health、overview、构建首页均 HTTP 200 |
| SSH deployment | 不适用（用户当前测绘范围） |
