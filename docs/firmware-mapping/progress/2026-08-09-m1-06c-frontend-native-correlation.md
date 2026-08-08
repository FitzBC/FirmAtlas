# M1-06C：Frontend / Native Candidate Correlation

> 工作项：M1-06C  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地实现、真实样本回放、GitHub；按用户当前测绘范围不部署 SSH

## 1. Interface 与边界

```text
correlate_frontend_native(frontend_results, native_results, policy)
  -> FrontendNativeCorrelationResult
```

结果 schema 为 `firmatlas.mapping.correlation-result/v1alpha1`，规则为 `frontend-native-exact/v1`。Module 隐藏输入去重、稳定排序、预算、覆盖传播、身份派生和义务生成。

只接受两种大小写敏感规则：

1. frontend 为 exact literal 且 Native 为完整 endpoint literal，字符串完全相等；
2. frontend endpoint 最后一个 path component 与 Native route token 完全相等。

无论哪种规则，输出均为 `candidate`，不是 `supported binding`。每个匹配产生 `registers_route` 和 `binds_handler` 义务；未匹配 frontend candidate 产生 `registers_route` 义务，供 script-backend/native-deep/runtime 调度。

## 2. TDD 记录

11 条公开 Interface 测试覆盖：

- exact component candidate 与两级义务；
- symbol 名称相似不产生 handler binding；
- 上游 partial coverage 向下传播；
- association budget 精确截断；
- HNAP 共享 endpoint 的 operation candidate 身份不合并；
- 重复输入不重复关联；
- literal prefix 不冒充 exact endpoint；
- 输入顺序变化不改变完整输出；
- 缺失 Producer 输入不是空成功；
- duplicate 不会虚假消耗 association budget；
- AC9 两份 frontend + 两份 Native 制品端到端回放。

实现过程中修复了三个设计缺口：

1. 未匹配项最初只有列表、没有可调度义务；
2. 重复上游结果最初会产生重复 association；
3. 输入顺序最初会改变结果顺序和 budget prefix。

## 3. AC9 中间结果

机器可读摘要见 [M1-06C Correlation JSON](../samples/m1-06c-frontend-native-correlation-summary.json)。

| 项目 | 数量 |
| --- | ---: |
| Frontend candidates | 7 |
| Native hints (`httpd` + `dhttpd`) | 371 |
| Candidate associations | 7 |
| `registers_route` obligations | 7 |
| `binds_handler` obligations | 7 |
| Unmatched frontend | 0 |
| `dhttpd` associations | 0 |
| Name-only symbol bindings | 0 |

所有 7 个 frontend candidate 只关联到 `bin/httpd` 的精确 route token。该结果证明多源线索收敛到同一待分析制品，不证明 route table 或 handler。

## 4. 当前验证证据

| 门禁 | 结果 |
| --- | --- |
| Correlation contract | 11/11 通过 |
| AC9 cross-producer replay | 7 associations / 14 obligations / 0 unmatched |
| Mapping 组合回归 | 91/91 通过 |
| JSON validation | `python3 -m json.tool` 通过 |
| 后端全量 | `make test`，151/151 通过 |
| 前端测试与构建 | Vitest 16/16、TypeScript 与 Vite build 通过 |
| 本地 API/UI smoke | 临时 SQLite 下 health、overview、构建首页均 HTTP 200 |
| Git revision / push | 待本记录提交后回填 |
| SSH deployment | 不适用（用户当前测绘范围） |

## 5. 下一动作

完成全量门禁后进入 M1-06B 文本后端 Producer，并设计 Native Deep Adapter 的最小定向请求：以 association 的 route-token evidence 为 anchor，解析 xref/route table 后才能晋级 `registers_route`，再解析函数指针或调用关系晋级 `binds_handler`。
