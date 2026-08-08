# 理论与研究模型

## 1. 研究命题

固件通信测绘不应被建模成“给定一个请求，在文件中搜索相似字符串”，而应被建模成：

> 在缺少样例输入的条件下，从多种不完备、异构且可能冲突的静态与动态证据中，逐步恢复外部交互身份、跨层语义关系和可达结构，并使每个推断都具有可回放的证据路径。

旧工具的价值在于认识到单个接口或参数可以作为线索贯穿前后端。新设计进一步把“线索”从人工输入提升为系统内部的一等研究对象：前端 URL、route registration、参数 getter、SOAPAction、NVRAM key、启动配置和运行时 trace 都可以产生线索，并通过统一证据语义互相扩展。

## 2. 形式化对象

设固件制品的可观测范围为 `A`，证据生产器集合为 `P`。每个生产器只产生可以回到原始制品位置的证据原子：

```text
E0 = ⋃ producer(a),  a ∈ A, producer ∈ P
```

证据原子近似表示为：

```text
e = <subject, predicate, object, source_span,
     producer_version, observation_kind, capability, confidence>
```

其中：

- `observation_kind` 区分直接观察、确定性推导、模型建议和运行时验证；
- `capability` 表示该证据能够支撑哪类主张，而不是一个通用分数；
- `confidence` 只表达同一能力内的不确定性，不能把低能力证据通过累加变成高能力证明。

验证后的推导算子集合记为 `Γ`。系统以追加方式计算证据闭包：

```text
E(n+1) = E(n) ∪ Γ(E(n), policy, budget)
```

在无新证据、预算耗尽或策略停止时发布部分固定点 `E*`。这里的“固定点”不是宣称掌握完整固件语义，而是声明：在给定制品、工具版本、策略和预算下，没有尚可执行的高优先级义务。覆盖账本保存这一限定条件。

## 3. 线索传播的核心性质

### 3.1 多源启动

第一批线索来自固件本身，而不是单个 seed：

- 前端表单、XHR、Fetch、WebSocket 和序列化代码；
- Web 配置、docroot、rewrite、认证区域和 CGI 映射；
- PHP、ASP、Lua、Shell、模板和脚本入口；
- Native route 表、字符串交叉引用、参数 getter 和 handler 注册；
- 进程启动、监听端口、IPC 和持久化键；
- 可选的漏洞文本、PoC、流量和动态 trace。

### 3.2 双向跨层传播

传播不是固定“前端到后端”：

- 前端 URL 可以寻找 route registration；
- 后端 getter 可以反查前端字段、JSON key 或 XML node；
- 持久化键可以连接多个接口操作和跨请求状态；
- handler 可以反查共享 dispatcher 和同族操作；
- 漏洞描述可以与已恢复实体对齐，但不能凭空创建已确认实体。

### 3.3 证据非循环性

派生主张不能成为其自身的独立支持。证据图必须能够展开为一个或多个不可变源码/运行时锚点；聚类标签、模型摘要和相似度结果不具备反向确认源实体的能力。

### 3.4 显式未知与冲突

每个主张使用至少四值状态：`supported`、`refuted`、`unknown`、`conflict`。缺少反例不等于支持，分析失败也不等于未发现。

## 4. 身份模型

暴露接口身份：

```text
I = <transport, endpoint, method, representation,
     selector_schema, authentication_context>
```

共享端点中的接口操作身份：

```text
O = <I, selector_assignment, request_shape, response_shape>
```

参数身份：

```text
P = <O, namespace, canonical_name>
```

这一分解解决三类常见错误：

1. 把 `/HNAP1` 下所有 SOAPAction 合并成一个接口；
2. 把 `/cgi-bin/apply.cgi` 中不同 selector 当成同一个行为；
3. 把不同命名空间的同名参数错误合并。

参数别名不是身份本身。前端字段、协议字段、后端局部变量和 NVRAM key 通过带证据关系连接到参数身份。

## 5. 多视图通信架构指纹

单一路径类别无法支持“这些固件可能属于同一后端通信架构”的强结论。对固件或接口操作定义：

```text
Φ(F) = [φwire, φdispatch, φbinding,
        φparser, φstate, φcode]
```

| 视图 | 表达内容 |
| --- | --- |
| `wire` | 协议、路径语法、method、编码、content type、selector |
| `dispatch` | route table、CGI 分发、SOAPAction、JSON-RPC、脚本入口 |
| `binding` | endpoint/operation 到 handler 的绑定方式 |
| `parser` | 参数 getter、反序列化、别名和约束结构 |
| `state` | auth、session、持久化状态和跨请求工作流 |
| `code` | handler 调用结构、常量、函数和代码谱系特征 |

关联结果不只给出一个总分，而应返回每个视图的相似度、覆盖度和证据。只有 `dispatch + binding/parser` 等高辨识度视图同时对齐时，才可以提出“可能共享后端通信架构”的假设；只匹配路径时应标为结构表面相似。

为避免证据稀少的对象获得虚高分，聚合相似度必须受覆盖度门控。缺失视图保持 unknown，不把它当作 0，也不按剩余视图重新归一化为满分。

## 6. 漏洞机制路径

通信架构图上的漏洞分析目标不是寻找危险函数，而是恢复候选因果路径：

```text
External Input
→ Parse / Deserialize
→ Dispatch
→ Authentication / State Guard
→ Validate / Transform
→ Sensitive State or Dangerous Sink
```

历史漏洞、补丁和公开 PoC 提供先验与外部证据；目标固件中的路径、版本和保护条件决定关联是否成立。系统必须区分：

- 机制相似；
- 代码可能同源；
- 危险函数仍存在；
- 外部路径可达；
- 受影响已经验证。

这些状态不能由一个“相关性分数”替代。

## 7. 预期研究创新

### I1. 无样例冷启动的证据约束线索传播

将接口发现定义为多源、双向、可终止的证据闭包，而不是以人工报文为根的局部字符串扩展。研究问题是它能否在不提供目标请求的情况下提高接口和参数召回，同时保持可解释精度。

### I2. 身份—证据—覆盖联合建模

接口、操作、参数身份与证据能力、覆盖账本同时建模，使“未知”和“未分析”成为可计算结果。研究问题是它能否降低传统工具把分析失败当作无接口造成的假阴性。

### I3. 多视图通信架构指纹

联合 wire、dispatch、binding、parser、state、code 六个视图，并对缺失证据进行覆盖校准。研究问题是它能否优于路径聚类、字符串相似和单一代码相似度完成跨版本/跨厂商检索。

### I4. 历史案例约束的漏洞机制推理

把历史漏洞从文本标签提升为“接口—路径—根因—补丁—证据”案例，用结构检索指导目标固件中的因果路径验证。研究问题是历史案例是否能提升漏洞候选排序和人工复核效率。

### I5. 可复现的渐进式深度分析

低成本全量发现与高成本定向反编译分离，分析预算和未决义务进入结果合同。研究问题是在相同资源预算下，线索调度能否覆盖更多真实入口和深层路径。

## 8. 可证伪假设

| 假设 | 对照 | 主要指标 |
| --- | --- | --- |
| H1 无 seed 线索传播能恢复多数公开接口 | seed-first、全局 regex、前端-only | Interface/Operation P/R/F1 |
| H2 多视图指纹优于路径类别关联 | path-only、string-only、code-only | Recall@K、MRR、误关联率 |
| H3 覆盖账本能减少伪阴性解释 | 无覆盖建模的流水线 | false-absence rate、校准误差 |
| H4 历史机制案例提升漏洞定位 | CPE/版本、CWE、纯 LLM、代码相似 | Recall@K、复核时间、路径正确率 |
| H5 定向深分析提高单位资源收益 | 全量反编译、固定规则调度 | 正确关系/CPU-hour、目标覆盖率 |

## 9. 论文主线建议

第一篇论文应聚焦：

> Evidence-Constrained Seedless Bootstrapping for Cross-Layer Firmware Communication Mapping

核心贡献限定为线索传播、身份模型、覆盖语义和多视图架构恢复。历史漏洞用于证明下游价值，但不要同时承诺自动 PoC。

第二篇可聚焦：

> Historical Vulnerability Mechanism Retrieval for Firmware Variant Analysis

使用第一篇产生的测绘快照，研究跨固件机制检索、可达性验证和定向测试。这样每篇都有单一主张和独立评测闭环。

## 10. 研究边界

- 不把模型生成文本视为固件事实；
- 不把路径相似视为代码同源；
- 不把危险函数存在视为漏洞可达；
- 不把候选输入生成宣称为完全无语料 fuzzing；
- 不在目标案例评估中泄漏其 PoC、补丁后验或等价种子；
- 不把当前产品路线描述成已经获得的论文结果。
