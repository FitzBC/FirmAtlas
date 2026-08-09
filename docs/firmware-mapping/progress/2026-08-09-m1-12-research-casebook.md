# M1-12：复杂通信架构研究案例合同

> 工作项：M1-12
> 日期：2026-08-09
> 状态：已验证
> 范围：本地实现、真实证据重放、论文素材沉淀与 GitHub；用户明确排除 SSH 部署

## 1. 动机

AC9 同时存在 `/goform` 前端请求和 nginx/FastCGI 支持链，但两者 namespace
不相交。M1-05 正确保留后端 ownership 未决，M1-06A 用 shallow 证据把深分析目标
从 `dhttpd` 收敛到 `httpd`，M1-10B 最终用 ARM PIC call-site 证明 route/handler
binding。若只保存最终结果，会丢失“系统为什么当时拒绝合并”这一最有论文价值的
认识过程。

本轮把该过程提升为版本化、内容寻址、可校验的 `ResearchCase`，并规定以后遇到
多进程分支、共享 dispatcher、误导二进制候选或跨阶段义务时按同一合同沉淀。

## 2. 冻结的 Interface

```text
build_research_case(ResearchCaseInput) -> ResearchCase
validate_research_case_corpus(tuple[ResearchCase, ...]) -> CorpusValidation
```

Interface 隐藏内容摘要、引用完整性、时间顺序和 corpus 准入检查。调用方只需提供
Evidence Reference、Claim、Stage、Obligation、Counterfactual、Paper Use 和
Limitation，不接触内部 identity 算法。

## 3. TDD 记录

首个公开 Interface 测试在实现前以 ImportError 失败，确认 RED。随后纵向实现并
通过以下行为：

1. 相同输入产生稳定 `research-case:<sha256>`；
2. claim 引用未知 evidence 时拒绝；
3. resolved obligation 没有后续 stage 关闭时拒绝；
4. 多证据线且具备反事实、论文用途和局限时 corpus 可准入；
5. 单证据线案例保持 `paper_ready=false`；
6. 真实 AC9 案例同时保存两个 unresolved 中间 claim 与最终 supported binding。

## 4. AC9 首个机器可读案例

案例 ID：`research-case:551b7c3e74e7512f1cb276cb0d6e96c8d9fb211f602b2c7863eb9dcd3e161d3b`

| 项目 | 数量 |
| --- | ---: |
| evidence references | 8 |
| evidence kinds | 5 |
| claims | 5 |
| analysis stages | 4 |
| obligations | 1 resolved |
| counterfactuals | 3 |
| paper uses | 3 |
| limitations | 3 |

证据按原始 Firmware Artifact、source SHA、精确 locator、Producer/version 和
capability 固定。`dhttpd 0/6` 被建模为 Coverage Ledger，而不是伪造一个不存在的
负面字节 Span。

## 5. Ghidra 调研与决策

只读审查了 `../iot_seedintelligentanalysis` 的 headless runner、配置模型、artifact
manifest、binary/interface/fusion 分层输出和旧 keyword/decompile 脚本。吸收临时
project、SHA 绑定、配置驱动、结果 manifest、secret 环境变量及 fail-closed 做法；
不复制自由文本反编译即结论、厂商特化和大段正则表达式重写。

设计决定为 `Ghidra Candidate Worker → Core Evidence Validator`。Worker 只枚举
xref/call-site/P-code 候选，Validator 必须对原始 ELF 重放后才能关闭义务。AC9 已
由确定性 ARM Profile 解决，本轮不无谓运行 Ghidra；遇到跨函数或间接控制流的
真实 open obligation 后再实现 Adapter。

## 6. 验证记录

- Research Case contract 与真实 AC9 回放：12 项通过；
- Python 全量回归：258 项通过；
- Console：9 个测试文件、17 项通过；
- TypeScript 检查和 Vite 生产构建通过，1800 modules；
- 真实 AC9 重算覆盖 7 个 EvidenceAtom 的 ID、source SHA、locator、capability
  与 producer/version；`httpd` 6/6、`dhttpd` 0/6 action component 对照成立；
- 案例生成器与记录 JSON 语义完全一致，案例 ID 稳定，Corpus
  `paper_ready=true`；
- Python 编译、全部 mapping sample JSON、`git diff --check` 通过；
- 35 份主控/测绘 Markdown 的本地链接检查为 0 缺失；
- 本轮没有 API、数据库或 UI 行为变化，本地 API/浏览器检查不适用；
- 通信测绘研究范围按用户明确要求不执行 SSH 部署。

实现与验证记录由本次 Git 历史共同固定。

## 7. 后续动作

1. 每轮按案例准入触发器审查新架构现象；
2. 为 DAP-3520 HNAP/XGI 判断是否形成第二个“混合后端”案例；
3. 获取共享 CGI 真实固件后，记录 endpoint 与 operation selector 二级身份案例；
4. 选择确定性 Profile 无法解决的 Native open obligation，作为 Ghidra Adapter
   首个正负例，而不是复用已解决 AC9 制造工具展示。
