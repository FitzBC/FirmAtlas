# MiniMax 固件测绘推理接入：第一方 API 契约与数据边界

> 日期：2026-08-18
>
> 资料范围：仅 MiniMax 开放平台官方文档、官方 OpenAPI 描述、官方用户协议与隐私政策；未调用真实 API，未使用、保存或展示任何真实 API Key。
>
> 目标：为 FirmAtlas 后续“证据辅助解释/线索补充”能力冻结一个可验证、可降级且不污染确定性测绘事实的 MiniMax 接入边界。

## 1. 结论先行

1. `https://api.minimaxi.com/v1` 可直接作为 OpenAI SDK 的 `base_url`；当前文本入口应为
   `POST /v1/chat/completions`，使用 `Authorization: Bearer <API_KEY>` 和
   `Content-Type: application/json`。旧的 `POST /v1/text/chatcompletion_v2` 已被官方标记
   `deprecated`，新代码不应依赖它。
2. 当前 Chat Completions 必填 `model` 与 `messages`，支持流式输出、工具调用、
   `max_completion_tokens`、`thinking`、`reasoning_split` 等参数。官方特别要求：多轮工具调用时，
   必须把模型返回的完整 assistant 消息放回历史，以维持交错推理上下文。
3. 当前官方 Chat Completions OpenAPI **没有声明 `response_format`**；当前 Responses API 的
   `text.format.type` 也只声明 `text`。旧接口曾允许 `MiniMax-Text-01` 使用
   `response_format: json_schema`，但旧接口已废弃且该模型不在当前模型列表中。因此 FirmAtlas
   不能把“严格 JSON Schema 输出”当成当前 MiniMax 接口保证。
4. `tools[].function.parameters` 使用 JSON Schema，可以帮助产生结构化 tool arguments；但当前
   OpenAPI 只声明 `tool_choice=auto|none`，并未给出强制指定某个工具或 strict schema conformance
   的保证。所有模型输出仍须在本地解析、JSON Schema 校验、证据引用校验，并在失败时降级为
   “无 LLM 补充”，不能晋级为测绘事实。
5. 官方错误体系同时包含鉴权、余额、限流、超时、内部错误、内容安全、参数与 token 限制。
   只有明确的暂态错误适合有界重试；必须记录响应 Header 的 `trace_id` 以便排障，但日志中不得
   记录 API Key 或完整固件片段。
6. 官方隐私政策明确：调用 API 时会处理本次提交的数据、鉴权信息、Group ID 和 API Key，数据会
   发送到云服务器计算，并可在问题反馈时被调取。用户协议第 5.4 条还允许为提供服务和提升算法
   服务访问、处理客户数据；第 6.3 条说明，经安全加密、去标识化且无法重新识别特定个人后，输入
   及对应输出可能用于服务优化、统计分析、问题排查和安全风控。当前公开资料中没有找到适用于本
   接入的“zero retention”或“输入绝不用于训练”的明确承诺。因此默认只能发送最小化、脱敏、
   可追溯的证据片段，不能上传完整固件、凭据、配置备份、私钥或未经审查的文件系统内容。

## 2. 第一方来源账本

以下链接均属于 MiniMax 官方开放平台，访问并核对日期为 2026-08-18：

| 主题 | 官方来源 | 本文使用内容 |
|---|---|---|
| OpenAI SDK | [OpenAI SDK 接入](https://platform.minimaxi.com/docs/api-reference/text-openai-api) | `base_url`、环境变量、SDK 示例、支持模型、工具调用历史要求、参数限制 |
| 当前 Chat Completions | [Chat Completions API](https://platform.minimaxi.com/docs/api-reference/text-chat-openai) | `/v1/chat/completions`、Bearer 鉴权、请求/响应 OpenAPI、模型枚举 |
| 当前 Responses API | [对话生成](https://platform.minimaxi.com/docs/api-reference/responses-create) | `/v1/responses` 与当前输出格式字段范围 |
| 历史文本接口 | [文本合成（已废弃）](https://platform.minimaxi.com/docs/api-reference/text-post) | 旧 `/v1/text/chatcompletion_v2`、旧 `response_format` 限制 |
| 模型发现 | [获取模型列表](https://platform.minimaxi.com/docs/api-reference/models/openai/list-models) | Bearer 鉴权的 `GET /v1/models` 与返回模型 ID |
| 限流 | [速率限制](https://platform.minimaxi.com/docs/guides/rate-limits) | RPM、TPM、账户共享范围与当前额度 |
| 错误 | [错误码查询](https://platform.minimaxi.com/docs/api-reference/errorcode) | `base_resp.status_code` 语义与 `trace_id` 排障要求 |
| 密钥安全 | [接口相关 FAQ](https://platform.minimaxi.com/docs/faq/about-apis) | API Key 获取方式及禁止浏览器/客户端暴露 |
| 数据使用授权 | [MiniMax 开放平台用户协议](https://platform.minimaxi.com/protocol/user-agreement) | 客户数据访问处理、算法服务提升及去标识化输入/输出用途 |
| 数据处理 | [MiniMax 开放平台隐私政策](https://platform.minimaxi.com/protocol/privacy-policy) | API 提交数据、鉴权数据、云计算、保存与用户权利 |
| 文档索引 | [官方 llms.txt](https://platform.minimaxi.com/docs/llms.txt) | 当前文本接口、模型与政策文档入口 |

本文不把搜索结果摘要、博客、SDK 二次封装说明或社区示例作为事实来源。

## 3. 当前鉴权、地址与最小请求

### 3.1 当前入口

官方 OpenAI SDK 文档给出的配置是：

```text
OPENAI_BASE_URL=https://api.minimaxi.com/v1
OPENAI_API_KEY=<由服务端安全注入的密钥>
```

SDK 的 `client.chat.completions.create(...)` 对应当前官方 OpenAPI 中的：

```http
POST https://api.minimaxi.com/v1/chat/completions
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

密钥必须只存在于 FirmAtlas 后端进程的 secret/environment 注入边界。官方 FAQ 明确要求不要把
API Key 暴露在浏览器或其他客户端代码中；因此 Console 不能接收、保存、代理显示或返回密钥，
后端健康检查也只能返回 `configured: true|false`。

### 3.2 最小非流式请求

```json
{
  "model": "MiniMax-M3",
  "messages": [
    {
      "role": "system",
      "content": "Only propose interpretations grounded in the supplied evidence IDs."
    },
    {
      "role": "user",
      "content": "Analyze the redacted evidence bundle."
    }
  ],
  "max_completion_tokens": 2048,
  "temperature": 0,
  "stream": false
}
```

当前 Chat Completions OpenAPI 要求 `model`、`messages`，并声明：

- `max_completion_tokens` 是当前生成长度字段，`max_tokens` 已弃用；
- `temperature` 范围 `[0, 2]`，默认 1；`top_p` 范围 `[0, 1]`；
- `stream=true` 返回流式 chunk；
- `tools` 当前为 function 工具；
- `MiniMax-M3` 的 `thinking.type` 可设为 `adaptive` 或 `disabled`，省略时默认 adaptive；
- `reasoning_split=true` 只改变 thinking 的返回位置，不会开启或关闭 thinking；
- `n` 只支持 1，`presence_penalty`、`frequency_penalty`、`logit_bias` 等部分 OpenAI 参数会被忽略。

低温度只能降低采样随机性，不构成可复现性或真实性保证。FirmAtlas 必须同时冻结 model、prompt
版本、输入证据摘要和本地输出校验器版本。

### 3.3 响应与工具循环

非流式响应的主要字段为 `id`、`choices[]`、`model`、`usage`、内容安全字段和
`base_resp`。`choices[].finish_reason` 当前声明为 `stop`、`length`、`content_filter` 或
`tool_calls`。实现必须：

1. 先检查 HTTP 层是否成功；
2. 再检查响应体中的 `base_resp.status_code` 是否为成功；
3. 检查 `finish_reason`，拒绝把被截断或过滤的内容作为完整建议；
4. 记录 token usage、模型 ID、请求/响应 ID 与安全标记，但不记录原始敏感 prompt；
5. 多轮 function call 时回传完整 assistant 消息及 `tool_calls`，不能只回传可见文本。

官方错误页没有完整规定各错误码对应的 HTTP status，也没有承诺 OpenAI SDK 会把所有
`base_resp` 错误统一映射成某类异常。因此实现不能只依赖 SDK exception 类型。

## 4. 模型名与运行时发现

截至核对日期，官方 OpenAI SDK/Chat Completions 文档列出：

- `MiniMax-M3`
- `MiniMax-M2.7` / `MiniMax-M2.7-highspeed`
- `MiniMax-M2.5` / `MiniMax-M2.5-highspeed`
- `MiniMax-M2.1` / `MiniMax-M2.1-highspeed`
- `MiniMax-M2`

官方把 `MiniMax-M3` 描述为最新 M 系列模型，适用于 Agent 推理、工具调用、代码和长上下文任务。
但模型名是供应商可演进配置，不应散落在业务代码中。推荐：

```text
FIRMATLAS_MINIMAX_BASE_URL=https://api.minimaxi.com/v1
FIRMATLAS_MINIMAX_MODEL=MiniMax-M3
FIRMATLAS_MINIMAX_API_KEY=<secret injection only>
```

服务启动或管理员验证时可用 Bearer 鉴权调用 `GET /v1/models`，确认配置模型确实可用；缓存模型
列表并设置 TTL，避免每个业务请求额外调用。每份 LLM 建议制品必须记录实际响应中的 `model`，
而不能只记录请求配置值。

## 5. JSON/结构化输出能力：能够使用什么，不能假设什么

| 能力 | 当前第一方证据 | FirmAtlas 结论 |
|---|---|---|
| Chat Completions `response_format` | 当前 `/v1/chat/completions` OpenAPI 的请求 schema 未声明该字段 | 不得发送或依赖 |
| Responses structured output | 当前 `/v1/responses` 只声明 `text.format.type=text` | 不能视为 JSON Schema 输出 |
| 旧 `json_schema` | 已废弃 `/v1/text/chatcompletion_v2` 曾声明只有 `MiniMax-Text-01` 支持 | 仅作为迁移历史，不能成为新实现基础 |
| Function tool arguments | `tools[].function.parameters` 是 JSON Schema | 可用于结构化提议，但仍须本地验证 |
| 强制指定 function | 当前 `tool_choice` 只声明 `auto`、`none` | 不能假设模型必然调用某个工具 |

因此第一版适配器应采用“宽输入、严校验、失败即降级”的协议：

1. Prompt 明确要求只输出一个 JSON object，不接受 Markdown fence；
2. 设置小型、版本化的本地 JSON Schema；
3. 先从完整文本中执行有界 JSON 解码，拒绝多余 trailing content；
4. 校验每个 evidence ID 确实存在于本次输入 bundle；
5. 校验枚举、长度、建议数量、confidence 范围与禁止字段；
6. 至多执行一次使用校验错误摘要的 repair 请求；
7. 仍失败则发布 `llm_enrichment_failed` 诊断，不生成、覆盖或删除任何确定性 claim。

Function tool 可作为后续优化，但在供应商文档没有 strict/forced-tool 保证之前，不能移除上述本地
校验和降级路径。

## 6. 错误与限流语义

### 6.1 错误分类

以下分类基于官方“解决方法”制定；“重试”是 FirmAtlas 的工程策略，不是供应商额外保证：

| `base_resp.status_code` | 官方含义 | 本地处理 |
|---:|---|---|
| `1000` | 未知/系统默认错误 | 有界指数退避重试 |
| `1001` | 请求超时 | 有界指数退避重试 |
| `1002` | 请求频率超限 | 抖动退避；尊重服务端可用的等待信息 |
| `1024`, `1033` | 内部错误、系统/下游服务错误 | 有界指数退避重试 |
| `2045` | 请求频率增长超限 | 降低并发与爬升速率后重试 |
| `2056` | Token Plan 资源限制 | 等下个配额窗口；不做紧密循环 |
| `1004`, `2049` | 未授权、无效 API Key | 立即失败；健康状态仅报配置错误，不输出 Key |
| `1008` | 余额不足 | 立即失败并提示账户处理 |
| `1026`, `1027` | 输入/输出内容涉敏 | 不自动原样重放；生成安全诊断 |
| `1039` | Token 限制 | 缩减证据 bundle 或调整输出上限 |
| `1041` | 连接数限制 | 打开熔断/降低并发并按官方渠道处理 |
| `1042` | 不可见/非法字符比例超限 | 规范化、脱敏后重新校验输入 |
| `2013` | 参数错误 | 编程/契约错误，不重试 |

重试应采用指数退避加 jitter、总 deadline、最大尝试次数和并发 semaphore。每次重试可能形成新的
模型调用和费用，不能无限重试。排障记录保存响应 Header 的 `trace_id`、本地 request ID、错误码、
模型和时间；不得保存 Authorization header。

### 6.2 当前文本限流

官方限流由 RPM（每分钟请求）和 TPM（每分钟输入+输出 token）共同约束，并在主账号与子账号间
共享：

| 模型 | 免费用户 | 充值用户 |
|---|---:|---:|
| `MiniMax-M3` | 20 RPM / 1,000,000 TPM | 200 RPM / 10,000,000 TPM |
| M2.7/M2.5/M2.1/M2 系列 | 20 RPM / 1,000,000 TPM | 500 RPM / 20,000,000 TPM |

这些数值是可变的供应商运营配置，不能硬编码成业务正确性条件。适配器应暴露本地可配置的保守
并发/速率预算，并以实际 `1002`/`2045` 为反馈。官方资料未说明标准化的 rate-limit response
headers 或 `Retry-After` 一定存在；如果响应提供则使用，否则按本地抖动退避执行。

## 7. 数据安全与隐私边界

### 7.1 第一方政策能证明的内容

MiniMax 中国开放平台隐私政策对“调用 API”列明会收集本次提交的处理数据、鉴权信息、Group ID
和 API Key，用于后台计算、生成返回数据，也可在问题反馈中调取。政策还说明交互数据会发送至云
服务器计算；一般只为实现目的所必需的最短时间保留个人信息，之后删除或匿名化，但法律、合同、
安全等情形可以改变保存期限。

用户协议给出了更直接的数据用途边界：第 5.4 条允许 MiniMax 为提供开放平台服务和提升算法服务
访问、复制、使用客户数据；第 6.3 条说明，在经过安全加密、去标识化且无法重新识别特定个人的
前提下，服务收集的输入及对应输出可能用于服务优化、统计分析、问题排查和安全风控。这里的
“去标识化且无法重新识别特定个人”主要是个人识别维度，并不自动消除固件知识产权、未公开漏洞、
商业秘密或设备凭据泄露风险。

政策表述的是个人信息处理框架，并不等价于面向固件二进制/商业机密的专门保密、训练排除或
zero-retention 承诺。本文在当前官方文档中没有找到以下可直接验证的保证：

- API prompt/response 的精确默认保存时长；
- 可供 API 客户选择的 zero-retention 模式；
- API 输入/输出绝不用于模型训练的明确承诺（反而存在上述“提升算法服务/服务优化”授权）；
- 针对该中国 endpoint 的企业 DPA、数据处理地域选择或内容删除 API；
- 固件、漏洞证据或商业机密的专门隔离承诺。

缺少公开承诺不能反向证明数据一定被训练或长期保存，但在工程风险模型中必须按“远程第三方处理”
对待，并在投入真实敏感数据前向 MiniMax 官方确认合同与数据治理条款。

### 7.2 FirmAtlas 必须实施的控制

1. **默认关闭远程推理**：只有管理员显式配置后端密钥并启用 provider 才运行。
2. **最小化输入**：只传递短小、脱敏、编号的文本证据片段与必要元数据；不传完整固件、rootfs、
   配置备份、崩溃转储、私钥、口令、token、证书私钥或用户上传的原始文件。
3. **先本地脱敏**：过滤 credential-like 字符串、个人信息、设备唯一标识和不必要路径；保留内容
   hash、制品内相对位置和 evidence ID，使输出仍可回溯。
4. **密钥只在服务端**：环境变量/secret manager 注入，进程启动时读取；不写入 Git、SQLite、
   AnalyzeRun、HTTP 响应、Console bundle、日志、测试快照或崩溃报告。
5. **日志分层**：默认只记录 prompt schema version、evidence digest、token usage、模型、latency、
   status code、trace ID；调试模式也不记录 Authorization 或未经脱敏内容。
6. **输出隔离**：LLM 输出存为独立、可删除的 proposal artifact；不得原地修改 deterministic
   Candidate、Catalog 或 Graph 边。
7. **预算和熔断**：限制单任务片段数、字符/token、调用次数、并发、超时和总费用；供应商不可用时
   核心固件测绘仍必须完成。
8. **密钥事件处理**：任何曾进入对话、日志、前端或版本库的密钥都按已暴露处理，立即轮换；官方
   FAQ 也明确禁止共享或在浏览器/客户端暴露 API Key。

## 8. 建议冻结的 FirmAtlas provider 契约

MiniMax 的职责应是“对已有证据提出可验证解释”，不是发现或发布结构事实：

```text
deterministic analyzers
  -> redacted EvidenceBundle
  -> MiniMaxReasoningProvider
  -> locally validated ProposalArtifact
  -> human/rule review
  -> optional association/explanation view

MiniMax output ─X─> direct mutation of Candidate/Catalog/Graph facts
```

建议输入 envelope：

```json
{
  "schema_version": "firmatlas.llm-evidence-bundle.v1",
  "prompt_version": "mapping-reasoning.v1",
  "analysis_id": "...",
  "task": "explain_unresolved_binding",
  "evidence": [
    {
      "evidence_id": "ev:...",
      "kind": "redacted_string_context",
      "artifact_path": "bin/httpd",
      "content_sha256": "...",
      "text": "...redacted bounded excerpt..."
    }
  ],
  "allowed_claim_kinds": ["hypothesis", "search_hint", "counterfactual"]
}
```

建议输出 schema 至少包含：

- `proposal_id`、`kind`、`summary`；
- `supporting_evidence_ids[]`，且必须是输入 evidence 的子集；
- `counter_evidence_ids[]`；
- `confidence`（仅是模型自评，不是事实置信度）；
- `next_deterministic_checks[]`；
- `limitations[]`；
- `provider`、实际 `model`、prompt/schema version、input digest、request/response ID、usage；
- `promotion_state="proposal_only"`，且模型无权改变此字段。

Catalog/UI 应把 proposal 与 deterministic/direct、deterministic-derived、historical-reference
证据用不同样式显示。只有后续确定性分析器生成新证据后，新的事实才可按现有证据规则发布。

## 9. 验证计划与上线门槛

### 离线、无密钥测试（CI 默认）

- 请求序列化 golden test：地址、Bearer header 注入边界、必填字段、大小预算；
- 响应解析：正常、stream、`length`、`content_filter`、tool call、空 choices；
- `base_resp` 每类错误的 retry/no-retry 表驱动测试；
- malformed JSON、schema mismatch、未知 evidence ID、超长字段与 prompt injection 回归；
- 日志和持久化快照 secret canary 扫描；
- provider timeout、熔断、无配置、供应商离线时确定性分析不受影响；
- 同一 evidence bundle 的 digest、缓存 key 和 proposal identity 可稳定复现。

### 显式 opt-in 的在线 smoke test

- 只使用仓库内合成、无敏感数据的 evidence bundle；
- 先调用 `GET /v1/models` 验证配置模型；
- 调用一次非流式短响应，验证 auth、usage、响应 ID 与本地 schema 失败降级；
- 不在 CI artifact、终端 transcript 或页面中输出密钥/Authorization；
- 测试后验证后端 API 与 Console 页面只显示 provider 状态和脱敏诊断。

### 正式发送真实证据前仍需向 MiniMax 确认

1. API 输入输出是否用于训练，以及可否合同化排除；
2. prompt/response、日志和备份的精确保存期及删除流程；
3. 数据处理地域、子处理者、DPA 与安全事件通知；
4. 当前 endpoint 是否提供结构化输出/strict function arguments 的未公开保证；
5. HTTP status、`Retry-After`、rate-limit headers 与计费重试的精确语义。

在这些问题未闭合之前，MiniMax 可以用于脱敏证据的可选解释与下一步搜索建议，但不应接收完整固件
或成为固件通信测绘完整性判定的必经依赖。
