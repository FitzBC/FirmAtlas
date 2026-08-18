# R2-32：MiniMax 证据受限分析建议

> 日期：2026-08-18
> 状态：已验证
> 主样本：R2-31 OpenWrt Tenda AC9 浏览器上传 Catalog
> 前序：[R2-31 浏览器上传作业生命周期](./2026-08-18-r2-31-browser-upload-job-lifecycle.md)

## 1. 本轮问题与出口

确定性测绘已经能从 AC9 原始制品发布 Catalog/Graph，但 117 个开放义务仍需要人工挑选下一步。
本轮实现模型辅助的最小纵切，同时冻结边界：模型只建议“下一步分析什么”，不能宣布发现接口、
参数、handler 或关系。

```text
published Catalog
→ bounded/redacted evidence bundle
→ MiniMaxReasonerAdapter
→ target/evidence whitelist validator
→ immutable-attempt ReasoningRun
→ Console proposal cards
```

模型结果不进入 Catalog、Graph 或 EvidenceAtom。后续事实晋级仍需独立确定性或运行时佐证。

## 2. 官方协议核验与认识时间线

实现初稿曾按一般 OpenAI-compatible 习惯发送 `max_tokens` 与 `response_format`。查阅 MiniMax 当前
官方 OpenAPI 后，测试先改为要求 `max_completion_tokens`、`stream=false` 且禁止
`response_format`，旧实现按预期失败；Adapter 随后纠正并转绿。这一过程保留在记录中，避免把
协议修正改写成从未发生过的成功。

当前边界：

- endpoint 为 `POST https://api.minimaxi.com/v1/chat/completions`，Bearer 鉴权；
- 同时检查 HTTP 状态和响应体 `base_resp.status_code`，只对明确瞬态错误有界重试；
- `finish_reason` 必须为 `stop`，本地只接受无前后附加文本的 JSON object；
- 官方没有为当前流程提供可依赖的零保留/不训练保证，只发送最小脱敏证据；
- API Key 只从命名环境变量读取，不进入 Adapter identity、SQLite、日志、HTTP 响应或本文。

详细来源见[MiniMax 原始来源研究](../research/2026-08-18-minimax-mapping-reasoning-primary-sources.md)。

## 3. 深模块与审计不变量

`MappingReasoningService` 是唯一编排 Interface。它从 Catalog 选择最多 20 个优先义务、24 个相关
候选和 48 个相关 EvidenceAtom，过滤候选属性并脱敏凭据、Bearer、PEM、MAC、IPv4 和长 opaque
token。模型输出必须满足：target 在请求白名单；至少引用一个既有 evidence；引用集合完全属于
白名单；kind、文本长度、confidence 和 required corroboration 均合法。

每次运行持久化 provider model/request/trace、token usage、拒绝数量、稳定错误码和诊断。成功、
partial、queued、running 的重复提交去重；failed 可以创建递增 attempt，新运行 ID 包含 attempt，
旧失败记录保留。服务重启时残留 queued/running 转为 `reasoning.interrupted`。

API：

- `GET /api/mappings/catalogs/{catalog_id}/reasoning`：能力与最新运行；
- `POST /api/mappings/catalogs/{catalog_id}/reasoning`：提交或复用运行，返回 `202`；
- 未配置模型时返回 enabled=false / `503`，不影响确定性 Catalog/Graph。

CLI 只有显式 `--mapping-reasoning-model` 时才启用；Key 通过
`--mapping-reasoning-api-key-env` 指定的环境变量读取，模型无默认值。

## 4. AC9 中间过程输出

对 R2-31 AC9 Catalog 实际构建的输入包为 24 candidates、20 obligations、48 EvidenceAtoms，序列化
48,308 字符，未包含凭据。离线合同样例选择
`ubus://luci/getSwconfigFeatures`，建议进一步追踪 rpcd 插件注册/ACL owner，并明确要求 Native
注册表或脚本注册证据；虚构 target/evidence 的对抗样例会被 Validator 拒绝。

样例见 [R2-32 AC9 reasoning proposal](../samples/r2-32-openwrt-ac9-reasoning-proposal.json)。它是离线
合同 fixture，不是一次真实供应商调用。用户曾提供的 Key 未用于本轮调用，也未保存或回显；正式
启用前应轮换。

## 5. TDD 与验证记录

已完成的定向验证：

- MiniMax 当前请求合同、Key 掩码、JSON 严格解析；
- 429 有界重试以及错误响应/Key 不回显；
- 虚构 target/evidence 拒绝、有效 proposal 接受、源 Catalog 不变；
- credential canary 在进入 Adapter 前剔除；
- 失败 attempt 可重试且不覆盖第一次记录；
- Reasoning API enabled/disabled、提交和读取合同；
- Console proposal 展示和“模型建议不是已验证事实”信任边界。

最终结果：

- 后端 reasoning/API 定向测试：19/19 通过；
- Python 全量：551/551 通过，`1255.95s`；
- Console：9 个测试文件、28/28 通过；两套 TypeScript 配置检查通过；
- Vite production build 通过；最终产物为 1,801 modules，JS gzip 113.97 kB；
- `compileall`、全部样例 JSON 解析、历史报告源码 SHA 合同和 `git diff --check` 通过；
- `/api/health` 为 `status=ok`；reasoning GET 返回 `enabled=false, latest=null`；
- 最终代码真实页面显示 AC9 `partial` Catalog、模型信任边界、禁用按钮和不影响确定性结果的说明；
- 从上传页跳入图谱后显示 1,665 nodes、2,273 edges、74/74 精确接口焦点；
- 浏览器 warning/error 日志为 0，本地服务保持 `127.0.0.1:18789` 开启。

## 6. 边界、反思与下一步

本轮没有为了结构化输出而依赖官方未声明的 `response_format`，也没有把模型文本包装成
EvidenceAtom。即使模型引用了真实 evidence，它仍只说明建议有上下文依据，不等于建议本身已被
证实。供应商失败、输出截断、注入文本、白名单越界都只产生独立诊断，不破坏确定性结果。

下一轮回到代表性 corpus gate，优先补 script-backend coverage 与 native-only acquisition；模型
评测则应建立固定离线 fixture，量化 citation precision、hallucination、schema valid、成本和 outage
行为，在达标前保持默认关闭。

## 7. 发布与交接

- SSH 部署：不适用；用户明确排除通信测绘研究的 SSH 远程部署。
- Git revision：本文所在 `feat(mapping): add evidence-constrained reasoning` 提交；以 `git log -1` 为准。
- 服务：最终验收后保持 `127.0.0.1:18789` 开启。
- 后续会话入口：先读本文、[模型设计](../model-reasoning.md)、[主控文档](../README.md)和
  `CONTEXT.md`，再核对 Git revision、服务状态与 corpus gate。
