# Tenda AC9 parameter-only 漏洞：原始来源核验

> 日期：2026-08-11
> 范围：`CVE-2021-42659`、`CVE-2026-2191`、`CVE-2026-2192`
> 目的：判断现有 `parameter_only` 分类中哪些条目实际上已有接口证据，以及哪些“参数”只是
> 配置键而不是 HTTP 参数。本文只做历史证据建模，不验证漏洞利用或当前固件可达性。

## 1. 结论先行

三条记录不能继续按同一种“只有参数、接口未知”语义处理：

| CVE | HTTP path | method | handler | 历史材料中的数据字段 | 版本结论 |
|---|---|---|---|---|---|
| CVE-2021-42659 | **原始 PoC 直接给出** `/goform/SetVirtualServerCfg` | **POST** | **原始分析明确** `formSetVirtualSer` | **HTTP body 参数** `list` | V3 `15.03.06.42_multi` 一致；V1 原始报告与 CVE 记录冲突 |
| CVE-2026-2191 | **未知** | **未知** | **明确** `formGetDdosDefenceList`；另有独立受影响 sink `formGetFirewallCfg` | **配置键** `security.ddos.map`，不是已证实的 HTTP 参数 | 原始报告只写 `v1 v3`；CVE 记录结构化为 `15.03.06.42_multi` |
| CVE-2026-2192 | 原文只给 route token `GetSysAutoRebbotCfg`；完整 `/goform/...` 只能推断 | **未知** | **明确** `formGetRebootTimer` | **配置键** `sys.schedulereboot.start_time`、`sys.schedulereboot.end_time` | 原始报告只写 `v1 v3`；CVE 记录结构化为 `15.03.06.42_multi` |

因此：

1. `CVE-2021-42659` 应从 `parameter_only` 升级为有完整来源证明的 HTTP interface expectation；
2. 两条 2026 漏洞应建模成“HTTP 配置导入入口（未知）→ 配置存储 → native handler 读取配置键”的
   间接通信链，不能把配置键平铺成 Web 请求参数；
3. `websFormDefine` 的 route token、完整 HTTP path 和 HTTP method 必须是三个不同字段和证据等级；
4. 三份 GitHub 文档是原始研究者披露，不是 Tenda 厂商公告。CVE 引用中的 Tenda 官网只标为
   product reference；本轮没有找到被 CVE 记录引用的厂商安全公告。

## 2. 来源与证据纪律

### 2.1 原始研究者材料（固定到提交）

| 材料 | 固定版本 | 本地复核 SHA-256 | 提交时间 |
|---|---|---|---|
| [CVE-2021-42659 原始报告 `stack4.md`](https://github.com/Lyc-heng/routers/blob/5092242e7154712c1cf74bd00d92654557cfe9a6/routers/stack4.md) | `5092242e7154712c1cf74bd00d92654557cfe9a6` | `e97ab9b25b99869888c6d5365edfd7421002eddbf9a0a9563239c79804bcf5aa` | 2021-10-15T20:23:56+08:00 |
| [CVE-2026-2191 原始报告 `tenda3.md`](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda3.md) | `2568d62c9bf94ef0ffb14da0f0dc97b933da0481` | `f186437edd2954f3337e1fb3975b2705a972a709ac72bf701863aa4a898be25d` | 2026-01-31T14:48:32+08:00 |
| [CVE-2026-2192 原始报告 `tenda4.md`](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda4.md) | `2568d62c9bf94ef0ffb14da0f0dc97b933da0481` | `d60f871484c48293cc85fc28586774092f386ba8905af8a0aae2ddb6d4224c74` | 2026-01-31T14:48:32+08:00 |

提交固定链接用于保证以后能看到本轮实际核验的内容；`main` 分支后续发生修改时，不应静默改变
历史 expectation。

### 2.2 官方登记与厂商版本来源

- [CVE-2021-42659 官方 CVE Record](https://www.cve.org/CVERecord?id=CVE-2021-42659)；
  [CVE Program JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2021/42xxx/CVE-2021-42659.json#L15-L49)。
- [CVE-2026-2191 官方 CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-2191)；
  [CVE Program JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/2xxx/CVE-2026-2191.json#L42-L61)。
- [CVE-2026-2192 官方 CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-2192)；
  [CVE Program JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/2xxx/CVE-2026-2192.json#L42-L61)。
- [Tenda 官方 AC9V3.0 `V15.03.06.42_multi` 发布页](https://www.tenda.com.cn/download/2908)：
  标明 2018-12-14 发布，且只适用于 AC9V3.0、当前版本为 `V15.03.06.X` 的设备。
- [Tenda 官方 AC9V1.0 `V15.03.05.14` 发布页](https://www.tenda.com.cn/download/2650)：
  这是本轮能在官方支持站复核的 V1 页面，但它**不能**证明下面有争议的两个 V1 build。

证据类型严格区分如下：

- **原文事实**：研究报告正文、代码块或官方 CVE/厂商页面直接陈述；
- **PoC 直接可读**：HTTP request 或配置文件样例中的 literal；
- **推断**：由 Tenda/GoAhead 命名惯例、函数名或相邻事实推导，不能发布成 discovered fact；
- **未知**：来源没有提供，不能用命名习惯补齐。

## 3. CVE-2021-42659

### 3.1 可以确认的事实

原始报告的 [基础信息（L4-L18）](https://github.com/Lyc-heng/routers/blob/5092242e7154712c1cf74bd00d92654557cfe9a6/routers/stack4.md#L4-L18)
明确对象是 Tenda AC9 等产品、`bin/httpd` 和虚拟服务器设置功能。

HTTP interface 证据是完整的：

- [PoC request line 与 body（L27-L41）](https://github.com/Lyc-heng/routers/blob/5092242e7154712c1cf74bd00d92654557cfe9a6/routers/stack4.md#L27-L41)
  直接给出 `POST /goform/SetVirtualServerCfg HTTP/1.1`；
- request body 只有一个具名表单字段 `list`。其值由四段逗号分隔内容组成，但来源没有给四段
  子值的字段名，不能把它们发明成四个独立参数；
- Cookie 中的 `password` 是会话/认证材料，不是报告认定的漏洞参数；HTTP headers 也不是
  endpoint 的业务参数；
- [静态调用链与解释（L43-L54）](https://github.com/Lyc-heng/routers/blob/5092242e7154712c1cf74bd00d92654557cfe9a6/routers/stack4.md#L43-L54)
  明确 handler 为 `formSetVirtualSer`，并明确它对应 `/goform/SetVirtualServerCfg`、接收 `list`。

字段判定：

| 字段 | 值 | 判定 |
|---|---|---|
| path | `/goform/SetVirtualServerCfg` | PoC 直接可读 + 正文明确 |
| method | `POST` | PoC 直接可读 |
| handler | `formSetVirtualSer` | 原始静态分析明确 |
| HTTP 参数 | `list` | PoC 直接可读 + 正文明确 |
| 其他具名业务参数 | 无 | PoC 中未出现；不能从 CSV 子段杜撰 |

### 3.2 版本冲突必须保留

- 原始报告 [L4-L10](https://github.com/Lyc-heng/routers/blob/5092242e7154712c1cf74bd00d92654557cfe9a6/routers/stack4.md#L4-L10)
  写 `V1.0 V15.03.05.19(6318)` 与 `V3.0 V15.03.06.42_multi`；
- 官方 CVE 描述写 `V1.0 V15.03.02.19(6318)` 与 `V3.0 V15.03.06.42_multi`，但其 structured
  `affected` 仍是 `vendor/product/version = n/a`；
- Tenda 官方页面能独立确认 AC9V3.0 存在 `V15.03.06.42_multi`，不能消除 V1 的
  `05.19` / `02.19` 冲突；本轮官方站搜索也没有得到可证明任一争议 V1 build 的 AC9 页面。

所以 V3 可记为多来源一致；V1 必须输出 `source_version_conflict`，不得自动规范化，也不能任选
其中一个覆盖另一个。

## 4. CVE-2026-2191

### 4.1 可以确认的事实

原始报告 [L4-L15](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda3.md#L4-L15)
明确：

- 产品为 AC9，firmware version 只写 `v1 v3`，没有 build；
- 主受影响函数为 `formGetDdosDefenceList`；
- `security.ddos.map` 被称为 configuration field，攻击过程是篡改配置文件中的该值；
- [配置样例（L19-L29）](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda3.md#L19-L29)
  也直接显示它是 `key=value` 配置项，不是 HTTP request body。

报告还说明同一配置键影响另一个函数：

- [L32-L35](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda3.md#L32-L35)
  明确给出 `websFormDefine("GetFirewallCfg", ..., formGetFirewallCfg)`；
- [反编译片段 L38-L74](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda3.md#L38-L74)
  直接显示 `formGetFirewallCfg` 读取 `security.ddos.map`，还读取 `firewall.pingwan`；后者没有被
  报告认定为本漏洞字段。

官方 CVE 记录把 affected build 结构化为 `15.03.06.42_multi`，并称该配置键为 argument；
对于通信测绘，原始报告的 configuration field 与 `GetValue(...)` 数据流是更精确的类型证据，
不能因为 CVE 摘要使用 argument 一词就改成 HTTP parameter。

### 4.2 仍然未知的内容

| 字段 | 结论 | 原因 |
|---|---|---|
| 主 handler path | 未知 | 报告没有 `formGetDdosDefenceList` 的注册语句或 HTTP request |
| 主 handler method | 未知 | 没有 HTTP request；函数名中的 `Get` 不能证明 GET |
| 配置上传 path/method/form field | 未知 | 报告只说通过上传恶意配置文件触发，没有给上传接口 |
| `GetFirewallCfg` 完整 path | 推断 | literal 只是 registration token；`/goform/GetFirewallCfg` 是框架惯例推导 |
| `GetFirewallCfg` method | 未知 | `websFormDefine` 本身不编码 GET/POST 限制 |

`GetFirewallCfg → formGetFirewallCfg` 是第二个 sink 的明确 binding，**不能**借给主 sink
`formGetDdosDefenceList`，更不能据此制造 `/goform/GetDdosDefenceList`。

## 5. CVE-2026-2192

### 5.1 可以确认的事实

原始报告直接给出：

- [binding（L10-L15）](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda4.md#L10-L15)：
  route registration token `GetSysAutoRebbotCfg`（保留原文 `Rebbot` 拼写）绑定
  `formGetRebootTimer`；
- vulnerable configuration properties 是 `sys.schedulereboot.start_time` 与
  `sys.schedulereboot.end_time`；
- [配置 PoC（L23-L32）](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda4.md#L23-L32)
  直接给出 `start_time` 配置行；`end_time` 没出现在该短样例中，但由正文与代码共同明确；
- [反编译片段（L35-L69）](https://github.com/glkfc/IoT-Vulnerability/blob/2568d62c9bf94ef0ffb14da0f0dc97b933da0481/Tenda/tenda4.md#L35-L69)
  显示 handler 通过 `GetValue` 读取这两个 key。

该函数还读取 `sys.schedulereboot.enable`、`sys.schedulereboot.max_speed` 与
`sys.schedulereboot.type`，但报告没有把它们认定为这条漏洞的受影响字段。工具可把它们收为
同一 handler 的普通配置依赖，不能扩写历史漏洞参数集合。

官方 CVE 记录把 affected build 结构化为 `15.03.06.42_multi`；原始报告自身只写 `v1 v3`。
Tenda 官方 AC9V3.0 页面独立证明这个 build 存在并适用于 V3，但没有提供漏洞确认。

### 5.2 仍然未知或只能推断的内容

| 字段 | 结论 | 原因 |
|---|---|---|
| route token | `GetSysAutoRebbotCfg`，明确 | 原始 `websFormDefine` literal |
| 完整 HTTP path | `/goform/GetSysAutoRebbotCfg`，仅框架推断 | 原文没有包含斜杠的 path 或 request line |
| HTTP method | 未知 | `websFormDefine` 不足以区分 GET/POST；`Get` 前缀也不是 method 证明 |
| HTTP 参数 | 未知 | 两个已知字段是配置键，不是 request 参数 |
| 配置导入入口 | 未知 | 报告未给出负责写入配置文件的接口、handler 或参数 |

## 6. 对 mapper 的具体改进建议

### 6.1 立即修正历史 coverage 数据

1. 为 `CVE-2021-42659` 创建结构化 interface expectation：
   `POST /goform/SetVirtualServerCfg → formSetVirtualSer → body:list`，证据引用固定 commit 与精确行；
2. 把 `CVE-2026-2191`、`CVE-2026-2192` 从模糊的 `parameter_only` 细分为
   `indirect_configuration_flow` 或 `configuration_key_sink`；
3. `CVE-2026-2192` 可发布 source-verified 的 route-token/handler binding，但 path 状态必须是
   `framework_inferred`、method 必须保持 `unknown`；
4. `CVE-2026-2191` 应保存两个独立 sink：主 sink `formGetDdosDefenceList` 无 route binding，
   secondary sink `GetFirewallCfg → formGetFirewallCfg` 有 token binding；不能合并 owner。

### 6.2 扩展数据模型而不是继续平铺字符串

建议给历史 clue/expectation 增加：

- `field_kind`: `http_parameter | cookie | configuration_key | response_field | unknown`；
- `interface_locator_kind`: `literal_http_path | route_registration_token | framework_derived_path`；
- `transport_method_state`: `source_verified | inferred | unknown`；
- `sink_role`: `primary | secondary_same_field`；
- `version_claims[]`: 每条 claim 独立保存 source、hardware revision、build 与 confidence；
- `conflicts[]`: 如 `V1 15.03.05.19(6318)` 对 `15.03.02.19(6318)`；
- `ingress_state`: `known | unresolved`，避免 native sink 已知时错误宣称端到端链路完整。

历史 overlay 应把“来源事实”和“当前固件发现”作为两层：历史材料可以生成调查义务和图谱虚线，
只有当前制品证据才能生成 discovered node/edge 或关闭义务。

### 6.3 新增配置导入链 producer/obligation

面对用户上传固件时，工具应确定性寻找：

1. 前端中的配置备份/恢复、文件上传表单、XHR URL、multipart field；
2. native registrar 中对应 route 与 handler；
3. 上传 handler 到配置解析/持久化函数的调用链；
4. 配置键写入和读取点，并把它们连接到 `formGetDdosDefenceList`、`formGetFirewallCfg`、
   `formGetRebootTimer`；
5. 如果只找到读取 sink，发布 `unresolved_configuration_ingress`，不要伪造直接 HTTP 参数边。

这会恢复真实通信结构：HTTP 上传的是文件或 blob；漏洞相关 key 经配置存储间接到达读取 handler。

### 6.4 修正语义参数提取器

`CVE-2021-42659` 的自然语言短语中，真正参数是 `list`，不是其后的普通动词 `occurs`。参数抽取应
优先级如下：

1. 解析 HTTP request body/query/cookie 的语法；
2. 解析代码中的 `websGetVar`、`GetValue` 等 typed API，并保留 API 决定的数据字段种类；
3. 使用引号、反引号和 code span；
4. 纯自然语言 NLP 只产生未验证 clue，并做 stop-word/语法过滤；
5. 大模型只能解释或提出候选，不能把候选直接提升成 `source_verified`。

应增加三条回归 fixture，验证 `list` 被恢复、`occurs` 被拒绝、配置键不会成为 HTTP 参数。

## 7. 不能做的推断

本轮材料不允许得出以下结论：

- 不得把 `security.ddos.map`、`sys.schedulereboot.*` 称为已发现的 HTTP 参数；
- 不得从 handler 名生成 `/goform/GetDdosDefenceList`；
- 不得把 `/goform/GetSysAutoRebbotCfg` 标为原文 path；它只能是框架派生候选；
- 不得从 `Get*` 前缀或 `websFormDefine` 推断 HTTP GET；
- 不得把 `GetFirewallCfg` 的 binding 迁移给 `formGetDdosDefenceList`；
- 不得把配置 PoC 中其他背景 key 扩充成漏洞参数；
- 不得任选一个 V1 build 消除 `CVE-2021-42659` 的来源冲突；
- 不得因为 Tenda 官方页面证明 firmware build 存在，就宣称厂商确认漏洞；
- 不得把历史跨版本材料当作当前上传固件的接口、可达性或漏洞存在证明；
- 不得把“没有公开 HTTP path”解释为“设备中没有 HTTP ingress”。它只是一个需要 mapper
  继续闭合的证据缺口。

## 8. 本轮验证记录

- 通过 CVE Program 官方 JSON 的 `references` 回溯三份原始 GitHub 材料；
- 使用固定提交读取报告，复核提交时间并计算文件 SHA-256；
- 逐行核对 request、route token、handler、配置键、反编译片段和版本；
- 查看 2026 报告随附的反编译/配置截图，截图内容与 Markdown 代码和字段一致，未发现额外 HTTP
  path 或 method；
- 对照 Tenda 官方 AC9V3.0 和 AC9V1.0 下载页进行 build 存在性核验；
- 未运行 PoC、未访问设备、未修改固件，也未把任何历史声明提升为当前制品事实。

研究结论的关键可复核判定是：`CVE-2021-42659` 的 HTTP 结构完整；另外两条目前只闭合到
native configuration sink，HTTP 配置导入入口仍是开放义务。
