# M1-04：Frontend Request Evidence Producer

> 工作项：M1-04  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地回归、真实样本回放、Git 提交与推送；按用户当前指示不部署 SSH

## 1. 结果

实现：

```text
discover_frontend_requests(source_entry, source_bytes, policy)
  -> FrontendProducerResult
```

结果版本为 `firmatlas.mapping.frontend-result/v1alpha1`，包含请求候选、参数候选、EvidenceAtom、覆盖状态、诊断和声明支持的构造集合。它只发布 frontend candidate，不直接发布 Exposed Interface，也不声称存在后端 route/handler。

当前声明的构造：

- Tenda `R.pageModel.getUrl/setUrl`；
- `R.moduleModel.getSubmitData` 的 form 参数序列化；
- jQuery `getJSON`、`post`、`ajax`；
- AJAX JSON object 与 header selector；
- HTML Form action/method 与具名 input。

## 2. 身份与证据语义

- exact literal 和 literal prefix 分开，`"/status?" + random()` 不伪装为完整 URL；
- method/representation 只有在框架调用或显式配置能够证明时才填写，`R.pageModel` 不猜 HTTP method；
- `SOAPAction` header 与共享 CGI `topicurl` 作为 operation selector candidate，不与普通参数混合；
- 相同请求结构的多处调用合并 Candidate ID，但每个字节位置保留独立 EvidenceAtom；
- Candidate ID 纳入 selector literal，因此 `/HNAP1` 的不同 SOAPAction 不会合并成同一个 operation candidate；
- 参数身份限定在 request candidate 与 namespace 内，相同 `mac` 不跨接口全局合并；
- 注释与无关字符串不成为请求证据；内容摘要、UTF-8 和预算失败进入 Coverage/Diagnostics。

## 3. TDD 记录

13 条公开 Interface 测试覆盖：

1. `R.pageModel` read/write candidate；
2. 注释与字符串误报隔离；
3. jQuery POST、method 与 form representation；
4. GET JSON 动态 literal prefix；
5. HNAP/SOAPAction header selector；
6. 共享 CGI JSON selector 与普通参数分离；
7. HTML Form 与 input 参数；
8. 非 UTF-8 失败不冒充空结果；
9. source/candidate 预算覆盖；
10. 最近前置 data assignment，防止后续同名变量污染；
11. 重复调用合并候选并保留多处证据；
12. `R.moduleModel.getSubmitData` 与唯一 setUrl 绑定；
13. 文档样例持续区分真实源与合成 fixture。

红阶段和真实回放实际发现：

- 全局正则把注释和字符串当请求；
- 全局变量表让请求错误绑定到后出现的同名赋值；
- AC9 两处 `getOnlineList` 产生重复 Candidate ID；
- 自由 URL 字符串不能表达动态尾部；
- 共享 endpoint 若不保留 selector，会把不同 operation 错误合并。

## 4. 实际与代表性样本

完整中间输出见 [M1-04 Frontend Producer JSON](../samples/m1-04-frontend-producer-summary.json)。

### 4.1 Tenda AC9：真实完整源文件

| Source | bytes | candidates | parameters | evidence | coverage |
| --- | ---: | ---: | ---: | ---: | --- |
| `static_route.js` | 11,206 | 2 | 1 | 3 | completed |
| `online_list.js` | 15,385 | 5 | 4 | 10 | completed |

关键结果：

- `SetStaticRouteCfg` 关联 form 参数 `list`；
- `SetOnlineDevName` 关联 `mac` 与 `devName`；
- `getOnlineList?` 两个调用点合并为一个 literal-prefix candidate，保留两条 evidence；
- `setBlackRule`、`delBlackRule` 的 `mac` 分别属于自己的 request candidate。

### 4.2 跨架构合同 fixture

| 类别 | endpoint | selector | 普通参数 | 作用 |
| --- | --- | --- | --- | --- |
| HNAP/SOAP | `/HNAP1` | header `SOAPAction=…GetDeviceSettings` | 0 | 证明单 endpoint 可按 header 拆 operation |
| 共享 CGI/JSON | `/cgi-bin/cstecgi.cgi` | JSON `topicurl=setting/setLanCfg` | `lanIp` | 证明 selector 与业务参数不能混为功能分类 |

这两项是合成合同 fixture，只证明身份模型与 Producer 行为，不计入真实固件召回率。D-Link/Totolink Firmware Artifact 尚未摄取，不能提前写成真实样本验证。

## 5. 回归与发布证据

| 门禁 | 结果 |
| --- | --- |
| Frontend Producer contract | 13/13 通过 |
| Mapping extraction/inventory/evidence/frontend/snapshot | 61/61 通过 |
| 后端全量 | `make test`，121/121 通过 |
| 前端测试 | Vitest 16/16 通过 |
| TypeScript / 生产构建 | 检查通过；Vite build 通过 |
| 本地 API / 前端烟雾 | 临时 SQLite 下 health 200、overview 200、FirmAtlas HTML 200 |
| AC9 完整源回放 | 2 files / 26,591 bytes / 7 candidates / 5 parameters / 13 evidence |
| 实现修订 | `275119a` |
| SSH deployment | 不适用（用户当前测绘范围） |

## 6. 反思与微调

- `completed` 只针对结果中列出的 `supported_constructs`，不能解释为任意 JavaScript 的负面真值；
- 当前轻量 tokenizer 比全局 regex 更安全，但不是完整 JavaScript parser；regex literal、模板插值、别名包装与跨函数数据流需要后续 AST/模型义务；
- `R.moduleModel` 参数只在单一 `setUrl` 时自动绑定；多个 write endpoint 时保持不绑定，后续由 clue scheduler 处理，不能按距离猜测；
- HTML 与 JavaScript 目前位于同一深 Module Implementation，通过同一 Interface 测试；若继续增加框架语法，应把 lexer/parser 拆成内部策略文件，但不扩大外部 Interface；
- operation selector 候选依赖结构化位置与 selector key 词表，不能因为 value 带 `/` 就自动判为 selector；
- 前端构造只能支持 `constructs_request/serializes_parameter/selects_operation`，不能晋级 `registers_route` 或 `binds_handler`。

## 7. 下一动作

M1-05：从 uhttpd/GoAhead/Boa/lighttpd/nginx 等配置、启动脚本和 docroot 线索发布 `exposes/maps_namespace/requires_auth/listens_on` EvidenceAtom，与 M1-04 candidate 做证据交叉验证。先冻结配置 Producer Interface 和“未支持格式不是空结果”的覆盖语义。
