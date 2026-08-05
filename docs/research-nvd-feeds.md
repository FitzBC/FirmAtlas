# NVD CVE JSON 2.0 Feed 调研

调研日期：2026-08-05

范围：只使用 NVD/NIST 官方页面、官方 JSON Schema 和官方 CVE 详情页。本文用于指导 FirmAtlas 的 NVD 全量镜像、增量更新和漏洞结构化解析。

## 结论摘要

- NVD 当前没有 JSON 2.0 的单个 `full` 文件。官方所谓“一次性导入完整数据集”是下载全部年度压缩 Feed：`2002` Feed 包含 2002 年及更早的 CVE，之后逐年下载直到当前年份。[NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- 全量初始化后，官方建议用 `modified` Feed 保持同步。`modified` 同时包含最近发布和最近修改的记录，`recent` 只包含最近发布的记录；两者仅覆盖前八天，并约每两小时更新。年度 Feed 每日更新一次，但内容未改变时不会更新。[NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- 每次下载归档前必须先读取对应 META。若 `lastModifiedDate` 或 `sha256` 没变则跳过；下载后应对**解压后的 JSON**核验 `size` 和 SHA-256。[NVD META 说明](https://nvd.nist.gov/vuln/data-feeds)
- JSON 2.0 的 `metrics` 可同时包含 CVSS v2、v3.0、v3.1、v4.0 的多来源数组。不能只保留一个裸分数，应保存版本、向量、来源、Primary/Secondary、基础分、危险等级及可用的影响/可利用性子分。[NVD CVE JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- `weaknesses`、`configurations` 和 `metrics` 都可能缺失。`configurations` 是带 AND/OR/NEGATE 语义的适用性树，不能扁平化后丢失逻辑。[NVD Vulnerability API 响应说明](https://nvd.nist.gov/developers/vulnerabilities)
- `references[].tags` 中包含 `Exploit` 可以作为“存在 NVD 标注的利用相关引用”的强信号，但不能据此宣称代码一定公开、可用或已验证。应展示标签和原始链接，并把“是否验证可用”作为独立状态。

## Feed 类型与准确 URL

基础目录：

```text
https://nvd.nist.gov/feeds/json/cve/2.0/
```

### 全量与年度 Feed

不存在官方 `nvdcve-2.0-full.json.gz`。完整语料由年度 Feed 拼成：

```text
GZIP  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{YEAR}.json.gz
ZIP   https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{YEAR}.json.zip
META  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{YEAR}.meta
```

其中 `{YEAR}` 从 `2002` 到当前年份。`2002` Feed 还包含 CVE-2002 之前的记录。官方页面当前列出了 2002 至当前年份的独立 Feed，并明确说明其按 CVE ID 的年份前缀组织。[NVD Feed 列表与完整导入说明](https://nvd.nist.gov/vuln/data-feeds)

示例：

- [2026 META](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.meta)
- [2026 GZIP](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.gz)
- [2026 ZIP](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip)

### Recent Feed

```text
GZIP  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz
ZIP   https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip
META  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.meta
```

`recent` 是最近发布记录的滚动集合，仅包含前八天范围；约每两小时更新。[NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)

### Modified Feed

```text
GZIP  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz
ZIP   https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip
META  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta
```

`modified` 包含最近发布以及最近修改的记录，仅覆盖前八天；约每两小时更新。完整初始化后的常规同步应选择它，而不是 `recent`。[NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)

## META 与更新协议

每个 Feed 都有同名 `.meta` 文本，字段为：

```text
lastModifiedDate:2026-08-05T01:00:07-04:00
size:72468696
zipSize:7000152
gzSize:7000008
sha256:AE021A77B11B9654D8A1465E5C63A7C9ACB6BAA782776921CE29D194555E8DF5
```

上例来自 [Modified META](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta)。官方说明 `size` 是未压缩 Feed 的大小，`zipSize`/`gzSize` 是各压缩归档大小，`sha256` 是未压缩文件的摘要；并要求先读取 META，未变化时不要重复下载归档。[NVD META 说明](https://nvd.nist.gov/vuln/data-feeds)

推荐同步事务：

1. 获取 META，保存原文和拉取时间。
2. 将 `lastModifiedDate` 与已成功导入的状态比较；未变化则结束。
3. 下载 GZIP 到临时文件，并限制最大下载/解压尺寸。
4. 流式解压，同时计算解压后字节数和 SHA-256；与 `size`、`sha256` 严格比较。
5. Schema 校验成功后，以 CVE ID 为自然键在同一数据库事务内 upsert 原始记录和规范化记录。
6. 只有事务提交成功后，才推进该 Feed 的 META 游标。
7. 保留最近一次成功归档或内容寻址原始 JSON，以支持重放、审计和解析器升级。

由于 `modified` 只有八天窗口，连续失败超过八天可能永久漏掉变更。恢复时应重新核对全部年度 META 并导入变化的年度 Feed；另一种补偿路径是按 `lastModStartDate`/`lastModEndDate` 调用 CVE API，但单个日期范围最多 120 天。[NVD CVE API 日期参数](https://nvd.nist.gov/developers/vulnerabilities)

## JSON 2.0 顶层与 CVE 主体

规范 Schema 当前标题为 NVD Vulnerability Data API `2.2.4`，Feed 页面将其作为 JSON 2.0 Feed 的 Schema。顶层必需字段为：

```text
resultsPerPage
startIndex
totalResults
format
version
timestamp
vulnerabilities[]
```

每个 `vulnerabilities[]` 元素包装一个 `cve` 对象。Schema 中 CVE 必需字段为：

```text
id
published
lastModified
references[]
descriptions[]
```

其他重要字段包括 `sourceIdentifier`、`vulnStatus`、`cveTags`、`metrics`、`weaknesses`、`configurations`、`affected`、`vendorComments`，以及 `cisaExploitAdd`、`cisaActionDue`、`cisaRequiredAction`、`cisaVulnerabilityName` 等 KEV 派生信息。[NVD CVE JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)

NVD 官方特别提醒：必需对象可能存在但没有有效数据， optional 对象只在有数据时出现；早期 CVE 的字段丰富度也通常低于新记录。因此解析器必须容忍缺失和空数组，不能把缺少 CVSS/CWE/CPE 误判成“无风险”或“不受影响”。[NVD Vulnerability API 响应说明](https://nvd.nist.gov/developers/vulnerabilities)

## CVSS 结构化解析

`cve.metrics` 是对象，以下键各自都是数组：

| 键 | 版本 | 每个条目的核心字段 |
|---|---|---|
| `cvssMetricV40` | 4.0 | `source`, `type`, `cvssData` |
| `cvssMetricV31` | 3.1 | `source`, `type`, `cvssData`, 可选 `exploitabilityScore`, `impactScore` |
| `cvssMetricV30` | 3.0 | 同 v3.1 |
| `cvssMetricV2` | 2.0 | `source`, `type`, `cvssData`, `baseSeverity` 及可选子分/布尔影响字段 |

`type` 的值为 `Primary` 或 `Secondary`。由于数组中可有多个来源，建议全部保留，并为 UI 另行计算“首选指标”，不要在摄取时覆盖。[NVD CVE JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)

### v3.0 / v3.1

`cvssData` 至少需要 `version`、`vectorString`、`baseScore`、`baseSeverity`。可解析的基础向量包括：

- `attackVector`
- `attackComplexity`
- `privilegesRequired`
- `userInteraction`
- `scope`
- `confidentialityImpact`
- `integrityImpact`
- `availabilityImpact`

Schema 还允许 temporal/environmental 字段，例如 `exploitCodeMaturity`、`remediationLevel`、`reportConfidence`。v3.1 的 `exploitCodeMaturity` 可为 `UNPROVEN`、`PROOF_OF_CONCEPT`、`FUNCTIONAL`、`HIGH` 或 `NOT_DEFINED`。[NIST 托管的 CVSS v3.1 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json)

### v4.0

v4.0 同样要求 `version`、`vectorString`、`baseScore`、`baseSeverity`，基础字段加入 `attackRequirements`，并将影响拆成脆弱系统的 `vuln*Impact` 与后续系统的 `sub*Impact`。可选 `exploitMaturity` 为 `UNREPORTED`、`PROOF_OF_CONCEPT`、`ATTACKED` 或 `NOT_DEFINED`。[NIST 托管的 CVSS v4.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json)

v4.0 Schema 对基础分与危险等级的规范映射为：

| Base Score | Severity | 中文展示建议 |
|---:|---|---|
| 0.0 | `NONE` | 无 |
| 0.1–3.9 | `LOW` | 低危 |
| 4.0–6.9 | `MEDIUM` | 中危 |
| 7.0–8.9 | `HIGH` | 高危 |
| 9.0–10.0 | `CRITICAL` | 严重 |

该映射由 [CVSS v4.0 官方 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json)直接约束。v3.1 Schema也定义 `NONE/LOW/MEDIUM/HIGH/CRITICAL` 枚举；展示时应优先使用来源给出的 `baseSeverity`，并用分数区间做一致性校验，而不是自行发明等级。[CVSS v3.1 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json)

### v2.0

v2 的 `cvssData` 包含 `version`、`vectorString`、`accessVector`、`accessComplexity`、`authentication`、CIA 影响和 `baseScore`；`baseSeverity` 位于外层 metric 条目。NVD 自 2022 年 7 月起不再为新 CVE 生成 CVSS v2，但保留既有 v2 信息。因此 v2 必须兼容解析，但不应作为新记录唯一必需评分。[NVD CVSS v2 说明](https://nvd.nist.gov/developers/vulnerabilities)；[CVSS v2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json)

### 首选评分建议

这是实现策略，不是 NVD 规范：

1. 优先最高可用版本：v4.0 > v3.1 > v3.0 > v2.0。
2. 同版本优先 NVD/NIST 的 `Primary`，其次其他 `Primary`，再其次 `Secondary`。
3. UI 明示“CVSS 版本 + 来源 + 类型”，并允许展开查看同版本其他来源的分歧。
4. 原始向量永远保留；搜索索引至少保存版本、基础分、等级、攻击向量、权限要求、用户交互、CIA 影响。
5. `reference Exploit tag`、CVSS v3 `exploitCodeMaturity`、CVSS v4 `exploitMaturity` 和 CISA KEV 是四类不同信号，不能合并为同一个布尔字段。

## CWE

`cve.weaknesses[]` 的每项包含：

- `source`
- `type`
- `description[]`，其中每项为 `lang` + `value`

`value` 通常是 `CWE-<数字>`，但 NVD 也使用 `NVD-CWE-Other` 和 `NVD-CWE-noinfo` 两个占位值。Awaiting Enrichment、Undergoing Enrichment 或 Rejected 状态可能没有 `weaknesses`。[NVD CWE 参数与响应说明](https://nvd.nist.gov/developers/vulnerabilities)

建议将 CWE 做成多值关系表，保存来源、类型、语言和值；占位值单独标为“未细分/无信息”，不要生成不存在的 CWE 链接。CWE 名称可在独立数据源补充，NVD Feed 本身的 weakness description 通常只给 ID，不能假定总有名称。

## Configurations 与 CPE

`cve.configurations[]` 是产品适用性声明，结构为：

```text
configurations[]
  operator: AND | OR
  negate: boolean
  nodes[]
    operator: AND | OR
    negate: boolean
    cpeMatch[]
      vulnerable: boolean
      criteria: CPE 2.3 match string
      matchCriteriaId: UUID
      versionStartIncluding | versionStartExcluding
      versionEndIncluding   | versionEndExcluding
```

官方说明这些配置是层次化逻辑；AND 表示多个产品共同存在才适用，OR 表示任一产品存在即适用，少数记录还使用 NEGATE。Awaiting/Undergoing Enrichment 或 Rejected CVE 不会包含 `configurations`。[NVD Configurations 说明](https://nvd.nist.gov/developers/vulnerabilities)；[NVD CVE JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)

因此本地模型应同时保留：

- 完整配置树，供精确适用性判定；
- 展平的 CPE 索引，供厂商/产品/part/版本快速检索；
- `vulnerable` 与版本上下界，不能只存 CPE 字符串；
- `matchCriteriaId`，为后续关联 NVD CPE Match 数据预留稳定键。

对固件判定而言，CPE `part=h` 是强硬件/设备信号，`part=o` 常是设备操作系统/固件信号，`part=a` 仍可能是路由器 Web 管理组件等嵌入式应用，不能仅凭 part 排除。后两句是 FirmAtlas 的分类推断，必须与描述、厂商、产品类别和其他证据联合使用。

## References、Tags 与 Exploit/PoC

`references` 是 CVE 必需数组。每条引用结构为：

```json
{
  "url": "https://example.invalid/advisory",
  "source": "source identifier",
  "tags": ["Exploit"]
}
```

只有 `url` 是 Schema 必需字段，`source`、`tags` 可缺失；`tags` 是字符串数组。NVD 将 reference tag 定义为对链接所含资源类型的分类，例如第三方公告、厂商公告、技术论文、媒体或漏洞库条目。[NVD References 说明](https://nvd.nist.gov/developers/vulnerabilities)；[NVD CVE JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)

官方实际记录 [CVE-2026-5302](https://nvd.nist.gov/vuln/detail/CVE-2026-5302) 将一条 GitLab 源码链接标为 `Exploit`，说明该值确实出现在 NVD Reference Tag 中。

建议解析规则：

```text
has_exploit_reference = any(
  casefold(tag) == "exploit"
  for reference in references
  for tag in reference.tags
)
```

UI 文案应为“存在 Exploit 标签引用”或“存在利用证据链接”，并展示链接、来源和全部标签。它不能直接等价为：

- 已验证 PoC；
- 可稳定利用；
- 已在野利用；
- 已公开完整攻击代码。

建议另建 `exploit_evidence` 结构，区分：

| 信号 | 含义 | 建议状态 |
|---|---|---|
| Reference Tag `Exploit` | NVD/CNA 将外链分类为利用相关资源 | `reference_tagged` |
| CVSS v3 `exploitCodeMaturity=PROOF_OF_CONCEPT/FUNCTIONAL/HIGH` | CVSS 时间度量中的代码成熟度 | `cvss_maturity` |
| CVSS v4 `exploitMaturity=PROOF_OF_CONCEPT/ATTACKED` | CVSS v4 威胁度量 | `cvss_maturity` |
| NVD 内嵌 CISA KEV 字段 | 已进入 CISA Known Exploited Vulnerabilities | `known_exploited` |
| FirmAtlas 沙箱人工/自动验证 | 平台实际验证过样本或代码 | `verified` / `failed` / `not_tested` |

其中 Reference Tag 的“不能证明可用性”是基于标签分类语义作出的谨慎推论，NVD 页面也明确声明其引用外部站点不表示 NIST 认可其内容。[CVE-2026-5302 引用免责声明与示例](https://nvd.nist.gov/vuln/detail/CVE-2026-5302)

## API 与 Feed 的当前官方指导

NVD 当前同时提供两条受支持路径：

- Feed 页面明确给出“完整压缩 Feed 一次性导入 + Modified Feed 持续更新”的传统镜像流程。[NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- 同一页面又明确称 2.0 API 是保持最新的首选方式，因为 API 与网站同频更新、支持 changed-since 查询并提供更灵活、更丰富的单一接口。[NVD API 与 Feed 对比](https://nvd.nist.gov/vuln/data-feeds)
- NVD 的企业本地库工作流建议先分页建立本地 CVE/CPE 仓库，再不超过每两小时使用 last-modified 日期范围更新。[NVD API User Workflows](https://nvd.nist.gov/developers/api-workflows)

对 FirmAtlas 的合理组合是：年度 Feed 用于高吞吐的全量初始化和定期对账，Modified Feed 用于低成本常规增量；API 用于八天以上断档补偿、特定 CVE 即时刷新以及 Feed 尚未覆盖的新鲜数据。这样同时满足本地检索性能、批量下载效率和更新完整性。

注意：[NVD 2022 年发布的未来变更公告](https://nvd.nist.gov/General/News/changes-to-feeds-and-apis)曾计划在 2023 年退役 Feed；但截至本次调研，当前官方 Feed 页面仍提供并实时更新 JSON 2.0 Feed，且包含明确同步指引。实现应以当前 Feed 页面和 META 的可用状态为准，同时把源类型封装在适配器后，避免依赖永久不变的发布机制。

## 面向 FirmAtlas 的最小存储清单

为支持本地高效检索且不损失官方语义，至少应保留：

- CVE 主表：ID、source、status、published、lastModified、多语言描述、原始 JSON、原始内容摘要；
- CVSS 多值表：CVE、版本、source、type、vector、baseScore、baseSeverity、impact/exploitability 子分和版本特有字段；
- CWE 多值表：CVE、source、type、lang、CWE 值；
- Reference 多值表：URL、source；以及独立 tags 表/数组索引；
- Configuration 树原文；另建 CPE match 展平表保存 criteria、UUID、vulnerable、四个版本边界和树路径；
- Affected 数据：source、vendor、product、版本与 status；
- KEV 字段、CVSS exploit maturity 和 Reference `Exploit` 三类独立索引；
- Feed 状态：feed key、META 原文、lastModifiedDate、size、sha256、最近尝试/成功时间、错误与导入计数。

数据库写入以 CVE ID upsert，但所有子表都必须按本次记录完整替换或做来源级版本化，避免 NVD 删除/纠正字段后本地残留陈旧关系。

## 官方来源索引

- [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds)
- [NVD Vulnerability API 文档](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD API User Workflows](https://nvd.nist.gov/developers/api-workflows)
- [NVD CVE JSON 2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [CVSS v4.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json)
- [CVSS v3.1 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json)
- [CVSS v3.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json)
- [CVSS v2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json)
- [Exploit Tag 官方实例：CVE-2026-5302](https://nvd.nist.gov/vuln/detail/CVE-2026-5302)
