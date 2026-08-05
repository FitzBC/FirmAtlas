# 固件漏洞情报实现

## 判定方法

平台不会把“包含某个词”直接视为确定结论。每条来源记录会经过规范化，然后由以下可解释信号累计 0–100 相关性分数：

| 信号 | 默认权重 | 说明 |
| --- | ---: | --- |
| 固件术语 | +55 | firmware、bootloader、UEFI、BIOS、BMC firmware 等 |
| 设备类型 | +25 | router、camera、NAS、gateway、PLC、IoT device 等 |
| 固件专属厂商 | +55 | 由策略明确标注，仅厂商命中即可进入“较相关” |
| 关注厂商 | +25 | Cisco、Huawei、Siemens 等，需要其他证据共同确认 |
| CPE 硬件类型 | +30 | CPE `part=h`，证明受影响配置涉及硬件产品 |
| CPE 固件目标 | +65 | CPE `target_sw=firmware/embedded` |
| 固件参考链接 | +10 | 公告链接包含 firmware 或 download 路径 |
| 非固件语境 | -25 | 云服务、SaaS、桌面/移动应用，且没有强固件证据 |

默认阈值为强相关 70、较相关 50。低置信度记录不进入情报流；每个判断均保存命中的信号、证据文本、权重与策略版本，便于后续规则调优。

## 为什么厂商分两类

“厂商关键词”很有价值，但 Cisco、Huawei、Siemens 等厂商同时拥有大量非固件产品，单独命中会产生明显误报。因此策略提供：

- **固件专属厂商**：适合主要目标为路由器、摄像头、NAS 等设备的厂商，单独命中得 55 分；
- **关注厂商**：单独命中只得 25 分，需要设备类型、CPE 或固件术语共同确认。

两组厂商均可在前端策略面板编辑，保存后会重新判定现有记录，不重新下载数据。

## 更新语义

### NVD JSON 2.0 本地镜像

- NVD 不提供单个 full JSON；一次全量由 2002（含更早 CVE）至当前年份的所有年度 feed 组成；
- 下载前读取对应 `.meta`，下载后同时校验压缩大小、解压后字节数和解压内容 SHA-256；
- 解析器以固定大小分块读取 `vulnerabilities` 数组，不把数百 MB 的年度 JSON 整体载入内存；
- 以 500 条为一批事务，按 CVE ID 幂等 upsert，并同步维护 FTS5、CWE 倒排表与 feed 状态；
- 全量完成后使用 `modified` feed 做约两小时粒度的变化更新；其覆盖近 8 天，断档超过 8 天时自动重新对账年度 META；
- 相同 META SHA 且状态为成功的 feed 会跳过，失败状态保留错误并允许安全重试。

详细官方字段与证据边界见 [NVD Feed 研究记录](./research-nvd-feeds.md)。

### NVD

- 使用 CVE API 2.0 的 `lastModStartDate` / `lastModEndDate`；
- 第一次按 `--days` 回溯，后续从成功游标向前重叠 5 分钟；
- 将时间范围切成 3 小时窗口并限制单页 200 条，避免大型 CVE 记录导致长连接超时；
- 按 `startIndex` 分页，单页最多 2,000 条；
- 保存 NVD 原始 JSON、源端修改时间、抓取时间和同步运行；
- 只有完整成功后才推进游标，失败可安全重试。

### CISA KEV

- 获取官方 KEV JSON；
- 以 CVE ID 与来源 ID 幂等更新；
- 与已有 NVD 记录合并 KEV 日期、要求动作、期限和勒索软件使用状态；
- 每次成功后保存目录同步游标和运行统计。

## 数据与接口

SQLite 保存规范化漏洞、来源原文、同步运行、游标和相关性策略。控制台使用以下接口：

- `GET /api/intelligence/overview`
- `GET /api/intelligence/statistics`
- `GET /api/intelligence/feeds`
- `GET /api/intelligence/vulnerabilities`
- `GET /api/intelligence/vulnerabilities/{id}`
- `POST /api/intelligence/sync`
- `GET /api/intelligence/sync/latest`
- `GET /api/intelligence/settings`
- `PUT /api/intelligence/settings`

每条 NVD 记录保留全部 CVSS v2/v3.0/v3.1/v4.0 评分、主评分向量和子分、CWE 来源、CPE 版本边界及 Reference 的来源与标签。`references[].tags` 包含 `Exploit` 时记录为“存在 Exploit 标签引用”，并保留原始链接；该状态不等同于 PoC 已验证可用，也与 CISA KEV 的“已知在野利用”保持独立。

生产部署时可将仓储适配器替换为 PostgreSQL，领域分类器、来源适配器和 HTTP 接口无需改变。
