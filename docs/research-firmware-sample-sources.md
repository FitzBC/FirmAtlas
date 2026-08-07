# 固件样本来源与首批漏洞映射研究

> 核查日期：2026-08-06。本文只核查元数据、目录页和 HTTP 响应，未下载固件二进制。

## 结论摘要

- [FirmEmuHub](https://github.com/a101e-lab/FirmEmuHub) 当前包含 100 个 `BM-*` 基准、100 个 `benchmark.yml` 和 100 个固件文件路径，覆盖 55 个规范化前的型号名称。厂商分布为 TP-Link 50、D-Link 49、Tenda 1。
- [IoTVulBench](https://github.com/a101e-lab/IoTVulBench) 当前包含 95 个 CVE 目录、95 个 `detail.yml` 和 96 个验证载荷。它通过 `environments[].name = BM-*` 与 FirmEmuHub 关联。
- IoTVulBench 的 95 个 CVE 实际只依赖 15 个不同的 FirmEmuHub 固件。下方首批清单的 15 个 `raw.githubusercontent.com` 端点在核查日均以 HTTP HEAD 返回 200，因此可以不下载文件就先导入系统。
- [WUSTL-CSPL/Firmware-Dataset](https://github.com/WUSTL-CSPL/Firmware-Dataset) 的研究盘点解析出 187,431 条下载记录和 33 个 FTP 站点；2026-08-07 的 FirmAtlas 流式导入实测读取 187,429 条有效行，经 URL 去重为 173,778 个候选，并识别出 270 个 HTTP/HTTPS/FTP 下载域名。它是扩充覆盖面的高价值“线索库”，但其中混有 OEM、OpenWrt、DD-WRT 等不同类型镜像，不能仅凭 `vendor` 字段判定为厂商原版固件。
- 十个重点厂商均有可记录的官方入口。除 Cisco 外，核查时均可匿名访问；Cisco 下载目录当前对无会话请求返回 403，且官方说明多数镜像要求登录，有些还要求有效服务合同。

## 可信度与来源类型

建议将“来源可信度”和“链接可用性”分开存储：

- `confidence = high`：厂商自己的下载/公告页面，或仓库内同时提供固件、SHA-256 和可复现漏洞环境映射。
- `confidence = medium`：学术数据集或公共归档；能提供下载线索，但原始发布者、镜像类型或链接新鲜度仍需复核。
- `confidence = low`：无校验值、无清晰来源链的聚合站。只作为发现线索，不自动进入可信样本集。
- `source_type` 建议枚举：`official_portal`、`official_advisory`、`official_cdn`、`benchmark_repository`、`research_dataset`、`community_archive`、`open_source_firmware`、`vulnerability_report`。
- `is_direct` 表示 URL 是否直接指向二进制/压缩包，而不是页面；`auth_required` 与 `region_restriction` 应保持三态 `yes/no/unknown`。

## 两个基准仓库的可导入关系

### FirmEmuHub

[README](https://github.com/a101e-lab/FirmEmuHub/blob/main/README.md) 说明每个基准目录都包含固件、仿真配置和可选认证脚本；[DEVICES.md](https://github.com/a101e-lab/FirmEmuHub/blob/main/DEVICES.md) 给出 `BM ID → vendor → model → firmware filename` 的总表。每个 `benchmark.yml` 还包含：

- `info.serial`
- `info.firmware.vendor/name/version/file_name`
- `info.firmware.architecture`
- `info.firmware.sha256`
- `info.firmware.release_date`
- 仿真 IP、端口和认证方式

因此导入时应把 `BM-*` 作为外部稳定 ID，把 GitHub blob 页作为 `evidence_url`，把 raw URL 作为 `download_url`，并保留仓库给出的 SHA-256。

### IoTVulBench

[README](https://github.com/a101e-lab/IoTVulBench/blob/main/README.md) 和 [vulnerabilities_list.md](https://github.com/a101e-lab/IoTVulBench/blob/main/vulnerabilities_list.md) 描述了 CVE 与设备的关系；具体 `detail.yml` 提供 CVE、描述、分数、标签和 `BM-*` 环境引用。适合形成：

```text
vulnerability --< vulnerability_sample >-- firmware_sample
                                         |
                                         +-- benchmark_external_id (BM-*)
                                         +-- payload_evidence_url
```

导入前应处理两项已确认的数据质量问题：

1. FirmEmuHub 的 `BM-2024-00078` 将厂商写作 `TP-LInk`，需要规范化为 `TP-Link`，同时保留原值。
2. IoTVulBench 的 `CVE-2021-43474/detail.yml` 重复列出两次 `BM-2024-00002`；关系表应以 `(vulnerability_id, firmware_sample_id, relation_type)` 去重。

另一个需要人工复核的语义异常是 `BM-2024-00062`：元数据将型号/版本标为 `TL-WR940N V6`，文件名包含 `wr940nv3_wr941ndv6`，而关联漏洞 CVE-2024-46313 指向 TL-WR940N v3。导入时不要静默改写，应标记 `identity_review_required = true`。

## 首批可导入候选：15 个固件覆盖 95 个 CVE

所有条目均为：`source_type=benchmark_repository`、`confidence=high`（样本存在性和仓库内映射）、`is_direct=yes`、`auth_required=no`、`region_restriction=no`。这里的 `high` 不表示它们均已从厂商 CDN 独立验证来源。

| BM ID | 厂商 / 型号 / 版本 | 文件与下载地址 | CVE 数 | SHA-256 / 元数据证据 |
|---|---|---|---:|---|
| BM-2024-00001 | TP-Link TL-WR940N V4 | [wr940nv4_us_3_16_9_up_boot_160617.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00001/emulation/firmware/wr940nv4_us_3_16_9_up_boot_160617.bin) | 2 | `c321933e4e5970ba7299fe21778dab9398994c22ca0ba0422c6cbc3fbb95ea26` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00001/benchmark.yml) |
| BM-2024-00002 | D-Link DIR-823G A1 v1.0.2B03 | [DIR823GA1_FW102B03.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00002/emulation/firmware/DIR823GA1_FW102B03.bin) | 11 | `ed2e85ccba514ba5c4e07c2ffece04e4b856dfeead3e7e8256c1b852324ee805` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00002/benchmark.yml) |
| BM-2024-00003 | D-Link DIR-825 B1 v2.10NAb02 | [DIR825B1_FW210NAb02.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00003/emulation/firmware/DIR825B1_FW210NAb02.bin) | 4 | `638591ad0ac5c187dd220196af4015ebfadb9cc016eaef79119f4f18b144e8f0` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00003/benchmark.yml) |
| BM-2024-00004 | TP-Link Archer C20i(UN) V1 | [firmware](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00004/emulation/firmware/Archer_C20iv1_0.9.1_3.2_up_boot%28170221%29_2017-02-21_17.14.03.bin) | 1 | `d111f105ec9938129f23f5fc1ccfbce19d18abdf0e5486e6b1a28966a089b929` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00004/benchmark.yml) |
| BM-2024-00005 | D-Link DIR-865L A1 v1.07FB | [DIR-865L_A1.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00005/emulation/firmware/DIR-865L_A1.bin) | 2 | `01a451ce45c758e18d58c4e318c3ba15f63c3da23e4165261d30ccde961c8e9c` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00005/benchmark.yml) |
| BM-2024-00007 | TP-Link TL-WR841N V10 | [firmware](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00007/emulation/firmware/wr841nv10_wr841ndv10_en_3_16_9_up_boot%28150310%29.bin) | 2 | `6f83f1dac5de040233132fa0eaf9099895aa639570c238813364d5dd5fd83811` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00007/benchmark.yml) |
| BM-2024-00009 | D-Link DIR-846 A1 v1.0.0 | [DIR846A1_FW100A43.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00009/emulation/firmware/DIR846A1_FW100A43.bin) | 6 | `4d8d141d0c80121021a8648a03bcaec7dfe3434f68dc6c824956211f6abbb202` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00009/benchmark.yml) |
| BM-2024-00010 | TP-Link TL-WR740N V1 | [firmware](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00010/emulation/firmware/wr740nv1_en_3_12_4_up%28100910%29.bin) | 3 | `811cadac31d699955442737224ccaaf141286d62012a13aba523c19b701fe0a9` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00010/benchmark.yml) |
| BM-2024-00012 | Tenda AC9 V15.03.05.19 | [tenda_ac9.zip](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00012/emulation/firmware/tenda_ac9.zip) | 30 | `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00012/benchmark.yml) |
| BM-2024-00017 | D-Link DIR-806 A1 v1.00 | [DIR-806_A1.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00017/emulation/firmware/DIR-806_A1.bin) | 3 | `dd14b4572ebeb8cd5ce62acdb8494d5e0000942342186090787974650f4f8229` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00017/benchmark.yml) |
| BM-2024-00018 | TP-Link TL-WR840N V4 | [TL-wr840nv4_0.9.1_3.16_up_boot.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00018/emulation/firmware/TL-wr840nv4_0.9.1_3.16_up_boot.bin) | 6 | `ea53ff01b2942fac88843f0ed6bc87de5ad9b41d57d3c1030148dc8f04f1a2a4` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00018/benchmark.yml) |
| BM-2024-00046 | D-Link DIR-846 v1.0.0 | [DIR846enFW100A53DLA-Retail.bin](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00046/emulation/firmware/DIR846enFW100A53DLA-Retail.bin) | 7 | `c7c91cbc70f00a07d58940fbd95f1c1c90fa4ee1de84fdcc3ee77dfe6a7b8be6` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00046/benchmark.yml) |
| BM-2024-00056 | TP-Link Archer-C50 V1 | [ArcherC50_V1_V1.zip](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00056/emulation/firmware/ArcherC50_V1_V1.zip) | 1 | `b41829b83029909d9e3ee187b850745391ea4a578a3e0d56396e6ce8c24308cf` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00056/benchmark.yml) |
| BM-2024-00062 | TP-Link TL-WR940N V6（需复核） | [firmware](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00062/emulation/firmware/wr940nv3_wr941ndv6_us_3_16_9_up_boot_151203.bin) | 1 | `895d311dea155fd7a2ad94608235aac06fe1c1b02379e59180ad40f908e166e9` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00062/benchmark.yml) |
| BM-2024-00083 | D-Link DIR-823G v1.0.2B05 | [dlink_DIR_823G_Version_1.0.2B05.zip](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00083/emulation/firmware/dlink_DIR_823G_Version_1.0.2B05.zip) | 16 | `3928936f860e40e792abc1ae9e4ee811f15b153396dbfdf5c482ca2e8b3a55c4` · [evidence](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00083/benchmark.yml) |

### 完整 CVE 分组

- `BM-2024-00001`：CVE-2017-13772、CVE-2019-6989。
- `BM-2024-00002`：CVE-2019-15528、CVE-2019-15529、CVE-2019-15530、CVE-2019-7297、CVE-2019-7298、CVE-2020-25366、CVE-2020-25367、CVE-2020-25368、CVE-2021-43474、CVE-2022-43109、CVE-2023-26613。
- `BM-2024-00003`：CVE-2020-10213、CVE-2020-10214、CVE-2020-10215、CVE-2020-10216。
- `BM-2024-00004`：CVE-2021-44827。
- `BM-2024-00005`：CVE-2020-13782、CVE-2022-32092。
- `BM-2024-00007`：CVE-2020-8423、CVE-2024-9284。
- `BM-2024-00009`：CVE-2019-17510、CVE-2020-27600、CVE-2021-46314、CVE-2021-46315、CVE-2022-46641、CVE-2022-46642。
- `BM-2024-00010`：CVE-2014-9350、CVE-2021-26827、CVE-2021-44864。
- `BM-2024-00012`：CVE-2018-16334、CVE-2018-18708、CVE-2018-18728、CVE-2020-13390、CVE-2020-13391、CVE-2020-13393、CVE-2020-13394、CVE-2021-31624、CVE-2021-31627、CVE-2022-25414、CVE-2022-25417、CVE-2022-25428、CVE-2022-25429、CVE-2022-25431、CVE-2022-25434、CVE-2022-25435、CVE-2022-25437、CVE-2022-25439、CVE-2022-27016、CVE-2022-27022、CVE-2022-36568、CVE-2022-36569、CVE-2022-36570、CVE-2022-36571、CVE-2024-2704、CVE-2024-2705、CVE-2024-2979、CVE-2024-30584、CVE-2024-30585、CVE-2024-4114。
- `BM-2024-00017`：CVE-2019-10892、CVE-2022-37055、CVE-2022-37056。
- `BM-2024-00018`：CVE-2022-25061、CVE-2022-25062、CVE-2022-25064、CVE-2022-26639、CVE-2022-26640、CVE-2022-26641。
- `BM-2024-00046`：CVE-2018-16408、CVE-2022-42156、CVE-2022-46552、CVE-2023-33735、CVE-2023-43284、CVE-2024-41622、CVE-2024-44340。
- `BM-2024-00056`：CVE-2021-29302。
- `BM-2024-00062`：CVE-2024-46313。
- `BM-2024-00083`：CVE-2018-17787、CVE-2018-17880、CVE-2018-19986、CVE-2018-19987、CVE-2018-19988、CVE-2018-19989、CVE-2018-19990、CVE-2019-12786、CVE-2019-12787、CVE-2019-13128、CVE-2019-13481、CVE-2019-13482、CVE-2019-15526、CVE-2022-44808、CVE-2023-29665、CVE-2023-51984。

## 重点厂商官方来源注册表

| 厂商 | 来源与证据 | source_type / confidence | 直链、登录与地区限制 | 建议采集方式 |
|---|---|---|---|---|
| TP-Link | [Download Center](https://www.tp-link.com/us/support/download/)；[TL-WR940N V4 示例](https://www.tp-link.com/us/support/download/tl-wr940n/v4/) | `official_portal` / high | 产品页不是直链；下载通常落到 `static.tp-link.com`；无需登录；硬件版本和销售地区强约束 | 枚举产品页和硬件版本，采集发布日期、语言、文件大小、发布说明及最终 CDN URL。地区站应分别保留。 |
| D-Link | [现行支持站](https://support.dlink.com/index.aspx)；[Legacy 入口](https://legacy.us.dlink.com/)；[DIR-850L REVA 目录](https://support.dlink.com/resource/products/dir-850l/REVA/) | `official_portal` / high | `resource/products` 可形成直接目录/直链；无需登录；地区和硬件 revision 强约束；EOL 产品可能只在 legacy | 优先抓产品 revision 目录并保存 release notes；把现行站和 legacy 视为两个 source record。 |
| Tenda | [Firmware Download Center](https://www.tendacn.com/download/3.html) | `official_portal` / high | 目录页不是直链，文件常在 Tenda 静态域；无需登录；全球/中文型号和版本可能不同 | 页面当前公开显示 444 个 firmware 项，适合按分页、关键字、版本、大小和详情页增量抓取。 |
| NETGEAR | [Download Center 使用说明](https://kb.netgear.com/19649/How-do-I-download-files-from-the-NETGEAR-Download-Center)；[安全更新直链示例](https://kb.netgear.com/000070691/EX2800-EX3110-EX5000-EX6110-Firmware-Version-1-0-1-84) | `official_portal` / high | 支持页不是直链，文件常在 `downloads.netgear.com/files/GDC/`；普通固件无需登录；部分 ISP 型号不提供手工固件 | 从型号页/KB 提取历史版本、release date、security fixes 和 CDN URL。 |
| Linksys | [官方固件下载说明](https://support.linksys.com/kb/article/1184-kr/)；[EA7500 多硬件版本示例](https://support.linksys.com/kb/article/559-en/?section_id=57) | `official_portal` / high | 支持页不是直链，文件常在 `downloads.linksys.com`；无需登录；硬件版本和 US/其他地区约束明显 | 以产品下载文章为枚举单元，保留硬件版本、区域、EOL 状态和最终 URL。 |
| ASUS | [全球支持入口](https://www.asus.com/support/)；[RT-AC68U firmware 示例](https://www.asus.com/uk/supportonly/rt-ac68u/helpdesk_bios/) | `official_portal` / high | 产品页不是直链，文件落到 `dlcdnets.asus.com`；无需登录；地区页面有发布时间差异 | 页面同时提供版本、日期、大小、SHA-256/MD5 和修复 CVE，是高价值的固件—漏洞映射源。 |
| QNAP | [Download Center](https://www.qnap.com/en-us/download) | `official_portal` / high | 选择器页面不是直链，文件通常在 `download.qnap.com`；无需登录；必须区分产品架构与 QTS/QuTS hero 版本 | 采集产品、OS 系列、build、发布日期、校验值及最终 `.zip` URL。 |
| Synology | [Download Center](https://www.synology.com/en-us/support/download) | `official_portal` / high | 选择器页面不是直链，文件常在 `global.download.synology.com`；无需登录；产品型号与 DSM major version 强约束 | 枚举产品和 OS 历史版本，区分完整 `.pat`、增量更新包、package 和工具。 |
| Ubiquiti | [Firmware releases](https://ui.com/download/releases/firmware)；[产品历史版本示例](https://www.ui.com/download/software/usw-lite-8-poe) | `official_portal` / high | 目录页不是直链，点击后可到 `fw-download.ubnt.com` 或 Ubiquiti 下载域；无需登录；部分旧版本因安全/监管原因被撤下 | 采集产品集合、release slug、发布日期、版本、release notes 和最终 URL；撤下状态也应保留。 |
| Cisco | [Software Download](https://software.cisco.com/download/home)；[下载与权限说明](https://software.cisco.com/download/static/assets/i18n/help.html) | `official_portal` / high | 无会话核查返回 403；多数镜像要求 Cisco 登录，部分要求有效服务合同；少数 Small Business 固件可匿名 | 先采集产品、release、镜像名和权限等级，不绕过认证；将 `auth_required` 和 `contract_required` 单独记录。 |

## 第三方、研究数据集与开源固件源

| 来源 | 覆盖与价值 | source_type / confidence | 直链、登录与限制 | 证据与风险 |
|---|---|---|---|---|
| FirmEmuHub | 100 个可仿真固件，带 SHA-256、架构、型号、版本 | `benchmark_repository` / high（样本存在性） | GitHub raw 直链；无需登录；无地区限制；可能受 GitHub 限速 | [仓库](https://github.com/a101e-lab/FirmEmuHub)。厂商原始出处未在所有记录中单独证明。 |
| IoTVulBench | 95 个 CVE、95 个 detail、96 个 payload，映射到 15 个固件 | `benchmark_repository` / high（仓库内映射） | 元数据/载荷可直接读取；无需登录；无地区限制 | [仓库](https://github.com/a101e-lab/IoTVulBench)。导入时处理重复环境关系。 |
| WUSTL Firmware-Dataset | 研究盘点为 187,431 条可解析 URL、33 个 FTP 主机；2026-08-07 导入快照去重后为 173,778 个 URL 候选。重点厂商记录包括 TP-Link 943、D-Link/DLINK 449、Tenda 328、NETGEAR 4,002、Linksys 242、ASUS 3,387、QNAP 6,342、Synology 16,212、Ubiquiti 1,442 | `research_dataset` / medium-high | URL 多为直链；登录、地区限制和存活状态随上游而异（默认 unknown）；不应自动下载 | [仓库与论文说明](https://github.com/WUSTL-CSPL/Firmware-Dataset)、[HTTP/FTP URL CSV](https://github.com/WUSTL-CSPL/Firmware-Dataset/blob/main/dat/firmware_download_list.csv)、[FTP 主机 CSV](https://github.com/WUSTL-CSPL/Firmware-Dataset/blob/main/dat/firmware_ftp_list.csv)。同一 vendor 下可能混有 DD-WRT/OpenWrt，必须按域名和镜像类型二次分类。 |
| firmware.center | 面向多个厂商的公开目录归档，当前可见 Asus、D-Link、DrayTek、Huawei 等目录 | `community_archive` / low-medium | 目录通常可直链、无需登录；未观察到地区限制；缺少统一 provenance/checksum | [根目录](https://firmware.center/firmware/)。仅作为发现与失效链接回补线索，需用厂商页或哈希交叉验证。 |
| OpenWrt Downloads / Firmware Selector | 大规模设备型号索引、历史 release、snapshot 和可定位镜像 | `open_source_firmware` / high | 直链、无需登录、无地区限制；Firmware Selector 可定位型号，ASU 另有构建 API | [下载目录](https://downloads.openwrt.org/)、[Firmware Selector](https://firmware-selector.openwrt.org/)、[官方说明](https://openwrt.org/docs/guide-developer/imagebuilder_frontends)。它是第三方替代固件，不得标作 OEM 固件。 |

## 可直接形成漏洞—固件关系的额外证据源

这些页面不只是“下载站”，还在同一证据页上给出 CVE/安全修复与固件版本，适合高置信关联：

1. TP-Link 的 [CVE-2023-50224 官方公告](https://www.tp-link.com/us/support/faq/5058/) 列出受影响型号、硬件版本、补丁状态，并链接到对应固件下载页。建议记为 `source_type=official_advisory`、`relation_type=fixed_by`。
2. TP-Link 的 [TL-WR940N V6 / CVE-2025-11676 声明](https://www.tp-link.com/us/support/faq/4755/) 直接指向该型号固件页。建议同时记录 `affected_before` 与公告时间。
3. ASUS 的 [RT-AC68U firmware 页面](https://www.asus.com/uk/supportonly/rt-ac68u/helpdesk_bios/) 在多个版本发布说明中直接列出修复的 CVE，并给出校验值。一个页面可生成多条 `fixed_by` 关系。
4. NETGEAR 的 [EX2800/EX3110/EX5000/EX6110 1.0.1.84 页面](https://kb.netgear.com/000070691/EX2800-EX3110-EX5000-EX6110-Firmware-Version-1-0-1-84) 同时给出 security fixes、版本、日期和各型号官方直链。
5. D-Link 的 [DIR-850L REVA 官方目录](https://support.dlink.com/resource/products/dir-850l/REVA/) 同时保留历史固件、hotfix/beta 和 release notes。可将 release-note 文档中的版本边界与目录内文件对应起来。

安全研究博客、GitHub issue/gist 和 NVD reference 中出现的下载 URL 应记为 `source_type=vulnerability_report`、默认 `confidence=medium`。只有当最终 URL 属于已登记的厂商域名、且型号/版本与报告一致时，才能升级为高置信；链接文字写着“firmware”但实际为空、跳转到网盘或已失效时，不应创建可下载样本。

## 推荐的首期导入字段

```text
firmware_source
  id, name, source_type, base_url, confidence
  vendor_scope, auth_required, contract_required, region_restriction
  crawl_strategy, terms_url, last_checked_at, last_http_status

firmware_sample
  id, external_id, vendor_raw, vendor_normalized, product, hardware_revision
  version, release_date, filename, architecture, sha256
  download_url, landing_url, evidence_url, source_id
  is_direct, availability, identity_review_required, last_checked_at

vulnerability_sample
  vulnerability_id, firmware_sample_id, relation_type
  affected_version_expression, evidence_url, confidence, notes
```

建议 `relation_type` 至少支持 `affected`、`reproduced_on`、`fixed_by`、`mentioned_with`。FirmEmuHub/IoTVulBench 的现有关系应标为 `reproduced_on`，不要自动扩展成“该固件覆盖 CVE 的全部受影响版本”。

## 后续采集优先级

1. 先导入上方 15 个 benchmark 样本和 95 个 `reproduced_on` 关系，UI 即可展示固件样本、下载状态、哈希和关联漏洞。
2. 建立官方来源注册表，优先抓 TP-Link、D-Link/Tenda，因为当前基准数据可立即与官方目录交叉验证；其次是 ASUS、NETGEAR、QNAP、Synology、Ubiquiti。
3. 将 WUSTL CSV 当作候选队列，先按官方 CDN allowlist 分类，再做 HEAD/重定向检查；不要直接批量下载。
4. 对每个候选保存 `last_checked_at`、最终响应码、重定向后的域名和 `Content-Length`。只有用户明确开启下载任务后才获取二进制并复算 SHA-256。
5. UI 中分别展示“官方来源”“研究样本”“社区归档”和“链接已失效”，避免把可访问性、来源真实性和漏洞复现证据混成一个状态。
