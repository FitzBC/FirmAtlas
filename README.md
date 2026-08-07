# FirmAtlas

FirmAtlas 是一个以证据为核心的一体化固件分析平台。它将固件归档、递归解包、组件清单、通信拓扑、接口与参数、历史漏洞关联、版本差异和最新漏洞情报放入同一条可追溯分析链。

当前仓库已经包含：

- 统一的[领域词汇](./CONTEXT.md)，避免“固件版本”“文件”“漏洞命中”等概念混用；
- [总体架构](./docs/architecture.md)、[功能范围与路线图](./docs/product-scope.md)；
- [情报源与同步策略](./docs/intelligence-sources.md)；
- 一个零第三方依赖的 Python 领域内核，用来固化首个分析结果接口；
- 针对不可信固件输入的[安全基线](./docs/security.md)；
- 可增量更新的 NVD / CISA KEV 情报后端与高级 React 情报工作台；
- 基于后端通信架构风格的接口语义分类、相似接口推荐与漏洞下钻；
- 元数据优先的固件样本目录，可从固件查漏洞，也可从漏洞反查关联样本。

## 先跑起来

要求 Python 3.9+；运行前端需要 Node.js 22.12+ 与 pnpm 10+。

```bash
make test
make demo
```

`make demo` 会输出一个最小分析报告，展示后续分析器统一提交的结果形状。

## 固件漏洞情报工作台

```bash
# 终端 1：准备演示数据并启动 API
make seed-demo
make api

# 终端 2：安装并启动 React 控制台
make web-install
make web-dev
```

访问 `http://127.0.0.1:5173`。获取真实官方情报可以执行：

```bash
PYTHONPATH=src python3 -m firmatlas intelligence sync --source nvd --source cisa-kev --days 1
```

需要完整的本地 NVD 数据集时，先执行一次年度全量初始化，再周期执行统一增量更新：

```bash
# 首次：下载 2002 至当前年份的全部 JSON 2.0 feeds，校验后批量入库
make intelligence-bootstrap

# 后续：按 META 判断是否变化，导入 modified feed；断档超过 8 天自动年度对账
make intelligence-update
```

年度压缩包保存在 `var/nvd-feeds/`，规范化记录、原始来源记录、FTS5 索引和 feed 状态保存在 `var/firmatlas.db`。命令可安全重跑：SHA-256 未变化且已成功导入的年度会被跳过。完整导入需要数百 MB 下载空间和更大的本地 SQLite 空间。

NVD API key 可通过 `NVD_API_KEY` 环境变量提供；未提供时客户端自动按更保守的分页间隔运行。完整判定与更新机制见[情报实现说明](./docs/intelligence-acquisition.md)。

## 固件样本目录与双向关联

固件资产页聚合公开 benchmark、厂商下载中心、研究数据集和社区归档。当前同步会登记 18 个来源，从 FirmEmuHub 收录 100 个 benchmark 候选，并根据 IoTVulBench 建立 95 条漏洞复现环境线索（覆盖 15 个不同固件）；同时流式读取 WUSTL Firmware Dataset，本次公开快照的 187,429 条有效记录经 URL 去重后形成 173,778 个候选。系统当前共可检索 173,878 个固件下载候选。同步过程只读取文本元数据，不下载固件二进制，也不会把候选地址冒充为已经校验的制品。

```bash
# 流式写入公开来源、样本候选和漏洞关系；约 30 MB 元数据，可安全重跑
make firmware-catalog-sync

# 然后启动 API 和控制台，在左侧进入“固件资产”
make api
make web-dev
```

支持的查询接口：

- `GET /api/firmware/overview`：来源、候选、厂商和漏洞关系总览；
- `GET /api/firmware/sources`：即使暂无具体样本，也保留已验证的来源入口；
- `GET /api/firmware/candidates?q=CVE-2017-13772`：按 CVE、厂商、型号、版本或文件名检索；
- `GET /api/firmware/candidates/{candidate_id}`：查看下载候选、来源证据和关联漏洞；
- `GET /api/firmware/vulnerabilities/{CVE}/samples`：从漏洞反查关联固件样本。

UI 和 API 会明确区分“候选地址”“漏洞复现线索”和“已下载/哈希校验制品”。大目录使用 SQLite FTS5 和服务端分页检索，输入筛选不会把 17 万条记录加载到浏览器。完整来源清单、15 个已验证可访问的 raw 地址、SHA-256、95 个 CVE 分组及数据质量异常见[固件样本来源研究](./docs/research-firmware-sample-sources.md)。

当前导入器会规范化 `TP-LInk` 等已确认拼写问题，并保留原始值；对于 `BM-2024-00062` 这类型号、版本和文件名语义冲突，只标记待人工核验，不静默篡改。

## 首个纵向切片

首版优先打通一条完整链路：

1. 上传一个固件并按 SHA-256 去重；
2. 在隔离环境中识别、递归解包并记录每一步证据；
3. 生成文件系统、软件组件、服务、监听端口和配置接口清单；
4. 用组件身份与版本范围关联历史漏洞，并保留匹配理由和置信度；
5. 比较同一设备型号的两个固件版本；
6. 持续同步漏洞情报，重新评估已有固件并产生提醒。

## 目录

```text
src/firmatlas/          可执行的领域内核与稳定接口
tests/                  面向接口的测试
analyzers/              分析器接入约定与未来实现
apps/                   控制面和 Web 控制台的演进位置
deploy/                 本地与生产部署定义的演进位置
docs/                   产品、架构、安全、情报与来源研究
```

## 设计原则

- **证据优先**：每个结论都能回到原始制品、文件偏移、路径或工具输出。
- **可复现**：分析报告绑定制品摘要、分析器版本、规则版本和运行参数。
- **事实与判断分离**：提取到的事实不因漏洞库更新而改变；漏洞匹配可以重复计算。
- **允许不确定性**：组件版本、端点和漏洞匹配都有置信度及人工复核状态。
- **默认隔离**：固件和解包内容是不可信输入，不在控制面进程内执行。
