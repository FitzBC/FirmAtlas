# R2-35：DAP-2695 原始固件与独立 Script-backend Catalog

> 日期：2026-08-20
>
> 状态：已验证并完成本地发布
>
> 范围：D-Link DAP-2695 Rev.A 1.20B20 RC101；raw artifact、AnalyzeRun、显式脚本 source scope、Corpus、API/Console
>
> 部署：不适用；本轮属于 `firmatlas.mapping`、mapping scripts/tests 与 `docs/firmware-mapping` 研究例外

## 1. 本轮问题与决策

R2-33 只证明当前 Script Backend Producer 能解析一次性解包的
`www/__action.php`，并没有形成 retained artifact、rootfs、AnalyzeRun 或 Catalog。若直接把
producer-only 结果称为独立 holdout，会把“一个文件可解析”偷换成“公开入口可稳定复现”。

本轮先冻结两个公开接口：

1. `analyze_firmware_artifact(...) -> FirmwareArtifactAnalysis` 验证原始固件到选根、
   AnalyzeRun 和 Graph 的真实闭环；
2. `build_corpus_report(CorpusReportInput) -> CorpusReport` 只消费有内容身份的不可变
   Catalog，不接受未发布的 producer 摘要。

实测揭示一个必须保留的架构分裂：整固件 `auto-v21` 为 `partial`，但
`script_backend` producer 对明确枚举的全部 PHP source scope 为 `completed`。因此本轮没有
放宽全局 coverage，也没有用 candidate scope 绕过 partial；而是增加 benchmark Adapter，
对每个选中源冻结 canonical path、size 和 SHA-256，形成
`firmatlas.mapping.selected-source-inventory/v1`，再从这些逐字节读取且全部 completed 的结果
装配独立 Catalog。该 scoped Catalog 只证明所声明的 PHP source universe，不代表整机分析完成。

## 2. 原始制品与提取

官方归档和许可边界见
[R2-35 一手来源记录](../research/2026-08-20-r2-35-dap2695-script-catalog-primary-sources.md)。

| 对象 | 固定身份 / 结果 |
| --- | --- |
| 官方 ZIP | `5a1a4e7f45b0a6fa2d58da0142a76dc153f3e3d3fe99bc1fdf99ecc0aae77f8e` |
| 内层 BIN | `11479c2dcce46af141954a067a0c0355d76bd49ed1793894b1d5960ac5300609` |
| 固定提取器 | `k4l1xx/binwalk@sha256:03d1560a…cf303`，Binwalk `2.2.1` |
| 选中 root | `_firmware.bin.extracted/squashfs-root` |
| 提取状态 | `partial_success`；rootfs 可用且被保守选择 |

第一次重放将 `expected_version` 错写成 `3.1.0`，容器身份探测按约拒绝并返回
`extraction.tool_unavailable`。复核固定镜像后用真实版本 `2.2.1` 重放成功。这个失败没有被
删除：它证明 raw entry point 会 fail closed，而不会在工具身份不匹配时静默继续。

## 3. 全固件与脚本作用域的双状态

### 3.1 完整 `auto-v21`

| 指标 | 结果 |
| --- | ---: |
| AnalysisRun | `mapping-analysis-run:ba8afbdc…342f` |
| Catalog | `discovery-catalog:eb73cdcd…d69ab` |
| coverage | `partial` |
| candidates / evidence / obligations | 5,999 / 9,522 / 91 |
| Graph | completed，7,301 nodes / 9,362 edges |

`partial` 有两个可区分来源：Inventory 保留 `inventory.symlink_target_missing`；Frontend 与
Frontend Reachability 保留 `frontend.invalid_utf8`。它们会继续影响全局 correlation 与
Catalog，不能因为脚本分析成功就被抹去。

### 3.2 全部 PHP source scope

| 指标 | 结果 |
| --- | ---: |
| source scope | rootfs `**/*.php`，485 个普通文件 |
| Script Backend stage | completed，485 inputs / 3,909 outputs |
| scoped Catalog | `discovery-catalog:2cc16272…6774` |
| candidates / evidence / obligations | 3,978 / 4,021 / 0 |
| capabilities | reads/writes configuration、reads parameter、selects operation |

这一作用域没有复用 DAP-3520 的候选或证据，因而是独立 vendor PHP-XGI holdout。Corpus
升级为 `firmatlas.mapping.corpus/m1.5`，五个 required category 继续通过，同时页面能明确
看到两个 independent holdout：FRITZ native-only 与 DAP-2695 script-backend。

## 4. 典型中间案例：`www/__action.php`

固定文件 SHA-256 为
`54612f24bed8c83f20b2429b39e17956a7627bbedfbb8bb7d38c3e1816335f57`。当前结果为：

- 339 candidates、356 evidence；
- 参数 `ACTION_POST`；
- 同时具备 `reads_parameter`、`selects_operation`、`reads_configuration` 和
  `writes_configuration`；
- 338 条 state access 与 source candidate 一同进入 Catalog。

这条案例解释了工具如何从请求参数进入脚本 dispatcher，再关联 XGI 状态读写。它仍是
静态证据：不能据此证明某个 action 在目标运行配置中可达、已授权、存在漏洞或可利用。

## 5. 工具与 UI 固化

- `scripts/build_dap2695_script_catalog_report.py` 生成可重复的独立样本报告、完整 AnalyzeRun
  和通信图；artifact 摘要不符、任一 PHP producer incomplete 或 source scope 为空都会拒绝；
- 代表性 Corpus 构建器加入 DAP-2695 retained rootfs、artifact identity 与独立 holdout；
- Console 解释边界改为同时展示 FRITZ 与 DAP 两个已闭合 holdout，并明确 DAP 的整机
  `partial` 与脚本 scope `completed` 可以同时成立；
- README、架构主文档和样本索引记录 selected-source identity 的职责边界。

## 6. 测试、可重复性与页面验收

TDD 红灯先证明缺少 DAP 报告模块和 corpus sample；绿灯后针对两个公开 seam 的测试通过。
最终验证结果：

- Python 全量回归最终为 560/560，耗时 1,298.125 秒。第一次全量为 559/560，唯一失败是
  Console 源 SHA 护栏；用正式构建脚本重建 R2-19 验收报告后恢复。第二次全量期间修正
  source scope 并重写报告，两个测试因内存旧身份/磁盘新身份竞态失败；冻结输入后两项定向
  测试通过，最终全量无失败。由此固化“先双生成，后全量，期间不改内容输入”的顺序；
- Console 为 9 files / 29 tests 全通过；TypeScript app/node 两套检查与 Vite production build
  通过，1,801 modules。首次 shell 因 `node` 不在 PATH 未进入测试，改用 Codex 固定 Node runtime
  后完成；测试还捕获并修正了从 1 个到 2 个 independent holdout 的精确断言；
- DAP 报告和 Corpus 连续双生成逐字节一致，SHA-256 分别为
  `ae0ea16db4b66ea4153a467218fe37734260b0e823057e671803fe5f60c85368`、
  `b1d7160143bdc5aa33e40f518b0d41362330ba60c4e527d1489b8d754e57aeca`；
- 本地服务运行于 `127.0.0.1:18789`。最终 Corpus report
  `corpus-report:fb195f18…c464`、DAP Catalog `discovery-catalog:eb73dcdc…d69ab` 与 Graph
  `communication-graph:87b5d91e…6d7c` 已不可变发布；`/api/health`、Corpus m1.5/DAP verified、
  Catalog partial 5,999/91、Graph completed 7,301/9,362 和生产首页均经 HTTP 验证；
- 真实页面显示 Corpus 5/5，DAP `independent-holdout` 3,978 candidates / 4,021 evidence、
  485 个 PHP source 和双状态解释。目录搜索 `__action.php` 后下钻到 `ACTION_POST` operation
  selector 与精确 evidence locator；图谱聚焦 `upload_config._int` 为 completed 4 nodes / 3 edges，
  可见 POST multipart、`configuration` 参数与开放 `registers_route` obligation；
- 页面切到 AC9 图谱复验 1,665 nodes / 2,273 edges，`ubus://luci/getFeatures` 焦点为 completed
  32 nodes / 31 edges，Frontend interface、Backend binding 与 ACL grant 均保留；再切回 DAP，
  浏览器 warning/error 日志为空，最终 DAP 图谱页作为 deliverable 保留；
- `git diff --check` 在提交前通过。SSH deployment 不适用，依据 `AGENTS.md` firmware mapping
  research exception；本轮仍需 commit 并通过已配置的 GitHub SSH remote push。

## 7. 反思与收敛

本轮没有新增核心 Producer；现有 Script Backend 能力已经足够，真正缺的是从官方 raw
artifact 到独立、可发布、可归责的验收链。这个结果说明后续不应继续无限增加同类 PHP
样本。下一轮应做整体收敛审计，优先关闭发布镜像版本歧义、增加一个非 ARM native holdout，
并为已闭合的 AC9/DAP/FRITZ 图谱选择最小运行时可达验证。AC9 继续作为主回归，MiniMax
继续只产生 evidence-constrained proposal，不能改写 Catalog 事实。

本轮也按 casebook 准入规则评估了“整固件 partial / producer source scope completed”分裂。
它属于覆盖分母与 benchmark 编排问题，而不是新的固件 dispatcher、多进程链或通信架构事实；
因此不新增 research-case corpus 条目，完整时间线、反事实与限制由本文件和一手来源记录保存。

## 8. 跨会话交接

下一会话先读本文件、R2-34、R2-33 和一手来源记录。受控样本位于忽略目录
`var/mapping-work/r2-35-dap2695/`；正式可提交结果是
`docs/firmware-mapping/samples/r2-35-dlink-dap2695-script-catalog.json` 与更新后的
`m1-11-representative-corpus-report.json`。不要提交固件、rootfs 或 API secret。用户在早期消息
中明文提供过 MiniMax key；该 key 从未写入本轮文件或输出，仍应在供应商控制台轮换。
