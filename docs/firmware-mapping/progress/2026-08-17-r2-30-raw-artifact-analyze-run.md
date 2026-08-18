# R2-30：原始固件制品到统一 AnalyzeRun

> 日期：2026-08-17
> 主样本：OpenWrt Tenda AC9 19.07.8 原始 `squashfs.trx`

## 1. 本轮收敛目标

R2-01 已有 `analyze_extracted_root`，但调用者仍需自行解包并猜测哪一个递归目录才是 rootfs。
这使“用户交付一个固件制品”的产品路径断裂。本轮将这段复杂性封装为一个深模块：

```text
analyze_firmware_artifact(request, extractor) -> FirmwareArtifactAnalysisRun
```

调用方只提供原始制品、隔离派生目录与固定镜像 Adapter；模块内部完成 SHA-256、隔离提取、保守
根目录选择、AnalyzeRun 和内容寻址结果。它没有创建 HTTP 上传接口，也没有改变已解包 root 的
既有分析 Interface。

## 2. 不变量与失败形状

1. 原始制品摘要由模块读取制品自行计算，不能由调用方声明；
2. 仅接受命名为 `squashfs-root`、`rootfs`、`filesystem-root` 或 `fs-root`，且含至少一个
   根文件系统标记的非符号链接目录；
3. 并列最高候选得到 `ambiguous_rootfs`，没有候选得到 `no_rootfs`，二者均不执行测绘；
4. extractor 的失败、partial 提取和完整 AnalyzeRun coverage 分别保留，不能由父状态吞没；
5. `publish-catalog`/`publish-graph` 可消费嵌套 `mapping_run`，使原始制品结果直接进入已有
   Console 图谱，而不是复制 Catalog 格式。

Container probe 的实证还发现旧版 Binwalk 的两个兼容性特征：`--version` 被当成输入文件，且只读
根下若 `HOME` 不可写会静默。因此 probe 在没有版本横幅时以同样隔离的 `-h` 复核，并明确设置
只读根下受限 tmpfs `HOME=/tmp`；镜像 SHA-256 和精确版本仍是硬门。

## 3. 真实 AC9 原始制品回放

使用本机已缓存的固定镜像
`k4l1xx/binwalk@sha256:03d1560ae439250f69a73f3d0bacff45cf1c04d8b0d0cbdf7d0170aa7e0cf303`
（Binwalk `2.2.1`）重放 `openwrt-19.07.8-bcm53xx-tenda-ac9-squashfs.trx`：

| 项目 | 结果 |
| --- | --- |
| 原始制品 SHA-256 | `d40b191c95c5b6e43358785d6c6e9d7915296e9a954d27fbc1936bdf48568ec9` |
| 自动选择 root | `_firmware.bin.extracted/squashfs-root` |
| AnalyzeRun | `mapping-analysis-run:576b91e491d1ac580d8ad2f911c5be93bf02598cf013f854e101f63f543ef7a9` |
| Catalog | `discovery-catalog:e1e06e0f9c15567ef088689896a7cc9e975b8f84a5069c901ef249d36eaff933` |
| 图谱 | `communication-graph:28161bc5edf299b6e171e8d3c92a2e49f04f9901bb3814ad1ea089604e77acf5` |
| 图节点 / 边 | 1665 / 2273 |
| 总状态 | `partial` |

`partial` 来自 extraction Inventory 的自身 coverage，而不是入口遗漏或空成功；机器输出完整保留
在 [raw artifact analysis](../samples/r2-30-openwrt-ac9-raw-artifact-analysis.json) 和
[communication graph](../samples/r2-30-openwrt-ac9-raw-artifact-graph.json)。

## 4. 验证记录

### 4.1 后端和真实制品

- 原始 AC9 `squashfs.trx` 经固定摘要 Binwalk 镜像完成真实解包、rootfs 选择、AnalyzeRun 和图谱投影；
- firmware artifact、container worker、AnalyzeRun、graph repository 和 Intelligence API 相关回归组通过，
  `compileall` 与 `git diff --check` 通过；
- “快速容器瞬间突破输出文件预算”用例曾出现一次非确定失败，随后单用例连续五轮与相关回归组均
  通过；没有放宽 `partial_success`、`output_files` 或诊断断言；
- 首次全量 Python 回归在真实 AC9 深度静态分析阶段持续高 CPU 超过 85 分钟；10 秒自动 traceback
  把热点定位到 `_tokenize_javascript → _luci_rpc_declarations → discover_frontend_asset_graph`。公共入口红测试
  证明同一内容会被多个提取器重复完整分词；加入最多 8 项的纯函数有界缓存后，该测试转绿，Frontend
  38 项通过，真实 Tenda AC9 深度用例在 132.339 秒通过；
- 修复后的全量 Python 回归为 **540 tests / 568.241s / OK**。这既关闭本轮门禁，也把此前约 23 分钟的
  套件基线降到约 9.5 分钟。后续仍应给样本级阶段增加显式耗时账本和 timeout，避免新 producer 再次
  形成不可观测的长尾。

### 4.2 Console、API 和页面交互

- Console：9 个文件、27 个测试通过；TypeScript 检查和 Vite production build 通过；
- 本轮隔离服务监听 `127.0.0.1:18788`，`/api/health` 返回 `ok`；Catalog/Graph API 分别返回
  1202 candidates、220 parameters、22 associations、117 open obligations，以及 1665 nodes / 2273 edges；
- 实际页面依次操作“通信测绘 → 架构图谱 → `ubus://system/validate_firmware_image` → 参数与状态”，
  恢复出 POST JSON-RPC、`object`/`method`/`path`、ACL、开放义务和逐字节 EvidenceAtom；维度切换后为
  7 nodes / 6 edges / 3 dimensions；浏览器 console 无 warning/error；
- 页面在本轮结束时保持打开，供后续会话直接复核。

## 5. 交接和下一步

本轮关闭了原始制品到 AnalyzeRun 的编排断点，且可用
`scripts/serve_openwrt_ac9_raw_artifact_round.py` 重放产品页面。下一阶段若实现浏览器内上传，必须
复用本模块：上传只创建受限文件与异步 job，不能在 HTTP handler 中直接执行 Binwalk，也不能绕过
根目录选择和原始摘要计算。MiniMax 仍不参与提取、根选择或 Catalog 事实晋级。

SSH 部署不适用：本轮仅含 firmware mapping research，符合用户明确的研究例外。
