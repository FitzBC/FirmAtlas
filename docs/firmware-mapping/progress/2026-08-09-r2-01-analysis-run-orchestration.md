# R2-01：Extracted-root AnalyzeRun 统一编排

## 1. 目标与 Interface

第一轮基线审计确认，现有 Inventory、Frontend、Web configuration、Script backend、
Native shallow、Correlation、Scheduler 和 Discovery Catalog 都已有稳定合同，但调用方仍需
用样本脚本手工选择文件和拼装 producer。R2-01 新增一个公共深模块 Interface：

```python
analyze_extracted_root(MappingAnalysisRequest(...)) -> MappingAnalysisRun
```

调用方只提供已解包 root、原始 Firmware Artifact SHA-256 与 Inventory policy。实现隐藏
Inventory、内容/路径联合 source plan、多 producer、Correlation、Scheduler fixed point、
Catalog 组装和内容寻址 run identity。CLI Adapter 为：

```bash
PYTHONPATH=src python3 -m firmatlas.mapping analyze-root ROOT \
  --artifact-sha256 SHA256 \
  --output mapping-analysis-run.json
```

stdout 只返回有界摘要，`--output` 保存完整 run、阶段、source plan 和 Catalog。

## 2. TDD 纵向切片

1. 小型 rootfs 自动恢复 HTML form、参数、PHP 参数和 nginx 配置；相同输入得到相同
   run/catalog identity。
2. 无效 UTF-8 frontend 不终止运行，发布 partial Catalog 与
   `frontend.invalid_utf8` stage diagnostic。
3. CLI 写出完整机器文档并打印候选/参数/证据/义务摘要。
4. ELF `.cgi` 和 `/usr/sbin/uhttpd` 不因扩展名或服务名误送文本 producer。
5. Scheduler 即使没有已注册 deep analyzer，也明确达到 `fixed_point` 并保留开放义务。

测试只通过 AnalyzeRun Interface 和 CLI seam 观察行为，不断言私有分类函数。

## 3. AC9 真实回放与计划迭代

OpenWrt Tenda AC9 19.07.8 的 Inventory 有 1103 个节点。初次自动计划选择 306 个输入，
但误把 ELF `.cgi` 送入 Script producer、把 `usr/sbin/uhttpd`/keep-list 送入 Web config，
造成可避免的 `invalid_utf8` 和 `unsupported_language`。修正为“ELF magic 优先、已知配置
精确路径、Shell 仅 CGI namespace”后：

| 阶段 | 输入 | 输出 | Coverage |
| --- | ---: | ---: | --- |
| Inventory | 1103 | 1103 | completed |
| Source plan | 1103 | 269 | completed |
| Frontend | 84 | 74 | partial：动态 LuCI template |
| Web configuration | 2 | 7 | completed |
| Script backend | 27 | 10 | completed |
| Native shallow | 156 | 612 | completed |
| Scheduler | 100 obligations | 100 open | completed fixed point |
| Catalog | 269 | 720 candidates | partial |

最终 Catalog 另含 220 parameters、1105 EvidenceAtom 和 22 associations。这里的 partial
来自真实动态身份与尚无 eligible deep analyzer，不再来自明显错误的 source routing。

紧凑机器报告见
[R2-01 AC9 AnalyzeRun](../samples/r2-01-openwrt-ac9-analysis-run.json)。生成器连续两次输出
SHA-256 均为 `e679fbbae2acb4779f2bebfd363131d48bc136173fae522aa74e0e89f540e6a8`。

## 4. 边界与下一步

发布门验证：

- AnalyzeRun 专项合同 4/4 通过；
- 后端全量 `make test` 370/370 通过；
- 前端 Vitest 9 files / 19 tests 通过；
- TypeScript check 与 Vite production build 通过；
- 真实报告连续两次摘要一致，文档 JSON 与生成结果语义相等；
- `git diff --check` 与凭据扫描通过。

- 当前入口接收已解包 root；原始上传与 ContainerBinwalkWorker 尚未串接。
- 自动计划运行四个基础 producer，尚未根据 ISA/Profile 自动注册 Native deep、ubus backend、
  set difference 或历史漏洞 expectation analyzer。
- source plan 目前是确定性规则，不使用模型；MiniMax 不应参与基础文件枚举或事实晋级。
- run manifest 尚未持久化为可恢复 job，也尚未进入 HTTP upload/job timeline。
- 非 HTTP protocol producer 仍是后续通信类别扩展重点。

下一轮应增加 versioned Analysis Profile/Analyzer Registry，让 Scheduler 按 source plan 注册
适用的 deterministic deep analyzer；随后再把 AnalyzeRun 接入原始固件 extraction、任务持久化、
上传接口和通信图 read model。

本轮属于固件通信测绘研究，SSH 部署按用户明确要求不适用。
