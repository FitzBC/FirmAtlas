# R2-28：AC9 CGI namespace 与 selector transport

> 日期：2026-08-14
> Profile / Registry：`auto-v20` / `builtin-v20`
> 范围：mapping-only；按约定 SSH 部署不适用

## 本轮结果

本轮把 R2-27 尚未闭合的 `UploadWebsite` transport 推进为可独立重放的 HTTP route：

```text
/cgi-bin registrar@0x178f0 (callsite 0x2eb64)
  -> webs_Tenda_CGI_BIN_Handler@0x3a678
  -> path 第二段 parser
  -> selector dispatcher@0x3a9a0 (7 arms)
  -> /cgi-bin/UploadWebsite
  -> handler@0x3e564
  -> GetUrlValue / SetUrlValue / CommitUrlCfm
  -> cfm/url_mib/*
```

`/cgi-bin/UploadWebsite` 是 `deterministic_derived`：路径由 prefix registrar、GoAhead `path` 分段语义和 selector compare arm 共同证明，不是完整 URL 字面量。HTTP method 没有 selector-specific guard，因此仍为 `unresolved`；不能因读取 upload body 就推成 POST。

## 发现—反思—修正

旧 anchor scanner 只恢复 6 个 arm。机器码复核显示漏项是 `DownloadFlash`：literal 为 13 bytes，但 `strncmp` width 为 11；旧规则错误要求二者等长。`auto-v20` 保留历史算法可回放，同时新增受结构约束的 prefix-width inventory，恢复完整 7 arms，并显式发布 `comparison_width`。

这是 obligation non-transitivity 案例：更深分析同时关闭 route binding、把 completeness 从 6 修正为 7，并保持 method 与 configuration URL document activation 两项义务开放。不得因 route 已闭合就传递关闭 loader obligation，也不得把 `/cgi-bin` 错写成 `/goform`。

## 固化能力与中间输出

- 新公共 seam：`discover_arm_cgi_selector_dispatches(artifacts)`；输入仅来自 Inventory，不含 AC9 route seed。
- 默认 `auto-v20` 从完整 rootfs 自动选择含 owner export 与 namespace 线索的 ARM ELF。
- Catalog 发布 `native_cgi_selector`，保留 registrar/callsite、owner、dispatcher、selector、compare width、handler、route derivation、method 和 loader status。
- Graph 以 `handler_identity` 将 `/cgi-bin/UploadWebsite` 连到 R2-27 URL consumer。
- Console 新增“CGI 组合路由”筛选和解释卡。
- checked report：[`r2-28-vendor-tenda-ac9-cgi-selector.json`](../samples/r2-28-vendor-tenda-ac9-cgi-selector.json)。其中 stage=`completed`、input=1、output=7，且 UploadWebsite graph edge 可重放。
- 原始来源：[`2026-08-13-ac9-uploadwebsite-http-binding-primary-sources.md`](../research/2026-08-13-ac9-uploadwebsite-http-binding-primary-sources.md)。

## 负回归

- 不生成 `/goform/UploadWebsite` 或 method `POST`；
- 不把 request body、URL IPC frame field 和 URL-store state key 合并为 HTTP 参数；
- 不生成 `UploadWebsite -> load_url_mib/reload_url_mib` 调用边；
- 不把静态 route/handler 提升为运行时可达、漏洞存在或可利用性。

## 收敛策略

后续不再按零散线索无限追加轮次，只保留三项有终止门槛的收敛工作：

1. **AC9 历史漏洞账本收口**：结构化/已核验记录必须归入 observed、out-of-scope、version-confounded 或 unresolved，且每个 gap 有机器可读原因；不拿错误版本事实凑 100%。
2. **跨样本 corpus gate 收口**：AC9、X5000R、OpenWrt 与 AC18 positive/negative control 覆盖 HTTP registrar、shared CGI、ubus/RPC、IPC、配置导入和 disabled-feature，每类至少一阳一阴稳定回放。
3. **产品闭环收口**：上传/解包→AnalyzeRun→Catalog/Graph→历史 overlay→Console 一键查看；MiniMax 只解释/排序带 evidence reference 的事实，不生成确定性事实。

三项通过后进入维护模式，仅在回归失败、新通信架构类别或明确历史漏检能提升 coverage gate 时新增 producer。

## 验证记录

- Python 全量：`526 tests in 1373.495s`；包含新 producer、auto-v20 cold-start、checked report、Catalog/Graph、负回归与历史 casebook。
- 提交前证据加固后再跑 producer + auto-v20 cold-start + checked report + casebook：`19 tests in 313.605s`，全部通过。
- Console：9 files / 26 tests；两套 TypeScript check 与 Vite production build 通过。
- `serve_vendor_tenda_ac9_mapping_round.py` 从真实 AC9 rootfs 独立分析并发布 SQLite：catalog 4,950 candidates、73 open obligations；graph 7,126 nodes / 9,329 edges。
- API：`/api/health` 返回 `status=ok`；`native_cgi_selector` 查询返回 7 项，`UploadWebsite` 正确保留 2 项义务；production document 和 hashed assets 可加载。
- 真实页面依次操作“通信测绘 → CGI 组合路由 → /cgi-bin/UploadWebsite”，可见 deterministic-derived、compare 13 bytes、handler `0x3e564`、method unresolved、loader `no_direct_handler_call` 与 9 条原始证据；新增证据分别固化 owner relocation 与第六参数 path 两次 `/` 分段结构，避免只凭相邻字面量派生 route。
- 首轮页面发现图谱结构索引仅请求 interface/state，导致真实 dispatch route 搜索为 0；修正为 interface/dispatch/state 并新增 Console 回归后复验。搜索 `UploadWebsite` 返回 1/1，聚焦后“接口结构”显示 route 与两项义务，“通信组件”显示 route → `bin/httpd@0x3e564` URL consumer 的 `calls` 边；浏览器 warning/error 为 0。
- 最终发布 identity：analysis run `mapping-analysis-run:32487fbbff90766cebcab7f1170cfe90ff1b22c08d4a5defdf3952ded0f65f2d`，catalog `discovery-catalog:928b9884ac447fcb5e677edc76f39bb872eec9be3486e37f04ad9d233154ca57`，graph `communication-graph:cbc905a860d6027093579c5cb430bd352303e2cd47465c961554d2dac7d779b8`。
- 验收后停止本地服务。mapping research 按用户约定不做 `satc_cloud` SSH 部署。
