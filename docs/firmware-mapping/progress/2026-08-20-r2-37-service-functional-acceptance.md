# R2-37 本地服务恢复与全功能验收记录

## 结论

2026-08-20 在最终 R2-36 实现与数据上重新启动本地产品服务，并通过后端全量回归、Console 测试/生产构建、API 场景矩阵和真实浏览器交互。OpenWrt Tenda AC9 原始制品从页面上传后完成隔离 AnalyzeRun，发布同一内容寻址的 Catalog 与 Graph。没有修改分析事实或为验收伪造数据。

交付后页面反馈暴露出初始验收范围错误：服务使用了只含测绘投影的单轮数据库，因此通信测绘正常，但漏洞情报工作台为 0。该阶段不能视为完整产品服务验收。修正时保留原始时间线，没有把初始成功叙述改写成 hindsight-only 结果。

本轮仅增加产品手册、验收记录和截图，并同步根 README、主控文档与部署手册。SSH 部署不适用：范围限于固件通信测绘研究，且用户已明确排除远程部署；本轮仍需提交并推送 GitHub。

## 服务恢复

初始服务监听 `127.0.0.1:18789`，使用：

- 数据库：`var/mapping-work/r2-36-release/firmatlas.db`；
- Console：`apps/console/dist`；
- 作业目录：`var/mapping-work/r2-36-release/jobs`；
- 容器运行时：`/usr/local/bin/docker`；
- 第一方 Binwalk：固定摘要的 3.1.0 镜像；
- 分析时限：600 秒。

该配置的 `/api/health` 返回 `status=ok`，但 `GET /api/intelligence/overview` 的 `relevant=0`、`last_updated=null`，证明仅检查健康和本轮焦点 API 不足以验收完整产品。

## 数据恢复勘误

只读核对确认：

- `var/firmatlas.db` 有 373,140 条漏洞，`strong=9,039`、`likely=10,179`，并已有 5 个测绘 Catalog；
- `var/mapping-work/r2-36-release/firmatlas.db` 有 1 个 Catalog、1 张 Graph 和 1 份 corpus report，但漏洞数为 0；
- 前端过滤假设被排除，因为空数据阶段 API 本身也返回 0。

在 `var/backups/firmatlas-before-service-data-restore-20260820.db` 创建主库一致性备份后，将 R2-36 AC9 Catalog/Graph 和 5/5 corpus report 不可变发布到主库，并把服务切换为 `--database var/firmatlas.db`。原始红色检查转绿：

- 373,140 条漏洞，19,218 条固件相关，2,774 条严重，179 条 KEV，4,353 条 EXP/PoC；
- 173,878 个固件候选、18 个来源；
- 6 个测绘 Catalog、1 张当前 Graph、corpus `passed`；
- 浏览器实际显示 19,218 条漏洞流及具体 CVE，通信测绘仍显示最新 AC9 的 1,278 个候选。

最终服务继续监听 `127.0.0.1:18789`。根因是操作配置选择了单用途数据库，不是数据丢失、前端过滤或 schema migration 失败。

## 自动化验证

| 门禁 | 结果 |
| --- | --- |
| Python 全量测试 | `Ran 560 tests in 1298.206s`，`OK` |
| Python 编译检查 | `python3 -m compileall -q src` 通过 |
| Console 测试 | 9 files / 29 tests 全部通过 |
| TypeScript | `pnpm exec tsc --noEmit` 通过 |
| Console 生产构建 | 1,801 modules transformed，构建通过 |
| API 场景矩阵 | 12/12 通过 |

API 断言覆盖：健康状态、目录列表、候选搜索、MiniMax 禁用边界、图列表、参数状态焦点、潜在隐藏接口 coverage gate、5/5 corpus gate、上传作业、版本比较缺失目标错误合同、历史 overlay 未发布错误合同、SPA 文档。

## 浏览器交互与可见结果

1. 进入“通信测绘”，目录显示 1,278 candidates、22 associations、117 obligations。
2. 打开图谱，显示 1,741 nodes / 2,421 edges / partial。
3. 聚焦 `ubus://system/validate_firmware_image`，接口结构显示 8 nodes / 7 edges；参数与状态显示 7 nodes / 6 edges。
4. 节点侧栏显示 `POST`、`json_rpc`、来源 `www/luci-static/resources/view/system/flash.js`、相邻关系和 EvidenceAtom。
5. 潜在隐藏接口正确显示 0 条已发布事实和 1 个 coverage-gap firmware。
6. 版本对比在只有一个目录时显示“至少需要两个测绘目录”。
7. 语料门禁显示 5/5 verified，并列出 AC9、DAP-3520、DAP-2695、X5000R 与 FRITZ!Box 4040 的作用域证据。
8. 从文件选择器上传真实 AC9 `.trx`，页面经历 running → partial，最终显示 Catalog、Graph 和“查看生成图谱”。
9. MiniMax 未配置时按钮禁用并明确说明确定性 Catalog/Graph 不受影响。

截图保存在 `docs/firmware-mapping/screenshots/`，并嵌入[产品功能与验收手册](../product-guide.md)。截图已逐张目视检查；关键指标、状态、导航和证据侧栏可见，无空白页或布局阻断。

## 解释边界与后续交接

- 上传作业的 `partial` 与 Catalog 的 117 个开放义务一致，是成功发布的诚实覆盖状态。
- 当前验收数据库没有第二个版本目录和历史 overlay，故验证空态/错误合同，不声称完成了本次数据上的版本差异或历史覆盖展示。
- MiniMax 本轮只验证禁用能力边界，没有使用或保存用户凭据，也没有发起外部推理。
- 服务在最终交付时必须继续监听 `127.0.0.1:18789`；完整产品验收必须同时检查漏洞情报、固件资产和通信测绘，不能再以健康接口和单一测绘 API 替代数据域检查。
- 本记录、功能手册与截图随同一 Git 提交推送；SSH 部署保持不适用。
