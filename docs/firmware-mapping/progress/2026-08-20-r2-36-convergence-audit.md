# R2-36：第一方提取器与目标收敛审计

> 日期：2026-08-20
> 状态：实现与 AC9 原始制品纵切完成；最终全量回归、服务和页面验收待本文末补录

## 1. 为什么这一轮必须收敛

本轮不再增加同类静态样本，而是把用户最初目标拆成可验证能力，寻找阻断独立使用的最后一个
缺口。审计结论是：上传、统一 AnalyzeRun、证据、历史漏洞差异、图谱 UI、代表性 corpus 和
MiniMax 受限建议都已经有产品纵切；唯一核心断点是 `containers/binwalk/Dockerfile` 不能在当前
Ubuntu 24.04 基线上冷构建，演示因此仍依赖第三方 Binwalk 2.2.1 镜像。

非 ARM 新样本和最小运行时可达验证能提高研究外推性，但不阻断“用户上传固件 → 静态通信目录
→ 证据图谱 → 历史差异与模型建议”的当前产品闭环，因此不作为本轮完成条件。

## 2. 原始目标—交付证据矩阵

| 原始目标 | 当前交付 | 主要证据 | 结论 |
| --- | --- | --- | --- |
| 用户上传固件后自动分析 | 有界上传、内容寻址制品、单 worker job、raw artifact → rootfs → AnalyzeRun → Catalog/Graph | R2-30、R2-31 | 已闭合 |
| AC9 作为典型主样本 | 原厂历史账本、OpenWrt 双版本、原始 `.trx`、前后端/UBUS/ACL/配置 IPC 图谱 | R2-20 至 R2-31，本轮第一方镜像重放 | 已闭合 |
| 接口、通信组件、参数多维度可视化 | 接口目录、架构图、参数与状态、执行主体、证据/义务面板、focus 查询 | R2-17 至 R2-19 | 已闭合 |
| 对照历史漏洞，解释哪些接口未发现及原因 | 71 条完整分母；observed/partial/not assessable；版本适用性、字段类型和漏检队列分离 | R2-20、R2-21、R2-29 | 已闭合 |
| 多种通信类别和代表样本 | 表单处理、HNAP/SOAP、共享 CGI、脚本后端、Native-only 五类 gate passed；DAP-2695 与 FRITZ 独立 holdout | M1-11、R2-33 至 R2-35 | 已闭合 |
| 中间过程与解释证据 | 内容寻址 EvidenceAtom、stage coverage、open obligation、研究案例时间线和机器报告 | M1-03、M1-07、M1-12、全套 progress/research 文档 | 已闭合 |
| 大模型用于后续业务分析 | MiniMax OpenAI-compatible Adapter；脱敏、有界 bundle；target/evidence 白名单；独立 ReasoningRun | R2-32 | 已闭合，默认关闭且不能晋级事实 |
| 每轮回归、服务和页面交互 | 主控强制本地 HTTP/API/真实 Console 验收并保留记录 | R2-19 以后各轮及本轮第 5 节 | 已闭合 |
| 跨会话/Agent 无缝衔接 | 唯一主控、冻结 schema/profile、进度模板、失败时间线、内容 ID 与下一动作 | 本主控第 7 节、delivery playbook、CONTEXT | 已闭合 |
| 最佳工程实践 | 深模块 Interface、确定性读模型、不可变发布、安全预算、失败不空成功、TDD/全量回归 | architecture、security、evaluation | 已闭合 |

这里的“已闭合”是当前**静态通信测绘 MVP**，不是宣称对任意固件都达到语义完备。未知处理器、
动态字符串、未启动组件和缺失文件必须继续表现为 partial/open obligation。

## 3. 第一方 Binwalk 红→绿

公共验收 seam 是仓库声明的构建命令和 `ContainerBinwalkWorker`，不是 Dockerfile 文本快照。

1. 无代理冷构建先在 GitHub release 下载处失败，保留为环境失败；
2. 显式传递 Docker build proxy 后进入真实构建，在 `python-lzo/minilzo` 编译处因缺少
   `Python.h` 失败；
3. 最小修复只为固定 Ubuntu 24.04 安装 `python3-dev`；
4. 同一配方成功构建，两个扩展 wheel 均完成，Binwalk commit 与 Rust 工具链校验保持不变；
5. 最终 arm64 镜像内容 ID 为
   `sha256:3530eae4148221dba9ca81771860807d524206e30a68b4235d08780afe00d083`，probe 为
   Binwalk `3.1.0`，OCI revision 为 `4fdab3d464d97b68e0af9088df3f9e2e1545b21c`。

这证明本地可从仓库配方构建并以内容 ID 运行；它不声称该 ID 已分发到公开 registry。跨主机分发
时必须使用 `repository@sha256:<manifest-digest>`，不能复用本地 image ID 伪装 registry digest。

## 4. AC9 第一方镜像纵切

输入为 OpenWrt 19.07.8 Tenda AC9 原始 `.trx`，SHA-256
`d40b191c95c5b6e43358785d6c6e9d7915296e9a954d27fbc1936bdf48568ec9`。最终重放：

- extraction `partial_success`，1,109 inventory entries；
- 自动选择 `partition_1.bin` 下的 `squashfs-root`；
- AnalyzeRun `mapping-analysis-run:d63876f5…e8116b`；
- Catalog `discovery-catalog:1914429d…14b4a77`，1,278 candidates、8,121 evidence、117 open obligations；
- Graph `communication-graph:602fff8a…e5a3b`，1,741 nodes / 2,421 edges；
- 总状态 `partial`，因为提取 Inventory coverage 为 partial 且保留 117 条开放义务；没有抬高为整固件 complete。

可提交的中间摘要见
[R2-36 machine report](../samples/r2-36-first-party-binwalk-ac9-replay.json)。完整 AnalysisRun/Graph
位于忽略目录 `var/mapping-work/r2-36-release/`，摘要记录其 SHA 和重放命令，避免把大体积派生物
提交到 Git。

## 5. 最终验证与页面验收

### 5.1 回归与构建

- 受影响 seam：container worker、extraction、firmware artifact、job service 共 29 项通过；
- Python 全量：**560 tests / 610.564s / OK**；
- Console：9 个文件、29 项测试通过；
- TypeScript app/node 双配置检查通过；
- Vite production build：1,801 modules transformed；
- `compileall`、JSON 解析和 `git diff --check` 通过。

### 5.2 服务、API 与页面交互

最终服务使用本轮第一方 image ID 与 Binwalk 3.1.0 配置，监听 `127.0.0.1:18789`，PID
`32273`；`/api/health` 返回 `ok`，作业 API 返回 `enabled=true`、64 MiB 上传预算。新 AC9
Catalog/Graph 已发布到本轮隔离数据库，代表性 corpus API 为五类 required category 全部
`verified`、gate `passed`。

实际页面按以下顺序验收：

1. “通信测绘 → 上传分析”显示内容寻址、无网络只读容器、64 MiB 和单任务串行边界，入口已启用；
2. “架构图谱”显示 AC9 `d40b191c…`、1,741 nodes / 2,421 edges / partial；
3. 搜索 `validate_firmware_image` 精确命中 1/1，聚焦后为 8 nodes / 7 edges / 5 dimensions；
4. 证据面板显示 POST JSON-RPC、`object/method/path`、ACL、两个未决义务，以及前端源码精确
   byte/line locator；
5. 切换“参数与状态”为 7 nodes / 6 edges / 3 dimensions，API 同一 focus 返回相同结构；
6. Chrome 重新进入通信测绘与架构图谱后，warning/error 日志为 0；页面作为 deliverable 保持打开。

页面首轮还发现本记录草稿误读不存在的 `catalog.obligations`，曾把开放义务写成 0；产品页面正确
显示 117。本轮随即改为读取 `catalog.open_obligations` 并修正机器报告。这个失败没有被最终成功
倒写删除，也没有修改产品实现来迎合错误摘要。

## 6. 明确不纳入当前完成声明的边界

- 静态注册不等于运行时进程实际启动、路由可达、ACL 可通过或漏洞可利用；
- MiniMax 输出只生成待验证建议，不修改 Catalog，不读取用户密钥以外的宿主秘密；
- 新 ISA、加密/自定义文件系统、强混淆和全程序 value-flow 仍需 Adapter 扩展；
- registry 多架构镜像分发、设备仿真和动态探测是独立交付，不由本轮本地内容 ID冒充；
- 用户曾在对话中明文提供模型 Key；仓库和报告均未保存或回显，仍应轮换该 Key。

mapping research 按用户明确约定不做 `satc_cloud` SSH 部署；完成后仍须提交并推送 GitHub。
