# 2026-08-08 M0 设计基线

## 结果

建立新一代固件通信测绘引擎的主控入口、理论模型、领域与证据模型、深模块架构、FirmAtlas 集成方案、评测回归体系和跨会话交付规范。本里程碑只形成设计与协作基线，不声称测绘引擎已经实现。

## 范围

完成：

- 复核旧 `iot_seedintelligentanalysis` 的发现、Fusion、证据和测试结构；
- 明确 seed-first 是结构耦合，选择 FirmAtlas 原生绞杀式重构；
- 形式化多源线索传播、证据闭包和多视图通信架构指纹；
- 定义 Interface/Operation/Parameter、EvidenceAtom、Snapshot、Coverage Ledger 和 Obligation；
- 设计 FirmwareMapper、FirmwareAssociator 和 VulnerabilityMechanismAnalyzer 深模块；
- 制定 M0—M7 路线、M1 工作项、回归矩阵和跨会话协议；
- 记录三个难以逆转的架构决定。

不包含：

- 新测绘代码、数据库表和 HTTP 路由；
- 固件下载、解包或 Ghidra 执行；
- UI 功能变化；
- 论文实验结果或性能声明。

## 设计与决策

- [ADR-0001：Seed 是可选证据源](../../adr/0001-seed-as-optional-evidence.md)
- [ADR-0002：发布不可变固件测绘快照](../../adr/0002-immutable-firmware-mapping-snapshots.md)
- [ADR-0003：生产测绘与主动验证隔离](../../adr/0003-separate-mapping-from-active-verification.md)

核心不变量：模型不能创造固件事实；失败不能伪装为空结果；Snapshot 不可变；相似性不能反向确认身份；动态验证不是生产测绘的必要依赖。

## 实现证据

本里程碑为文档设计，相关文件由 [主控文档](../README.md) 导航。没有新增运行时代码或 schema。

## 回归证据

| 检查 | 命令 | 结果 |
| --- | --- | --- |
| Markdown 本地链接 | Python 只读检查器，覆盖 README、CONTEXT、主控目录和 ADR | 15 个文件，全部链接可解析 |
| Diff 格式 | `git diff --check` | 通过 |
| 后端全量回归 | `make test` | 60 tests passed，4.261s |
| 前端测试（初次） | `pnpm --dir apps/console test` | 未通过：系统 PATH 缺少 `node`，未归因于测试代码 |
| 前端测试（固定运行时） | 使用 Codex workspace Node PATH 运行 `pnpm --dir apps/console test` | 8 files / 16 tests passed，1.73s |
| 前端构建（初次） | `make web-build` | 未通过：系统 PATH 缺少 `node` |
| 前端生产构建（固定运行时） | 使用 Codex workspace Node PATH 运行 `make web-build` | TypeScript check 与 Vite build 通过，1799 modules transformed |
| 本地 API | 临时空数据库启动 API，访问 `/api/health` | HTTP 200，status=ok |
| 本地前端文档 | 访问 `/` 并检查 React root | HTTP 200，HTML 565 bytes，root 存在 |
| 本地行为端点 | 访问 `/api/intelligence/overview` | HTTP 200，JSON 160 bytes |

固定 Node 路径来自本地 Codex workspace runtime；没有修改项目依赖或锁文件。

## 发布证据

- 设计基线提交：`1ab781258a7915adaffc1e3f12641156f6d26fc7`；
- GitHub：已推送到 `FitzBC/FirmAtlas` 的 `main`；
- `satc_cloud`：本次仅规划和文档设计，用户明确要求不进行 SSH 部署，因此标记为不适用；
- 范围调整前曾启动一次 `make deploy`，它在 SSH banner/linger 预检阶段终止，未创建远端 release、未同步文件、未切换 `current`、未重启服务；
- 本记录的状态收口将由紧随其后的文档提交发布到 GitHub。

## 覆盖缺口与未决义务

- 尚未冻结 M1 的最小 Snapshot JSON/schema contract；
- 尚未选择并登记第一批可再现标注固件；
- 论文相关工作对标和数据集许可审查仍需独立开展；
- 旧仓库的可复用代码尚未按许可证、依赖和测试逐项提炼。

## 下一动作

- M1-01：建立版本化 `FirmwareMappingSnapshot` 最小合同；
- 与 M1-01 同步冻结至少五类通信架构的最小标注清单。
