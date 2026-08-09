# 交付与协作手册

## 1. 工作组织

所有工作使用里程碑 ID 和工作项 ID。一次会话优先完成一个可验证纵向切片，避免同时打开多个未落地设计。主控状态位于 [README.md](./README.md)，历史证据位于 `progress/`。

目录约定：

```text
docs/firmware-mapping/
├── README.md                         # 唯一主控入口和当前状态
├── theory-and-research.md            # 理论、创新与论文假设
├── domain-and-evidence-model.md      # 领域结构和不变量
├── architecture.md                   # 深模块与分析流水线
├── firmatlas-integration.md          # 数据、查询和 UI 集成
├── evaluation-and-regression.md      # 工程/研究验证
├── delivery-playbook.md              # 本文，协作与完成规范
└── progress/
    └── YYYY-MM-DD-<milestone>-<slug>.md
```

架构决策位于 `docs/adr/`，领域词汇位于根目录 `CONTEXT.md`。不要在 progress 记录中重新定义领域词汇，也不要用 ADR 记录普通实现选择。

## 2. 每个工作项的生命周期

### 2.1 Orient

- 阅读 `AGENTS.md`、主控文档、`CONTEXT.md`；
- 阅读当前工作项依赖的设计文档和最近进度记录；
- 检查当前 Git revision、工作树、远端差异和已有测试；
- 确认没有覆盖其他会话的未提交修改。

### 2.2 Frame

在实现前记录：

- 工作项 ID；
- 用户可见结果；
- 目标 Module 和 Interface；
- 输入/输出与不变量；
- 明确不做的内容；
- 风险、数据迁移和回滚；
- 验收证据与回归范围。

如果结果不能通过 Module Interface 观察，应重新检查 Seam 是否放错。

### 2.3 Implement

- 先写 contract/fixture regression；
- 实现最小完整纵向行为，不建立未使用的扩展点；
- 依赖从外部注入，不在领域逻辑中创建远程客户端；
- 返回结构化结果，不用日志代替状态；
- 每种失败进入 diagnostic/coverage；
- 更新用户可见功能、命令、数据源或工作流时同步更新根 README。

### 2.4 Verify

执行 [评测与回归体系](./evaluation-and-regression.md) 中受影响矩阵和全量发布门禁。记录命令、退出码、数据版本、性能变化和跳过理由。

### 2.5 Record

创建 progress 记录，更新主控表和下一动作。若领域术语、难逆转决策或论文假设改变，同时更新 CONTEXT、ADR 或研究文档。若出现多进程分支、共享 dispatcher、误导候选、跨阶段义务或漏洞描述与内部实现偏差，按研究案例准入触发器评估；保存当时的 unresolved 状态，不能用最终成功叙事覆盖。

### 2.6 Release

遵守仓库 `AGENTS.md`：

1. 审查 diff 与敏感信息；
2. 提交 intended revision；
3. 推送远端；
4. 确认工作树干净；
5. 运行 `make deploy`；
6. 验证远端 revision、`/api/health`、前端文档和至少一个行为 endpoint；
7. 把远端证据写入 progress 记录或紧随其后的部署记录；
8. 只有全部成功后，主控状态才能改为“已验证”。

常规发布不得使用 `make deploy-with-data`。只有明确需要替换远端情报数据库并具有备份/恢复计划时才允许。

如果用户在当前目标中明确限定某类研究功能“暂不需要 SSH 部署”，该范围内工作项可以在本地全量回归、样本回放、文档、提交和推送后标记已验证；progress 必须将远端标为“不适用（当前用户范围）”。这不改变仓库对其他功能的默认部署规则，也不能被后续会话默认扩大。

## 3. Definition of Done

一个工作项完成需要：

- [ ] 用户目标和非目标已记录；
- [ ] Interface、失败模式和不变量有文档或类型合同；
- [ ] contract/fixture regression 覆盖新行为；
- [ ] 受影响后端测试通过；
- [ ] 前端测试和生产构建通过；
- [ ] 本地 API/浏览器行为已验证；
- [ ] schema、缓存和历史数据兼容性已验证；
- [ ] README/设计/领域/研究文档按影响更新；
- [ ] progress 记录含命令和结果；
- [ ] intended revision 已提交并推送；
- [ ] 从干净工作树完成 `make deploy`，或 progress 已记录用户明确的暂不部署范围；
- [ ] satc_cloud revision、health、frontend 和行为 endpoint 已核验，或远端项已按上述范围标为不适用；
- [ ] 主控状态和下一动作已更新；
- [ ] 未解决问题转换为明确 Obligation 或后续工作项。

少一项都不能称“完成”。

## 4. Progress 记录模板

```markdown
# <日期> <工作项 ID> <标题>

## 结果
一句话说明用户可观察结果，不夸大覆盖范围。

## 范围
- 完成：
- 不包含：

## 设计与决策
- Interface / invariant：
- ADR：

## 实现证据
- Files：
- Schema/analyzer versions：

## 回归证据
| 检查 | 命令 | 结果 |
| --- | --- | --- |

## 发布证据
- Commit：
- Push：
- satc_cloud release：
- Health/frontend/behavior：

## 覆盖缺口与未决义务
- ...

## 下一动作
- <work item id>
```

## 5. 文档影响矩阵

| 变化 | 必须检查的文档 |
| --- | --- |
| 新领域术语或语义改变 | `CONTEXT.md`、domain model |
| 难逆转架构决定 | ADR、architecture、master summary |
| Module Interface 改变 | architecture、integration、contract tests |
| 用户功能/命令/工作流改变 | root README、integration、product scope |
| producer/证据能力改变 | domain model、architecture、evaluation |
| schema/持久化改变 | architecture、integration、migration tests |
| 论文假设/指标改变 | theory、evaluation、dataset manifest |
| 复杂架构或跨阶段义务 | research casebook、机器可读 case corpus、progress |
| 里程碑状态改变 | master、progress record |
| 部署方式改变 | `AGENTS.md`、`deploy/README.md` |

## 6. 回归节奏

- 每个工作项：目标 contract/fixture tests；
- 每个合并前变更：后端全量、前端测试、生产构建；
- 每个较大功能：固定 benchmark smoke、迁移、API 和浏览器纵向回归；
- 每个里程碑：完整标注集评测、性能基线、文档与证据审计；
- 每次发布：satc_cloud revision/health/frontend/behavior；
- 每次 analyzer/schema 版本升级：旧 Snapshot 可读性和重算差异审计。

## 7. 多会话并行规则

- 工作项按 ID 分配，避免两会话同时修改同一 Module Interface；
- 每个进行中工作项在主控表中标明，不使用只存在于聊天中的占用信息；
- 并行 producer 可以独立开发，但 EvidenceAtom 和 Snapshot 合同由单一工作项维护；
- 发现依赖冲突时暂停实现，在 progress 记录中写明并调整主控依赖；
- 不让 Agent 总结替代源文件、测试或 Git 状态；新会话以仓库证据为准；
- 不覆写用户或其他会话的未提交修改；必须先分离工作树或协调工作项。

## 8. 决策纪律

创建 ADR 需要同时满足：难以逆转、未来读者会疑惑、存在真实取舍。以下不需要 ADR：函数命名、单个 parser 库、小型 UI 布局和易替换优化。

设计新 Seam 前必须回答：

1. 什么行为真的会变化？
2. 至少有哪两个 Adapter？
3. 调用者因此少知道了什么？
4. 测试是否通过同一 Interface？
5. 删除这个 Module 后，复杂度会不会扩散回多个调用者？

无法回答时，不新增抽象。

## 9. 论文实验纪律

- 实验配置、数据 manifest、工具和 prompt 版本均进入结果；
- 负结果和失败类型保留；
- 在运行主实验前冻结指标与切分；
- 目标 PoC/补丁后验不得进入冷启动条件；
- 工程缓存不能跨越实验隔离边界；
- 每个表格数字可由脚本从原始结果重新生成；
- 产品演示案例不能替代独立测试集。
