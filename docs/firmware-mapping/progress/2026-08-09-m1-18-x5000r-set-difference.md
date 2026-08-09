# M1-18：X5000R 前端 / Native 集合差异归因

> 日期：2026-08-09  
> 范围：集合差异归因、Discovery Catalog、Research Case、Console 查询  
> 样本：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

## 1. 问题与边界

M1-16 在四张 MIPS inline table 中证明了 123/199 个前端 selector 的 handler
binding，同时留下 76 个 Frontend-only 与 14 个 Native-only operation。差集不是
噪声：它可能暴露前端扫描范围不全、仅声明未消费的 wrapper、另一执行主体、版本漂移
或无 UI 的原生注册。但字符串相似、同固件共现或路径风格都不能单独证明这些原因。

本轮公开 Interface 为：

```python
attribute_frontend_native_set_difference(
    frontend,
    native_inventory,
    artifacts,
    policy=SetDifferencePolicy(),
) -> SetDifferenceAttributionResult
```

它只读取已经发布的 Frontend Asset Graph、Native binding inventory 和有界辅助制品；
保留上游 EvidenceAtom，新增精确 token 或变体 token 的定位证据，不生成 handler binding。

## 2. 真实结果

扫描 94 个 UTF-8 Web 辅助制品和 226 个辅助 ELF，共处理 24,586,858 bytes：

| 差集侧 | 归因类别 | 数量 | 含义 |
| --- | --- | ---: | --- |
| Frontend-only | `frontend_consumer_native_absent` | 38 | operation 被其他功能页面精确消费，但 dispatcher 无注册 |
| Frontend-only | `frontend_declaration_native_absent` | 38 | 只在 wrapper 中声明，未发现辅助消费者或 native 注册 |
| Native-only | `frontend_scope_gap` | 3 | `wan_ie.html` / `advance/config.html` 有精确引用，原三文件图范围不足 |
| Native-only | `cross_native_token_variant` | 1 | `loginAuth` 仅作为 `userloginAuth` 的后缀变体出现 |
| Native-only | `native_registration_no_frontend_reference` | 10 | 有 native 注册，但辅助前端范围无精确引用 |

代表证据包括：`getDosCfg` 在 `www/advance/dos.html` 的消费、`getWanIeCfg` 在
`www/wan_ie.html` 的范围缺口，以及 `usr/sbin/lighttpd` 中的 `userloginAuth` 变体。
最初探索性的 substring 扫描会把最后一项误写成 exact；正式实现使用 identifier
boundary，并把 suffix variant 放入独立类别。这一负例对论文同样重要。

## 3. 解释规则

- exact auxiliary occurrence 只能证明“该制品提及/消费 token”，不能证明运行时可达；
- native-only exact Web reference 可关闭“差集形状未知”，但会创建“扩展一等前端范围”义务；
- wrapper-only 不能直接解释成 dead code；
- suffix、prefix 或大小写变体不得冒充 exact token；
- 来源摘要不一致、非法 UTF-8、预算耗尽或上游不完整时，结果降级为 `partial`；
- 任何类别都不会自动发布 `binds_handler`。

## 4. 系统投影与论文价值

Discovery Catalog 新增 `set_difference_attribution` candidate 和 producer coverage，
X5000R 当前发布 679 candidates / 1,580 EvidenceAtoms，其中 90 个差异归因候选可按
token、类别、来源与开放义务查询。Console 增加“集合差异”筛选，详情继续由服务端
投影证据，不在浏览器重新推断。

Research Case 新增第 7 阶段：关闭“76/14 差集形状”义务，同时保留剩余 selector 的
运行时原因、三个前端范围扩展、CFG-aware value-flow 等义务。论文可用它说明：只有将
页面声明、真实消费者、Web 配置、dispatcher 表和其他二进制共同测绘，才能区分
“接口未实现”“扫描范围不全”“另一 native 变体”等不同现象；不能只凭接口名称或
同一固件归档强行合并后端架构。

## 5. 中间产物与重放

- [集合差异机器报告](../samples/m1-18-x5000r-set-difference.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_set_difference_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
```

## 6. 遗留义务

1. 把 `wan_ie.html` 与 `advance/config.html` 纳入可配置的一等 Frontend Asset Graph；
2. 对 38 个 consumer/native-absent 与 38 个 declaration-only operation 分别验证版本、
   条件构建、死 UI 或替代执行主体假设；
3. 对 10 个无前端引用的 native registration 查找运行时调用、协议入口或生成式客户端；
4. 在确定性 Profile 无法重放跨块/跨函数 witness 时启用隔离 Ghidra Candidate Worker。

## 7. 验证记录

- `git diff --check` 与 Python `compileall` 通过；
- Python 全量 296/296；Console 9 个测试文件 17/17；TypeScript check 与 Vite
  production build（1800 modules）通过；
- 40 个 Markdown 文件的本地相对链接检查为 0 缺失；
- 临时本地 Catalog API 验证 `/api/health`、前端文档、
  `kind=set_difference_attribution&q=getWanIeCfg` 和候选详情均为 200；详情含 6 个
  EvidenceAtom，覆盖 route/table/handler 与 `www/wan_ie.html` 辅助证据；
- X5000R Catalog ID：
  `discovery-catalog:f710150342045b38e7c1a0b9a57daec377ffb158b5fef19b4fb00f193dcaa61d`。

通信测绘研究按 `AGENTS.md` 的用户例外不部署到 SSH 环境。
