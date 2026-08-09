# M1-15：X5000R 跨资源 Frontend Asset Graph

> 工作项：M1-15
> 范围：Frontend Asset Graph、X5000R Catalog、Research Case
> 部署：通信测绘专项，按仓库例外不执行 SSH 部署

## 1. 关闭的义务

M1-14 只在 `config_ie.js` 中恢复到少量完整字面请求；真实 wrapper 的 endpoint
定义和 operation 消费分别位于：

```text
www/static/js/config.js
  globalConfig.cgiUrl = /cgi-bin/cstecgi.cgi
                    │
                    ▼ resolves_endpoint_binding
www/static/js/topicurl.js
  this.srcUrl = globalConfig.cgiUrl
  data.topicurl = this.topicurl
  JSON.stringify(data) → $.ajax(...)
                    │
                    ▼
  199 个 prototype operation selector
```

本轮新增公共 seam：

```python
discover_frontend_asset_graph(
    tuple[FrontendAssetInput, ...]
) -> FrontendAssetGraphResult
```

它只在符号定义唯一、wrapper 合同完整且来源均为 coverage completed 时解析绑定；
冲突定义返回 `partial + frontend.asset_symbol_conflict`，注释、字符串、模板和正则
表达式中的赋值形文本不构成定义。定义证据仍定位 `config.js`，请求构造和 selector
证据仍定位 `topicurl.js`，没有把两份来源压成一个不可审计结论。

## 2. X5000R 结果

- `globalConfig.cgiUrl → /cgi-bin/cstecgi.cgi`：1 个跨资源 binding；
- `topicurl.js`：199 个静态枚举 operation，包括 `getSysStatusCfg`、`getWanCfg`、
  `setWanCfg`、`setLanCfg` 等；
- Catalog：339 candidates、942 EvidenceAtom、0 Catalog scheduler obligation；
- Catalog ID：`discovery-catalog:04b1857d52280928a10cf0107af881eb866a827290f539d053f350bc34b8f804`；
- Corpus report ID：`corpus-report:a48d28f7b752db86dfe6183bb3627aca165d05736b1c178eec261eeb1312e4b3`。

真实 wrapper 使用 `type:this.type`，因此 199 个 operation 的 `method` 均保持
`null / unresolved_dynamic`。恢复 endpoint 和 selector 并不授权系统猜测 GET 或 POST。

## 3. 研究案例演进

案例时间线保留 M1-14 的初始未知，并新增后续阶段：

1. shared CGI、lighttpd CGI namespace 和 MIPS `cstecgi.cgi` 目标已建立；
2. 创建跨资源 endpoint 义务；
3. Asset Graph 以定义端和消费端两处 EvidenceAtom 关闭该义务；
4. 创建并继续保留 selector → Native handler/value-flow 义务。

这可用于论文说明“动作面恢复”和“后端 handler 定位”是两个不同证明层级：不做
跨资源测绘会漏掉 199 个逻辑操作；只做前端测绘仍不能指出每个操作在 MIPS 二进制
中的具体处理函数。下一阶段应先尝试确定性 MIPS dispatcher Profile，无法充分验证时
再触发隔离 Ghidra Candidate Worker。

## 4. 可重复产物

- [Frontend Asset Graph 中间输出](../samples/m1-15-x5000r-frontend-asset-graph.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)。

重放：

```bash
PYTHONPATH=src python3 scripts/build_x5000r_frontend_asset_graph.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
```

## 5. 验证记录

- 跨资源正例、冲突定义和注释/字符串/正则误识别负例均通过；
- 真实 X5000R 199-operation 输出与仓库 JSON 逐字重放；
- Corpus 和 Research Case 引用均由当前 Producer EvidenceAtom 重放；
- Python 全量 279/279、Console 9 个测试文件 17/17、TypeScript 检查和 Vite
  production build（1800 modules）通过；
- 本地 `/api/health`、前端文档和 `/api/mappings/catalogs` 均返回 200；
- 通信测绘专项按 `AGENTS.md` 例外不执行 SSH 部署。
