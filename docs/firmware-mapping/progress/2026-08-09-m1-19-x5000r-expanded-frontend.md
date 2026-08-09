# M1-19：X5000R 前端范围扩展与嵌套 Selector

> 日期：2026-08-09  
> 范围：Frontend Asset Graph、集合差异、Discovery Catalog、Research Case  
> 样本：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

> 后续状态：M1-20 已从原始 MIPS `main` 重放 upload mode、第二 query segment、
> `cutUploadFile`、slash suffix、`set_handle_t` 与 exact handler，关闭本记录创建的
> upload-mode owner 义务；本记录仍作为前端范围扩展基线保留。

## 1. 从差集归因返回 Producer

M1-18 将 14 个 Native-only operation 中的三个精确引用归为 `frontend_scope_gap`：
`getWanIeCfg`、`setWanIeCfg` 和 `setUploadSetting`。本轮没有简单地从差集中删除它们，
而是把引用页面加入 Frontend Asset Graph，要求 Producer 重新证明 endpoint、method、
representation、selector 和来源位置。

最初的三文件范围为 `config.js + config_ie.js + topicurl.js`。扩展范围加入：

- `kr.js`：证明 `kr.request` 的缺省 endpoint；
- `wan_ie.html`：包含显式读取与按 WAN 模式分支构造的写入 payload；
- `advance/config.html`：包含配置恢复上传 URL 与 `fileUpload` 消费点。

## 2. 三种不同请求架构

```text
getWanIeCfg
  wan_ie.html
  → kr.request({url:"/cgi-bin/cstecgi.cgi", data:{...}})
  → direct literal endpoint + JSON selector

setWanIeCfg
  wan_ie.html branch payload e={topicurl:"setWanIeCfg", ...}
  → kr.request({data:e})
  → kr.js options.url || "/cgi-bin/cstecgi.cgi"
  → cross-resource default endpoint + payload-variable selector

setUploadSetting
  advance/config.html importAction=
    "/cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting"
  → upload.fileUpload({data:file, url:this.importAction})
  → POST multipart_form
  → outer selector action=upload
  → inner selector setting=setUploadSetting
```

这三条链共享物理 CGI，但不是同一种通信结构。尤其不能把 `action=upload` 与
`setUploadSetting` 压成一个 selector：后者存在于 MIPS `set_handle_t`，前者不在该表中，
其 upload-mode 处理主体在 M1-19 时仍是开放义务；后续 M1-20 已用原始 ELF 六段
确定性证据关闭静态 owner，运行时可达与认证 guard 仍开放。

## 3. Interface 与证据规则

本轮没有增加新的公开 Interface，继续深化：

```python
discover_frontend_asset_graph(assets, policy) -> FrontendAssetGraphResult
attribute_frontend_native_set_difference(frontend, native, artifacts, policy)
```

Asset Graph Implementation 新增两类确定性构造：

1. `custom.request.cross-resource-default`：只有同时证明 constructor 的 request 默认
   URL、全局 receiver 实例化、实际 `.request(...)` 调用和同一函数作用域内到达调用点的
   object-literal payload，才发布请求；
2. `custom.file-upload-property`：只有 URL 属性被 `.fileUpload({data, url:this.x})`
   实际消费且属性值唯一时，才发布 multipart request，并分别保存等号型和斜杠型 query
   selector。

同名 payload 不得跨函数拼接；缺少 `data` 的 fileUpload 调用不得发布请求。默认 URL
定义和页面消费各自保存 EvidenceAtom，路径共现或字符串包含不能替代 binding。

## 4. 真实结果与变化

| 指标 | M1-18 三文件范围 | M1-19 扩展范围 |
| --- | ---: | ---: |
| 一等前端 operation | 199 | 203 |
| Frontend-only | 76 | 77 |
| Native-only | 14 | 11 |
| `frontend_scope_gap` | 3 | 0 |
| Asset Graph binding | 1 | 2 |

新增四个唯一 operation 是 `getWanIeCfg`、`setWanIeCfg`、`setUploadSetting` 和外层
`upload`。前三个关闭原范围缺口；`upload` 成为新的 Frontend-only operation，并在辅助
Native 制品中有 exact literal，因此保持“alternate native literal”候选，不能强行映射到
inline topicurl table。

扩展后的 X5000R Discovery Catalog 发布 694 candidates、223 parameters、1,662 个
EvidenceAtoms；新增页面请求还使 targeted Native binding 投影能够保留多种 frontend
request shape 指向同一 native registration 的独立关系证据。

## 5. 论文案例价值

这个阶段可以支持两个方法学结论：

1. 差集不是最终统计，而是反向驱动范围和 Producer 改进的反馈信号；若只把三个 token
   从 Native-only 表中手工删除，就无法知道它们分别经过显式 URL、缺省 URL 和上传 URL；
2. 同一 CGI 字符串可以同时承载外层 transport mode 与内层业务 operation。扁平化 URL
   或按路径风格聚类会掩盖真正需要分析的 dispatcher 层级和二进制目标。

## 6. 中间产物与重放

- [M1-19 扩展前端机器报告](../samples/m1-19-x5000r-expanded-frontend.json)；
- [M1-18 差集归因基线](../samples/m1-18-x5000r-set-difference.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_expanded_frontend_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
```

## 7. 遗留义务

1. 追踪 `action=upload` 的外层 dispatcher 与 `setUploadSetting` 的控制流连接；
2. 对扩展后的 77 个 Frontend-only 与 11 个 Native-only operation 继续做版本、条件构建、
   其他执行主体和运行时可达验证；
3. 将 HTML script dependency closure 从样本编排 Adapter 下沉为有预算的通用分析范围
   Planner，避免未来样本依赖手工路径清单；
4. CFG / 间接调用超出确定性 Profile 时，再启用隔离 Ghidra Candidate Worker。

## 8. 验证记录

- Python 编译检查通过：`PYTHONPATH=src python3 -m compileall -q src scripts`；
- 全量 Python 回归通过：302/302；
- Console 回归通过：9 个测试文件、17/17；
- TypeScript 检查与生产构建通过，Vite 转换 1800 个模块；
- 扩展样本、研究案例 Corpus 与代表性 Corpus 均可由脚本确定性重放；
- 本地发布 Catalog
  `discovery-catalog:5cd309241c052af440c18bac88a8e627b4241b821064e4f3a08bced1b7d85c0c`，
  得到 694 个候选、223 个参数和 1662 个 EvidenceAtom；
- 本地 `/api/health`、生产前端文档、Catalog 列表均返回 HTTP 200；
- `kind=native_route_binding&q=setUploadSetting` 返回唯一受支持绑定，详情聚合
  4 个 EvidenceAtom；
- `kind=set_difference_attribution&q=upload` 保留精确的
  `alternate_native_literal` 归因，没有将外层 upload mode 伪装成已验证 handler。

通信测绘研究按当前用户约定不部署到 SSH 环境，本轮部署记为 N/A。
