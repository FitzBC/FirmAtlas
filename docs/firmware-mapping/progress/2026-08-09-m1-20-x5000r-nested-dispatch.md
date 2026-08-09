# M1-20：X5000R Multipart Nested Dispatch

> 日期：2026-08-09
> 范围：MIPS CGI Nested Dispatch、Discovery Catalog、Research Case
> 样本：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

## 1. 本轮回答的问题

M1-19 只能证明前端发出：

```text
POST /cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting
Content-Type: multipart/form-data
```

并且 `setUploadSetting` 存在于 `set_handle_t`。两者同时存在并不能证明
`action=upload` 会把请求送到该 handler。本轮从原始 `cstecgi.cgi` ELF 重放中间
控制流，关闭 `obligation:x5000r-upload-mode-owner`，同时继续保留运行时可达与认证
保护义务。

## 2. 已验证的通信路径

| 阶段 | 原始 MIPS 地址 | 已验证事实 |
| --- | ---: | --- |
| Transport mode | `0x0042e5a8` | `strstr(QUERY_STRING, "action=upload")` 的结果控制 upload 分支 |
| Selector extraction | `0x0042e648` | `getNthValueSafe(1, query, "&", ...)` 提取第二个 query segment |
| Multipart parse | `0x0042e660` | `cutUploadFile` 处理上传 body 和文件元数据 |
| Payload construction | `0x0042e768` | 第二段被写入 JSON `topicurl`，随后由 `cJSON_Parse/websGetVar` 读取 |
| Suffix normalization | `0x0042e7d0` | 若 `topicurl` 含 `/`，dispatcher 选择 `/` 后的 operation suffix |
| Table selection | `0x0042e8c0` | `"set"` 分支加载 `set_handle_t` 并逐项 `strncmp` |
| Registration | `0x0044a124` | `setUploadSetting` 表项绑定 executable handler `0x0042bf14` |
| Handler invoke | `0x0042e904` | 匹配表项的 handler pointer 经 `jalr` 调用 |

因此完整的静态通信结构为：

```text
advance/config.html
  action=upload & setting/setUploadSetting
             │
             ▼
cstecgi.cgi main@0x0042e390
  upload mode → second query segment → cutUploadFile
             │
             ▼
JSON topicurl="setting/setUploadSetting"
  slash suffix → "setUploadSetting"
             │
             ▼
set_handle_t entry@0x0044a124
             │
             ▼
handler@0x0042bf14
```

## 3. 新增 Deep Module

公开 Interface：

```python
discover_mips_cgi_nested_dispatch(source, content, anchors, profile, policy)
```

调用者只需提供原始 ELF 与来自前端图的嵌套 selector anchor。Implementation 隐藏：

- ELF dynamic symbol 与 MIPS GOT 解析；
- `main` 内 bounded call-site 与 delay-slot 重放；
- query segment index、delimiter 和寄存器传递验证；
- transport branch、payload、slash normalization 与表循环验证；
- 对既有 MIPS inline table Validator 的精确 handler 复用；
- 六段 EvidenceAtom 捕获、预算、覆盖与失败语义。

Catalog 新增 `native_nested_dispatch` candidate kind。X5000R Catalog 从
694 candidates / 1662 EvidenceAtom 变为 695 / 1668，参数仍为 223；新 Catalog ID：

```text
discovery-catalog:9726c91047dc4b62d0f4ec4bcd6cf40f629e06ddc5020ffcb1471a1e0b2b8b09
```

## 4. 为什么本轮仍不触发 Ghidra

该路径跨越多个基本块，但所需事实都有稳定的 dynamic symbol、GP/GOT call target、
常量参数、条件分支、表符号和 executable handler entry，可由小型 Profile 从原始
ELF 确定性重放。此时运行 Ghidra 只会增加工具与反编译文本信任面。

若其他版本隐藏任一边为无符号函数、间接 factory、不可支持 CFG 或跨函数 high
P-code 数据流，则触发既有 `Ghidra Candidate Worker → Core Validator` seam。Worker
只缩小候选范围，不能单独发布 binding。

## 5. 负例与证据门限

测试不是只断言“发现大于零”，而是分别篡改关键语义：

1. 第二段索引由 `1` 改为 `2`：返回 `selector_extraction_not_proven`；
2. upload match 后的条件分支被清除：返回 `transport_branch_not_proven`；
3. 表项匹配后的间接 `jalr` 被清除：返回 `table_dispatch_not_proven`；
4. 持久化的 table claim 被改为 `other_handle_t`：结果合同拒绝；
5. source digest 不一致：failed；dispatcher 指令预算不足：partial。

这保证 route literal、表项或字符串共现不能绕过真实控制流。

## 6. 研究案例演进

研究案例新增第 9 阶段，关闭：

- `obligation:x5000r-upload-mode-owner`。

并创建两个更准确的开放问题：

- `obligation:x5000r-upload-runtime-reachability`；
- `obligation:x5000r-upload-auth-guard`。

论文中可将此例用于说明：只有固件测绘才能从一个 multipart URL 恢复 transport
mode、operation namespace、真实 dispatcher、表类型、注册位置和 handler；漏洞描述、
路径风格或 strings 搜索都无法独立提供这条结构链。

## 7. 中间产物

- [Nested Dispatch 报告](../samples/m1-20-x5000r-nested-dispatch.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_nested_dispatch_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
```

## 8. 后续义务

1. 恢复 upload 分支之前的认证/授权 guard；
2. 区分静态可达与真实部署运行时可达；
3. 将 HTML script dependency closure 下沉为通用、有预算的 Scope Planner；
4. 继续解释剩余 77/11 差集与 branch-aware parameter-to-sink flow；
5. 在确定性 Profile 不再足够时实现隔离 Ghidra Candidate Worker。

## 9. 验证记录

- Python 全量回归：`311 tests`，全部通过；
- 前端回归：`17 tests`，全部通过；
- TypeScript 检查与 Vite production build：通过，`1800 modules transformed`；
- 本地 HTTP `/api/health` 与 production frontend document：通过；
- Catalog API 查询 `kind=native_nested_dispatch&q=setUploadSetting`：唯一返回
  `mips-nested-dispatch:6ef4b240a7fbeced5979138dcece07993fbabe0b1436008fd3b1b9883730f8ac`，
  detail 精确包含六种证据能力；
- 三个生成物重新执行后 SHA-256 与仓库文件逐字节一致：
  - nested dispatch：`061ab4d96a5bc50bfef0953a67b75c5e8fc9d064798556b775b3b8465a9c19e1`；
  - research cases：`c6f25a17a38bfe005fe47c2322b805c12b9aee02877a2e6685cf1247adb3af48`；
  - representative corpus：`5b5e119a546bd28a2c1094169b3ebc4afb529cb4bcc5c43ce99b47b611cca4db`；
- 本地 Markdown 链接检查与 `git diff --check`：通过；
- SSH 部署：按当前通信测绘研究约定，本里程碑不部署，记为 N/A。
