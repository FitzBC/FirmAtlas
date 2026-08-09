# Native Deep：Ghidra Worker Adapter 接入设计

> 文档 ID：FM-NATIVE-GHIDRA
> 状态：设计冻结，按需实现
> 参考实现来源：`../iot_seedintelligentanalysis`

> M1-16 触发审计：X5000R dispatcher 由带大小的 MIPS inline route-table 动态符号
> 直接证明，因此未触发 Ghidra。76 个未绑定 frontend selector 和已绑定 handler 的
> 跨函数 value-flow 仍可能成为首个 Ghidra Worker 触发点。

> M1-17 触发审计：本机相邻项目配置所指 Ghidra 12.0.4 已不可用；系统明确记录工具
> 缺失而不伪造候选。`setLanCfg` 首个无分支前缀已由 GP/GOT 确定性 Profile 证明两条
> 参数—状态链，因此该窄范围仍不触发 Ghidra。分支后缀和跨函数 sink 保持触发候选。

> M1-20 触发审计：X5000R `main` 保留 dynamic symbol，upload branch、GP/GOT callee、
> query segment、`cutUploadFile`、JSON topicurl、slash suffix、table loop 与 exact handler
> 均可从原始 MIPS 字节确定性重放，因此仍不触发 Ghidra。缺少这些稳定边的固件变体
> 才进入 Candidate Worker。

> M1-21 触发审计：vendor lighttpd 的 `http_response_write_header`、`userloginAuth` 与
> `checkLoginUser` 都是带边界的 exported dynamic symbol；路径 gate、direct/GOT call、
> `SESSION_ID`、session lookup 和 302 分支可由原始字节重放，因此未触发 Ghidra。
> stripped 变体隐藏函数边界或会话流时，再使用相邻项目思路编写 headless candidate script。

> M1-22 触发审计：`init_router`、`start_services_once`、`start_httpd` 均为 bounded exported symbol，GOT/direct call、argv pointer table、`memcpy → _eval` 参数流及配置文本均可从原始制品确定性重放，因此未触发 Ghidra。stripped init chain、computed argv 或间接 service factory 才进入 Candidate Worker。

AC9 当前 ARM PIC 注册模式已由小型确定性 Validator 从原始 ELF 字节直接证明，
因此没有为了“使用 Ghidra”而增加工具依赖。Ghidra Adapter 只在复杂控制流、间接
调用、跨函数数据流、未知 ISA profile 或参数 getter 追踪确实需要时启动。

## 1. 从相邻项目吸收的做法

只读审查 `../iot_seedintelligentanalysis` 后，值得复用的是：

- `analyzeHeadless` 使用临时 project，导入目标后执行 post-script 并删除 project；
- 结果目录绑定二进制 SHA，而不是依赖文件名；
- 配置驱动目标、预算、分析模式和输出目录；
- 将 route、handler、parameter、graph、fusion report 分层输出；
- `artifact_manifest.json` 保存每个输入/输出的 SHA 与集合 fingerprint；
- provider key 只从环境变量读取，不进入配置、命令行或产物；
- 没有三线证据或 validator 未接受时 fail closed。

不直接复制的部分包括大型自由文本 decompile 后正则替换、厂商特化参数、重复的
表达式重写函数以及“反编译看起来像”即升级结论的逻辑。它们可以产生候选，但不
满足 FirmAtlas EvidenceAtom 的发布门限。

## 2. Deep Module 与两个 Adapter

```text
Scheduler Obligation + NativeRouteAnchor
        ↓
Ghidra Candidate Worker Adapter
        ↓  versioned candidate manifest
Core Native Evidence Validator
        ↓  replay against original ELF
NativeDeepResult + EvidenceAtom + resolved/open obligations
```

Ghidra Worker 不是结论权威。它只枚举候选函数、call-site、xref、P-code value-flow
和可能的 route/handler/parameter 关系。Core Validator 必须使用原始 ELF、加载
地址、section、relocation、指令或 P-code witness 重新核验；无法重放的 decompiler
文本只能保持 candidate。

两个真实 Adapter 才形成 seam：

- 当前 deterministic ARM PIC Adapter：适合已知、可直接验证的注册 Profile；
- 后续 Ghidra headless Adapter：适合复杂控制流和跨函数数据流。

Scheduler 和 Catalog 始终只依赖 `NativeDeepResult`，不需要知道 Ghidra project、
Java/Python script 或反编译器版本。

## 3. Candidate manifest 最小合同

Worker 输出只允许结构化字段：

```json
{
  "schema_version": "firmatlas.mapping.ghidra-candidates/v1alpha1",
  "tool": {"name": "ghidra", "version": "...", "script_sha256": "..."},
  "input": {"artifact_sha256": "...", "language_id": "...", "image_base": "..."},
  "budget": {"timeout_seconds": 0, "max_functions": 0, "max_candidates": 0},
  "anchors": [{"target_ref": "...", "token": "..."}],
  "candidates": [{
    "target_ref": "...",
    "function_entry": "0x...",
    "callsite": "0x...",
    "callee": "0x...",
    "argument_witnesses": [{"slot": "r0", "value_ref": "..."}],
    "xref_addresses": ["0x..."],
    "confidence": "candidate"
  }],
  "coverage": {"status": "completed|partial|failed", "diagnostics": []}
}
```

禁止输出即接受的自由文本 handler 结论。所有地址必须绑定 image base 与原始 Artifact
SHA；超时、反编译失败、函数预算耗尽必须进入 coverage。

## 4. 分析脚本建议

首批脚本按能力拆分，而不是写一个无限扩张的总脚本：

1. `ExportStringXrefs.py`：route/selector 字符串的 data/code xref；
2. `ExportRegistrarCandidates.py`：同一 callee 的多组稳定参数形态；
3. `ExportHandlerValueFlow.py`：从 call argument 向 function pointer/relocation 回溯；
4. `ExportParameterGetters.py`：从已确认 handler 搜索 query/form/json getter 与 key；
5. `ExportCallGraphSlice.py`：在预算内导出 handler 周围的调用图切片。

每个脚本只产生 candidate manifest，Core Validator 分别实现可接受的 profile。这样
脚本更新不会静默改变已发布事实，旧结果可由 tool/script SHA 重放。

## 5. 安全与可复现约束

- Ghidra 在独立 Worker 进程运行，不嵌入 API 进程；
- project/output 使用任务专用临时目录，禁止跟随固件路径写入；
- 固定 Ghidra 版本、语言 ID、loader options、script SHA 和 auto-analysis 配置；
- 限制时间、内存、函数数、反编译数、xref 与候选数量；
- stdout/stderr 是诊断，不是证据；
- 不执行固件二进制，不加载固件内插件；
- LLM 可解释已验证候选或规划下一义务，但不能创造地址、xref 或 binding；
- MiniMax key 只通过环境变量注入未来业务 Adapter，永不写入 manifest。

## 6. 实现触发条件与首个验证样本

当一个真实样本满足以下任一条件时进入实现，而不是预先制造复杂性：

- 当前 ISA/Profile 不支持且 shallow 已定位多个候选；
- route 与 handler 跨基本块或跨函数传播；
- handler 通过间接表、factory 或多级函数指针取得；
- 参数 getter 需要反编译器 high P-code 才能稳定跟踪；
- 现有 Validator 保持 open obligation，且 Ghidra candidate 能明显缩小验证范围。

首个样本必须同时准备正例、被篡改的地址/xref 负例、超时/partial coverage 以及另一
二进制的误候选。只有 Worker candidate 和 Core Validator 两端测试都通过，才能
关闭 Scheduler obligation。
