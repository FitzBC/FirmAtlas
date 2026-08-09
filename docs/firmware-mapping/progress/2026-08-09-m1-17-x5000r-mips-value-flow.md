# M1-17：X5000R `setLanCfg` 参数—配置状态链

> 日期：2026-08-09
> 范围：Native Value Flow、Discovery Catalog、Research Case、Ghidra 触发审计
> 样本：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

## 1. 问题与边界

M1-16 已证明 `set_handle_t` 表项 `0x0044aa2c` 将 `setLanCfg` 绑定到
`www/cgi-bin/cstecgi.cgi@0x004209b8`，但“哪个请求字段由哪个函数读取、最终写入
哪个配置键”仍是开放义务。仅知道 handler 地址仍不足以描述功能模块，更不能据此
声称危险数据流或漏洞存在。

本轮只分析 handler 的**首个无分支指令前缀**。扫描到 `0x00420ad8` 的第一个条件
分支立即停止；DHCP 分支、commit、网络重配置和敏感 sink 均保持未决。这个边界是
Profile 的组成部分，不是分析失败。

## 2. 深模块 Interface

公开入口为：

```python
discover_mips_handler_value_flows(
    source,
    content,
    handler_address,
    profile=MipsHandlerValueFlowProfile(),
    policy=MipsHandlerValueFlowPolicy(),
) -> MipsHandlerValueFlowResult
```

实现从原始 MIPS32 ELF 重放：

1. `.dynamic` 中的 `DT_PLTGOT`、`DT_MIPS_LOCAL_GOTNO`、
   `DT_MIPS_SYMTABNO`、`DT_MIPS_GOTSYM`；
2. local/global GOT slot 到 defined/undefined dynamic symbol 的映射；
3. `lui/addiu` 常量、stack-relative GP 保存/恢复和 MIPS caller-saved 寄存器；
4. `jalr` delay slot、`websGetVar` 返回值到 saved register 的 provenance；
5. 同一 provenance 作为 `nvram_set` 的值参数时，发布参数—状态映射。

每条映射要求五段 EvidenceAtom：参数字面量、getter 调用、状态键字面量、setter
调用、确定性映射。来源摘要不匹配、GOT 元数据异常、handler 非 executable、预算
耗尽或 delay slot 截断均 fail closed。

## 3. 真实结果

```text
set_handle_t[setLanCfg]
  → handler 0x004209b8
  → websGetVar("lanIp")      @ 0x00420a54
  → nvram_set("lan_ipaddr") @ 0x00420a8c

  → websGetVar("lanNetmask")  @ 0x00420a74
  → nvram_set("lan_netmask")  @ 0x00420aa0

  → first conditional branch @ 0x00420ad8
  → stop; branched suffix remains open
```

结果为 `completed`，含义仅是
`mips32-gp-straight-line-getter-setter/v1` 的 72 条指令范围完整结束于声明的控制流
边界。两条 flow 共发布 10 个可逐字重放的 EvidenceAtom。

Discovery Catalog 新增 `native_value_flow` Producer batch 与
`native_parameter_state_flow` supported candidate。X5000R Catalog 因此从 587/1438
更新为 589 candidates / 1448 EvidenceAtoms；查询层可以直接展示 `lanIp →
lan_ipaddr` 和 `lanNetmask → lan_netmask`，无需 UI 再推断。

## 4. Ghidra 触发审计

按用户建议只读学习了 `../iot_seedintelligentanalysis` 的 xref、decompile、string
literal 和临时 project 思路。相邻项目配置指向的 Ghidra 12.0.4 当前在本机已不存在，
因此不会把旧配置当作可用工具，也不会生成伪候选。

本轮目标位于一个可由小型确定性 Profile 完整重放的无分支前缀，故没有为使用工具而
恢复大型运行时。Ghidra Candidate Worker 仍适用于下一阶段的分支合流、跨函数调用图
和敏感 sink；其输出只能缩小候选范围，核心 Validator 仍须重放原始 ELF。

## 5. 中间产物与重放

- [M1-17 机器报告](../samples/m1-17-x5000r-mips-value-flow.json)；
- [M1-16 dispatcher 报告](../samples/m1-16-x5000r-mips-dispatch.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_mips_value_flow_report.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
```

## 6. 论文使用与局限

这个切片可以支撑“接口路径或 handler ownership 仍不足以恢复真实功能”的实例：同一
`setLanCfg` operation 内，必须继续识别 getter ABI、请求字段、配置状态键和控制流
边界。它也提供一个负面方法学案例：若线性扫描越过 `0x00420ad8`，就可能把互斥的
DHCP 分支拼成不存在的路径。

不能从两条映射声称运行时可达、认证状态、commit 行为、命令执行、漏洞存在或整个
`setLanCfg` 已完成分析。

## 7. 遗留义务

1. 对 76 个 Frontend-only 与 14 个 Native-only operation 做版本/模块归因；
2. 为 `setLanCfg` 分支后缀构建 CFG-aware provenance，恢复 DHCP 状态和 commit/
   network/sensitive sink；
3. 确定性 Profile 无法重放跨块或跨函数 witness 时，实现隔离 Ghidra Candidate
   Worker，并准备地址/xref/预算篡改负例。

## 8. 验证记录

- 合成 ELF 正例、source mismatch、instruction budget 和未知寄存器变换负例通过；
- 真实 X5000R 机器报告、Catalog、Corpus Report 与 Research Case 可逐字重建；
- Python 全量 291/291；Console 9 个测试文件 17/17；TypeScript check 与 Vite
  production build（1800 modules）通过；
- 临时本地 Catalog API 验证：`/api/health`、前端文档、
  `kind=native_parameter_state_flow` 查询和含 5 个 EvidenceAtom 的候选详情均为 200；
- 本地 X5000R Catalog ID：
  `discovery-catalog:0416439303aa0adf65a8281e1c6881e7376ca26436050d6406a9e8e780d1d257`。

通信测绘研究按 `AGENTS.md` 的用户例外不部署到 SSH 环境。
