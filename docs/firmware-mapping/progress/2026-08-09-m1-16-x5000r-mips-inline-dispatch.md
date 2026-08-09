# M1-16：X5000R MIPS Inline Dispatcher 绑定

> 工作项：M1-16
> 范围：Native Deep、X5000R Catalog、Research Case、Ghidra 触发决策
> 部署：通信测绘专项，按仓库例外不执行 SSH 部署

## 1. 为什么本轮不需要先上 Ghidra

M1-15 已恢复 199 个 `topicurl` operation，但只凭字符串仍不能说明哪个 Native
函数处理它们。本轮审计 `www/cgi-bin/cstecgi.cgi` 后发现四个带地址和大小的导出
动态符号：

| 表符号 | 地址 | 大小 | 注册项 |
| --- | ---: | ---: | ---: |
| `get_handle_t` | `0x004490a0` | `0x1034` | 61 |
| `set_handle_t` | `0x0044a0e0` | `0x0d48` | 50 |
| `del_handle_t` | `0x0044ae28` | `0x0374` | 13 |
| `other_handle_t` | `0x0044b19c` | `0x03b8` | 14 |

四张表均严格满足以下 MIPS32 little-endian 布局：

```c
struct route_entry {
    char route[64];
    void (*handler)(...);  // executable ELF address
};                         // 68 bytes
```

因此可以从原始 ELF 独立重放，不需要把反编译文本提升为事实。相邻项目
`../iot_seedintelligentanalysis` 的 string-xref、候选收集、固定流水线、失败空产物和
headless 生命周期仍然适用于下一步 handler value-flow；但本轮遵循“确定性 Profile
足够时不扩大 Ghidra 信任面”的原则。

## 2. 新的 Deep Module Interface

```python
discover_mips_inline_route_bindings(
    source,
    content,
    anchors,
    profile=MipsInlineRouteTableProfile(),
) -> NativeDeepResult
```

一个 binding 必须同时具有四线证据：

1. inline route 字段的 `mentions_endpoint`；
2. `.dynsym` 地址与大小的 `resolves_table_symbol`；
3. 68-byte entry 的 `registers_route`；
4. handler pointer 落入 executable section 的 `binds_handler`。

表大小不整除、非零 padding、非打印 route、handler 非 executable、来源摘要不一致、
非 MIPS32 ELF 或预算超限均 fail closed。部分坏项会产生 `partial`，不会被静默忽略。

## 3. 真实结果与差集

```text
Frontend Asset Graph          Native inline tables
199 unique selectors         138 registrations / 137 unique routes
             \               /
              123 bound selectors
              124 proofs (getTelnetCfg registered twice)

Frontend-only: 76            Native-only: 14
```

代表性绑定：

| selector | table entry | handler |
| --- | ---: | ---: |
| `getInitCfg` | `0x004490a0` | `0x00415454` |
| `getSysStatusCfg` | `0x0044916c` | `0x004166e8` |
| `getWanCfg` | `0x00449854` | `0x0040d080` |
| `setWanCfg` | `0x0044a9a4` | `0x004212cc` |
| `setLanCfg` | `0x0044aa2c` | `0x004209b8` |

76 个 Frontend-only selector 不被解释成“没有功能”；它们可能来自版本错配、条件构建、
死 UI、动态模块或另一处理主体。14 个 Native-only route 同样不能被丢弃，它们可能是
无页面管理动作、上传入口或兼容接口。两组差集已进入机器可读产物和开放义务。

## 4. Catalog 与研究案例

- X5000R Catalog：587 candidates、1438 EvidenceAtom；
- Catalog ID：`discovery-catalog:1b4684ece8017c825445ecb09e427a1541edb00631fe30fcf2d24135b1521870`；
- Corpus report ID：`corpus-report:948b8fcc36daecb6ebe62ddc2335d188904843c91163b109aa07d125e56e8589`；
- X5000R research case 新增 MIPS inline-table 阶段和 `setLanCfg` 四线证据；
- “绑定全部 199 selector 并恢复 value-flow”义务仍为 open，没有用 123/199 的部分
  成功冒充整体闭合。

这个案例可支撑论文中的三组消融：path-only 会把 199 operation 压成一个 URL；
string-only 会把 76/14 差集误写为绑定；缺少 table-symbol/section 验证会把任意相邻
指针误写为 handler。

## 5. 可重复产物与下一步

- [MIPS dispatcher 中间输出](../samples/m1-16-x5000r-mips-dispatch.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)。

重放：

```bash
PYTHONPATH=src python3 scripts/build_x5000r_mips_dispatch_report.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
```

下一步按两个方向推进：

1. 对 76/14 差集做版本、模块和处理主体归因；
2. 从已验证 handler entry 恢复 JSON getter、配置状态和敏感 sink。确定性 MIPS
   Profile 无法重放跨函数 value-flow 时，再实现隔离 Ghidra Candidate Worker。

## 6. 验证记录

- 合成 MIPS ELF 正例、部分坏表负例与真实 X5000R 回放通过；
- 真实中间输出、Corpus 和 Research Case 均由当前 Producer 逐字重建；
- Python 全量 285/285、Console 9 个测试文件 17/17、TypeScript 检查和 Vite
  production build（1800 modules）通过；
- 本地 `/api/health`、前端文档和 `/api/mappings/catalogs` 均返回 200；
- 通信测绘专项按 `AGENTS.md` 例外不执行 SSH 部署。
