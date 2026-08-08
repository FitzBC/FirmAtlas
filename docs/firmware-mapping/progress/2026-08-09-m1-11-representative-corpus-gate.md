# M1-11：代表性通信架构 Corpus Gate

> 工作项：M1-11
> 日期：2026-08-09
> 状态：进行中
> 当前 gate：`partial`

## 1. 为什么需要独立 Gate

此前 `/goform`、HNAP/SOAP、共享 CGI、脚本后端和 Native route 的验证分散在 Producer fixture、真实源文件与漏洞候选中。若只统计“测试出现过”，合成 fixture、旧 Binwalk 目录和漏洞文本很容易被误报成真实固件覆盖。

本轮新增 `build_corpus_report(CorpusReportInput) -> CorpusReport`，以 Discovery Catalog 为事实输入，并将研究样本定义限制为类别、角色和能力门限。类别是研究分层标签，不是从路径风格自动推断的实现同源结论。

## 2. 证据层级与晋级条件

| 层级 | 含义 | 能否使类别 verified |
| --- | --- | --- |
| `real_firmware` | 已知 Firmware Artifact SHA 与 Catalog 身份一致 | 满足全部门限时可以 |
| `derived_firmware` | 真实派生源码，但原始制品或当前解包谱系不完整 | 不可以 |
| `contract_fixture` | 验证语法与身份模型的合成输入 | 不可以 |
| `external_lead` | 漏洞文本或样本候选提供的获取线索 | 不可以 |

Real firmware 还必须同时满足：Catalog coverage completed、required capabilities 全部存在、forbidden capabilities 全部缺席、0 open obligations。required category 即使没有任何样本，也会保留为 `acquisition_gap`。

## 3. 当前机器可读结果

可重复命令：

```bash
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py \
  --ac9-root ../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root
```

输出：[M1-11 corpus report](../samples/m1-11-representative-corpus-report.json)，稳定身份为 `corpus-report:f266dd3578426395806815d00223d49dbc484431be3656da00920c9c95853d52`。该身份同时绑定完整 required/forbidden capability policy；修改已满足的门限也会产生新报告身份。

| 类别 | 当前状态 | 解释 |
| --- | --- | --- |
| `form_handler` | `verified` | AC9 真实制品身份；374 candidates、392 evidence、0 open obligations，包含 `constructs_request` 与 `binds_handler` |
| `hnap_soap` | `contract_only` | HNAP/SOAPAction fixture 证明 operation selector 身份，不是固件召回证据 |
| `cgi_gateway` | `contract_only` | shared CGI/topicurl fixture 证明共享端点拆分，不是固件召回证据 |
| `script_backend` | `coverage_gap` | D-Link DSL 旧 Binwalk 派生源码已有 Producer 结果，但缺原始制品身份绑定后的 Catalog |
| `native_only` | `acquisition_gap` | 尚缺不依赖前端候选的可校验原始样本 |

因此当前总 gate 必须保持 `partial`。

## 4. TDD 与审查修正

公开 Interface 当前覆盖：真实样本晋级、fixture/lead 不抬高、派生源码不抬高、能力缺失/禁止能力、Artifact SHA mismatch、开放义务阻断、缺失 required category 可见性和确定性 report identity。

代码审查额外收紧了三个容易抬高结果的条件：real firmware 必须声明预期 Artifact SHA；只要 Catalog 仍有开放义务，样本即为 coverage gap；report identity 必须绑定完整 required/forbidden capability policy，而不只绑定缺失结果。报告 orchestration 保留在 `scripts/` Adapter，核心 Module 不认识 AC9、HNAP 或任何具体路径。

## 5. 下一步

1. 用生产隔离 Binwalk Worker 摄取一个原始 HNAP 或共享 CGI 固件，固定工具版本与派生谱系；
2. 发布其完整 Discovery Catalog，使对应类别从 `contract_only` 晋级或暴露真实误差；
3. 选择一个前端缺失的 Native-only 原始固件，验证无 frontend seed 的发现链；
4. 三个缺口全部关闭后再运行 M1-GATE，不因当前已有 AC9 成功而提前标记 M1 完成。

## 6. 本轮验证

- Corpus Report 合同与真实 AC9 重放：11 项通过；
- Python 全量回归：228 项通过；
- Console：9 个测试文件、17 项通过；
- TypeScript 检查与 Vite 生产构建通过，1800 modules；
- Python 编译、JSON 解析、`git diff --check` 通过；
- 脚本重放结果与记录 JSON 完全一致，report ID 稳定；
- 本地 `GET /api/health` 返回 200，生产前端文档 GET 返回 200；
- 本轮没有 UI 行为变化，浏览器交互验收不适用。

实现修订为 `c1317a0`。通信测绘专项按用户明确范围不执行 SSH 部署。
