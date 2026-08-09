# M1-22：X5000R 静态初始化与服务装配

> 日期：2026-08-09
> 范围：MIPS Service Assembly、Discovery Catalog、Research Case
> 样本：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

## 1. 研究问题

M1-21 已证明 `usr/sbin/lighttpd` 的静态请求保护范围，但仅凭配置文件和一个服务器二进制仍不能说明固件会选择这条服务链。本轮从系统初始化入口出发，恢复服务启动函数、实际 argv、配置、listener、document root、CGI namespace 和最终请求处理制品之间的静态装配关系。

## 2. 已验证结构

| 阶段 | 制品 / 地址 | 已验证事实 |
| --- | --- | --- |
| 初始化入口 | `sbin/rc:init_router@0x0040850c` | 经 GOT 在 `0x00408f1c` 调用 `start_services_once` |
| 服务组调度 | `start_services_once@0x0040b644` | 在 `0x0040b6b0` 直接调用 `start_httpd` |
| argv 构造 | `start_httpd@0x0040aadc` | 从 `0x00457314` 构造 `/usr/sbin/lighttpd -f /lighttp/lighttpd.conf` |
| 启动调用 | `0x0040ab24` | argv 作为参数进入 `_eval` |
| 配置解析 | `lighttp/lighttpd.conf` | listener `80/8080`、document root `/www/`、CGI namespace `/cgi-bin/` |
| 请求主体 | `www/cgi-bin/cstecgi.cgi` | namespace 目标解析为同一固件内的 MIPS ELF |

```text
sbin/rc:init_router
  └─ start_services_once
      └─ start_httpd
          └─ _eval([/usr/sbin/lighttpd, -f, /lighttp/lighttpd.conf])
              └─ :80/:8080 → /www/ → /cgi-bin/ → www/cgi-bin/cstecgi.cgi
```

这是一条跨三个制品的静态服务装配证明，不是启动成功、网络可达或认证状态证明。

## 3. 公开 Interface 与证据合同

```python
discover_mips_service_assembly(artifacts, anchors, profile, policy)
```

结果 `firmatlas.mapping.mips-service-assembly-result/v1alpha1` 要求十一类 EvidenceAtom 同时成立：进入服务 bootstrap、调度 service launcher、定义与排序 argv、调用 launcher、解析 server artifact、加载配置、暴露 listener、映射 document root、绑定 CGI namespace、解析请求处理制品。任何一段缺失时都不能发布 completed assembly。

结果显式固定 `runtime_reachability_verified=false`。Discovery Catalog 新增 `native_service_assembly` candidate，并验证 server 与 request target 的引用完整性。X5000R Catalog 当前为 697 candidates / 223 parameters / 1684 EvidenceAtom，coverage completed。

## 4. TDD 与失败边界

合同测试先以缺失公开 import、Catalog projection 和报告脚本进入 red，再实现最小生产能力进入 green。破坏性负例覆盖：

1. CGI namespace 被改写，目标解析失败；
2. 请求主体缺失或 source digest 不一致；
3. argv table 被破坏或指令预算不足；
4. 结果被篡改为 `runtime_reachability_verified=true` 时合同拒绝；
5. 报告与 Research Case 必须从冻结制品逐字重放。

因此配置文本、二进制字符串、函数名和 `_eval` import 均不能单独构成服务装配事实。

## 5. Ghidra 决策

本轮沿用 `../iot_seedintelligentanalysis` 的分层思路：复杂、stripped 或间接控制流进入 Ghidra Candidate Worker，核心只接受可从原始 ELF 重放的结构化候选。本样本三个关键函数均有 bounded dynamic symbol，GOT/direct call、argv pointer table 与 `_eval` 参数流可确定性解码，因此没有伪造 Ghidra 结果，也没有扩大依赖面。后续遇到 stripped init、computed argv 或 service factory 时再触发 Ghidra/P-code。

## 6. 论文价值与边界

该例把“观察到 `/cgi-bin/cstecgi.cgi`”提升为可审计的系统结构：初始化代码选择 lighttpd，lighttpd 使用哪份配置，配置把哪个 namespace 映射到哪个实际 ELF。没有这条链，就无法确定后续应该分析 `sbin/rc`、`usr/sbin/lighttpd` 还是 `www/cgi-bin/cstecgi.cgi`，也无法区分配置残留与固件选择的服务结构。

它可用于跨制品通信结构图、strings-only/config-only 消融，以及“先测绘、再选择漏洞分析主体”的案例。不能据此声称真实设备完成启动、端口对外开放、请求一定到达 CGI、认证缺失或漏洞可利用。

## 7. 中间产物

- [静态服务装配报告](../samples/m1-22-x5000r-service-assembly.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_service_assembly_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
```

## 8. 后续义务

1. 将 `native registration − completed frontend scope` 的 10 个 X5000R 项投影为“潜在隐藏接口”，并扩展到所有已测绘固件；
2. 为候选保存固件、二进制、注册/handler、前端覆盖、差集证据和未决运行时原因；
3. 在通信测绘工作区增加跨固件统计、分布、版本对照和逐级证据下钻；
4. 真实运行时进程、监听、请求生命周期与外部中介仍作为独立验证层。

“潜在隐藏接口”只描述高价值静态证据形状，不等于后门、可达接口或漏洞。

## 9. 验证记录

- 专项合同：service-assembly、request-protection、research-case、corpus-report 共 `42 tests`，全部通过；
- Python 全量回归：`328 tests`，全部通过；
- 前端：`9 files / 17 tests`，全部通过；
- TypeScript 检查与 Vite production build：通过，`1800 modules transformed`；
- Catalog `discovery-catalog:63fba1561a4860f04c9b7f72f747d9baed40d3f3bdf128e886e5a92d21010826`：697 candidates / 223 parameters / 1684 EvidenceAtom，coverage completed；
- 三个机器产物重生成并逐字重放：
  - service assembly：`24ef2319727e17c37412867b5ef63c4f844ba026c26ccc51e83f27cb9473ca0c`；
  - research cases：`d34cd5aae0ac4214b74715a99c6717a6f40cac29a86d3a77d031c8d039761cbf`；
  - representative corpus：`32079c3f723af7a746a29d45c4d8137685f827c72264022299db8ac9b5d09e63`；
- `compileall` 与 `git diff --check`：通过；
- SSH 部署：通信测绘研究范围按用户约定不部署，记为 N/A。
