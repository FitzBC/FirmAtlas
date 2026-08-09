# M1-21：X5000R 跨二进制请求保护范围

> 日期：2026-08-09
> 范围：MIPS Request Protection、Discovery Catalog、Research Case
> 样本：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

## 1. 研究问题

M1-20 已把 multipart 请求绑定到 `cstecgi.cgi main → set_handle_t → setUploadSetting@0x0042bf14`，但“上传分支之前是否存在认证保护”仍是明确义务。仅在二进制中看到 `SESSION_ID` 或登录函数，不能说明所有 CGI 都经过它；本轮要恢复保护条件的精确适用范围，并与业务 handler 所在的另一个二进制连接起来。

## 2. 已验证结构

| 阶段 | 二进制 / 地址 | 事实 |
| --- | --- | --- |
| 路径门 | `usr/sbin/lighttpd:http_response_write_header@0x004079fc` | 五个 `strstr` gate：`.asp`、`.html`、`.htm`、`config.dat`、`/login/login.cgi` |
| 认证入口 | `userloginAuth@0x00409300`，callsite `0x00407b2c` | 匹配路径进入 vendor 自定义认证函数 |
| 会话验证 | `checkLoginUser@0x00408978` | `ws_get_cookie("SESSION_ID")@0x00408a9c → form_get_idx_by_sessionid@0x00408ab4` |
| 拒绝分支 | `0x00407b40` | 认证拒绝结果写入 HTTP `302` |
| 保护正例 | `/advance/config.html` | `guarded_by_path_gate` |
| 范围负例 | `/cgi-bin/cstecgi.cgi` | `excluded_from_path_gate` |
| 业务分发 | `www/cgi-bin/cstecgi.cgi` | M1-20 已证明 nested upload dispatch 与 `handler@0x0042bf14` |

```text
usr/sbin/lighttpd
  suffix/path gate ──匹配──> userloginAuth → checkLoginUser → SESSION_ID → 302
         │
         └──不匹配 /cgi-bin/cstecgi.cgi
                         │
                         ▼
www/cgi-bin/cstecgi.cgi main
  action=upload → setting/setUploadSetting → set_handle_t → 0x0042bf14
```

认证基础设施与业务 dispatcher 位于不同二进制；保护范围由真实分支决定，而不是由“同一固件存在登录函数”决定。该结论拒绝 `obligation:x5000r-upload-auth-guard` 所表达的预期，但不等价于漏洞结论。

## 3. 新增公开 Interface

```python
discover_mips_request_protection(source, content, anchors, profile, policy)
```

结果 `firmatlas.mapping.mips-request-protection-result/v1alpha1` 保存 function identity/address、auth callsite、session cookie/lookup、denial status、guard patterns、逐路径分类和五类 EvidenceAtom。Catalog 新增 `native_request_protection`，并强制 `target_ref` 指向已存在的前端请求候选。

代表性 X5000R Catalog 由 695 candidates / 1668 EvidenceAtom 演进为 696 / 1673，参数保持 223；新增候选可按 `/cgi-bin/cstecgi.cgi`、保护状态、函数身份和状态码查询。

## 4. TDD 与失败边界

公开合同测试先以缺失 import、缺失 Catalog candidate 和缺失报告进入 red，再实现最小能力进入 green。破坏性负例固定：

1. 清除 `userloginAuth` call：`auth_hook_not_proven`；
2. 把 302 改为 200：`auth_enforcement_not_proven`；
3. 篡改 `SESSION_ID`：`session_validation_not_proven`；
4. source digest 不一致或指令预算不足：failed / partial；
5. 反转路径分类：结果合同拒绝。

因此函数名、cookie 字符串、单个 branch 或配置中的 CGI executor 都不能单独发布保护范围。

## 5. Ghidra 决策

本轮参考 `../iot_seedintelligentanalysis` 的 headless Ghidra、按 binary SHA 保存产物、分层导出和 candidate/validator 思路。本机没有可用 Ghidra；但三个关键函数都是带边界的 exported dynamic symbol，direct/GOT call、GP、分支目标、常量和 session denial join 可从原始 MIPS 字节确定性重放，因此未伪造 Ghidra 结果，也未把临时 Capstone 审查工具加入依赖。

当其他版本 stripped 掉函数边界、隐藏 call target 或使会话值跨函数/复杂 CFG 传播时，才触发隔离的 `Ghidra Candidate Worker → Core Validator`；Worker 自由文本不能关闭义务。

## 6. 论文价值与边界

这是 AC9 split web stack 之外的第二类代表性反例：AC9 说明配置 namespace 不足以确定 `/goform` owner；X5000R 说明认证符号存在也不足以确定一个 CGI operation 的保护状态。二者共同支撑“通信测绘必须先恢复执行主体、分发和保护条件，再选择漏洞分析二进制”的论点。

可用于 path-only / strings-only 消融、跨二进制通信结构图、义务被证据拒绝的时间线和目标二进制选择案例。不能据此声称 live service 一定按静态配置启动、没有其他中介保护、请求可从外网触达、存在未授权漏洞或可被利用。

## 7. 中间产物

- [请求保护范围报告](../samples/m1-21-x5000r-request-protection.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)；
- [代表性 Corpus 报告](../samples/m1-11-representative-corpus-report.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_request_protection_report.py
PYTHONPATH=src python3 scripts/build_mapping_research_cases.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
```

## 8. 后续义务

1. 证明 `sbin/rc:start_httpd → usr/sbin/lighttpd → lighttp/lighttpd.conf → CGI executor` 的静态服务装配；
2. 将真实运行时进程、监听端口、请求生命周期与外部中介作为独立验证层；
3. 分析 `setUploadSetting@0x0042bf14` 的文件、命令、持久化与重启 sink，但不跳过输入 provenance；
4. stripped/复杂变体再实现 Ghidra Candidate Worker。

## 9. 验证记录

- 专项合同：request-protection、research-case、corpus-report 共 `33 tests`，全部通过；
- Python 全量回归：`319 tests`，全部通过；
- 前端第一次执行因桌面 shell 缺少 Node 未进入测试；加载工作区固定运行时后重跑，`9 files / 17 tests` 全部通过；
- TypeScript 检查与 Vite production build：通过，`1800 modules transformed`；
- 本地 HTTP `/api/health` 与 production frontend document：通过；
- Catalog `discovery-catalog:b6f28fb391ca92b70650e2e6250958f93b7737ba8558cac5191dfafccebdacb2`：696 candidates / 223 parameters / 1673 EvidenceAtom，coverage completed；
- Catalog API 查询 `kind=native_request_protection&q=cstecgi` 唯一返回 `/cgi-bin/cstecgi.cgi -> excluded_from_path_gate`，detail 精确包含五种保护证据能力；
- 三个机器产物重生成并逐字重放：
  - request protection：`3d80257d965110ed58bb4b12caadee6e1ee2684183605dd4747f4be666ace030`；
  - research cases：`e152f66dbdd0f70a591f0be43c9e0f008e1074b924ac5512386e67b1181f680d`；
  - representative corpus：`202c442851598aed6788f74d5cf047a77504b8965850b44db06bfc88b5c48f61`；
- `compileall`、Markdown 相对链接检查与 `git diff --check`：通过；
- SSH 部署：通信测绘研究范围按用户约定不部署，记为 N/A。
