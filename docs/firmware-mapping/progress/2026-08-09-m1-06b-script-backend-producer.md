# M1-06B：文本后端 Evidence Producer

> 工作项：M1-06B  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地实现、真实样本回放、GitHub；按用户当前测绘范围不部署 SSH

## 1. Interface 与边界

```text
discover_script_backend(source_entry, source_bytes, policy)
  -> ScriptBackendProducerResult
```

结果 schema 为 `firmatlas.mapping.script-backend-result/v1alpha1`。首版声明支持厂商 ASP、PHP、LuCI Lua、POSIX Shell/CGI 的下列确定性构造：

- ASP `Request_Form` 参数读取和等值 selector；
- ASP `TCWebApi_set/commit` 配置写入链；
- ASP `tcWebApi_get` 模板状态读取；
- PHP superglobal 与 Slim 风格显式 route；
- LuCI `entry` 与 `luci.http.formvalue`；
- Shell CGI shebang 与 CGI 环境变量读取。

最重要的边界是：`CGI_PROGRAM`、模板文件和 `BackendRouteCandidate` 身份分离。只有 PHP/LuCI 的显式注册构造产生 `registers_route`；文件位于 `cgi-bin`、扩展名为 `.asp/.cgi` 或文件名像接口，都不能单独证明外部 URL 已暴露。

## 2. TDD 记录

11 条公开 Interface 测试覆盖：

- 厂商 ASP 参数、selector、状态写入和 commit；
- 内嵌模板状态读取不冒充 HTTP 参数；
- 空 ASP 占位文件不产生接口；
- Shell CGI 与普通 init shell 的身份差异；
- CGI environment 参数；
- PHP route/superglobal/header；
- LuCI route composition/formvalue；
- PHP/Lua/Shell 注释负面对照；
- UTF-8、source identity、source budget 与 finding budget；
- 真实 D-Link DSL 样本回放。

红绿过程中修复了三类契约问题：组合 LuCI 路径和规范化 header 必须标记为 `deterministic_derived`；ASP `<>` 普通条件不能误标为 operation selector；Shell CGI 必须保存实际 shebang 而不是假定 `/bin/sh`。

## 3. 真实样本中间结果

机器可读摘要见 [M1-06B Script Backend JSON](../samples/m1-06b-script-backend-summary.json)。样本来自本地已有 Binwalk 派生目录，本轮只消费已解包 rootfs，不将其冒充生产 Extraction Worker 的当前证明。

| 文件 | 识别架构 | 参数 | 状态访问 | 模板读取 | Route | 解释 |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `MAINTENANCE/mt_admin.asp` | vendor ASP | 2 | 6 | 1 | 0 | `button_type=1` 分发；`admPass1 → Account_Entry0.web_passwd/console_passwd` |
| `hnap.asp` | vendor ASP | 0 | 0 | 0 | 0 | 空占位，不从文件名创造 HNAP 实现 |
| `get/ADVANCED/ad_routing.cgi` | Shell CGI | 0 | 0 | 0 | 0 | shebang 只证明 CGI program，不证明 URL 注册 |

该 ASP 结果首次恢复出一个可解释的参数到配置状态链：

```text
FORM admPass1
  → TCWebApi_set(Account_Entry0, web_passwd, admPass1)
  → TCWebApi_set(Account_Entry0, console_passwd, admPass1)
  → TCWebApi_commit(Account_Entry0)
```

它仍未证明该脚本的外部 URL、认证要求或底层 Native 实现；这些关系必须由 Web Configuration、Server dispatcher 或运行时证据补齐。

## 4. 当前验证证据

| 门禁 | 结果 |
| --- | --- |
| Script Backend contract | 11/11 通过 |
| Mapping 组合回归 | 103/103 通过 |
| 后端全量 | `make test`，163/163 通过 |
| 前端测试与构建 | Vitest 16/16、TypeScript 与 Vite build 通过 |
| JSON validation | `python3 -m json.tool` 通过 |
| 本地 API/UI smoke | 临时 SQLite 下 health、overview、构建首页均 HTTP 200 |
| 实现修订 | `475e433` |
| GitHub push | 随本里程碑关闭提交一并验证 |
| SSH deployment | 不适用（用户当前测绘范围） |

## 5. 下一动作

进入 M1-07 线索调度与固定点终止：把 Frontend、Web Configuration、Script Backend、Native Shallow 与 Correlation 的覆盖账本和未决义务统一进入稳定队列。并行保留 M1-02B：在容器运行时可用后，用允许的 Binwalk 实现隔离生产 Extraction Worker，不能在主分析进程直接运行。
