# M1-05：Web Configuration Evidence Producer

> 工作项：M1-05  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地实现、回归、真实样本回放与 GitHub；按用户当前测绘范围不部署 SSH

## 1. 结果

实现公开 Interface：

```text
discover_web_configuration(source_entry, source_bytes, policy)
  -> WebConfigProducerResult
```

结果 schema 为 `firmatlas.mapping.web-config-result/v1alpha1`。当前声明支持：

- nginx `listen`、`root`、`alias`、`internal`、`fastcgi_pass`、`proxy_pass`、`auth_basic`、`auth_basic_user_file`；
- 直接 POSIX shell `nginx -p` 与 `spawn-fcgi -a/-p executable` 启动形式；
- listener、document root、namespace mapping、auth requirement、service start 五类 finding；
- 每个 finding 引用内容摘要和精确字节 Span 可重放的 EvidenceAtom；
- invalid UTF-8、未知格式、源不匹配、文件与 finding 预算使用不同 Coverage/Diagnostic 语义。

配置 finding 不直接升级为 Interface/Operation，也不与 M1-04 frontend candidate 合并身份。

## 2. TDD 与失败语义

11 条公开 Interface 测试覆盖：

1. nginx server/location scope；
2. listener、root、FastCGI 和 internal alias；
3. auth zone 与 user file；
4. nginx 注释样例隔离；
5. nginx 与 spawn-fcgi 直接启动；
6. shell 注释、echo 与普通变量不产生执行事实；
7. 未支持文本是 `not_applicable`，不冒充空成功；
8. invalid UTF-8 是 `failed`；
9. source/finding 预算是显式 skip/partial；
10. nginx server-level auth 与 `internal`/`alias` 指令顺序无关；
11. AC9 两份真实完整文件及全部 EvidenceAtom 回放。

TDD 过程中保留了两项最初未写入预期但有直接证据的结果：FastCGI listener 对应 executable，以及 nginx 错误页 location 的相对 root `html`。它们不应为迎合窄测试而删除。

## 3. AC9 实证与中间输出

机器可读摘要见 [M1-05 Web Configuration JSON](../samples/m1-05-web-configuration-summary.json)。

| Source | SHA-256 | bytes | findings | evidence | coverage |
| --- | --- | ---: | ---: | ---: | --- |
| `etc_ro/nginx/conf/nginx.conf` | `66d18e…3663` | 2,888 | 5 | 5 | completed |
| `etc_ro/nginx/conf/nginx_init.sh` | `c1e33c…b9a1` | 138 | 3 | 3 | completed |

支持链：

```text
nginx listen :8180
  └─ /cgi-bin/luci/
       └─ fastcgi_pass 127.0.0.1:8188
            └─ spawn-fcgi /usr/bin/app_data_center
```

另有 `/download/ → /var/etc/upan/` internal alias 与根路径 `/ → /etc/nginx/conf`。

## 4. 跨 Producer 解释

M1-04 在同一 AC9 固件恢复的是 `goform/GetStaticRouteCfg`、`goform/SetStaticRouteCfg`、`goform/SetOnlineDevName` 等请求。M1-05 的 nginx namespace 是 `/cgi-bin/luci/` 与 `/download/`，没有直接覆盖 `/goform/*`。因此：

- 不按“同一固件”或“路径看起来像接口”合并身份；
- nginx/FastCGI 链可以作为独立通信架构分支发布；
- `dhttpd/httpd` 是否承载主 Web UI、如何注册 `/goform/*` 保持 unresolved；
- 后续 M1-06/Native Producer 必须提供 route/dispatcher/handler 证据。

## 5. 验证证据

| 门禁 | 结果 |
| --- | --- |
| Web Configuration contract | 11/11 通过 |
| Mapping extraction/inventory/evidence/frontend/snapshot/config | 71/71 通过 |
| AC9 Evidence replay | 8/8 通过 |
| JSON summary validation | `python3 -m json.tool` 通过 |
| 后端全量 | `make test`，132/132 通过 |
| 前端测试 | Vitest 16/16 通过 |
| TypeScript / 生产构建 | 两组 `tsc --noEmit` 与 Vite build 通过 |
| 本地 API/UI smoke | 临时 SQLite 下 health、overview、构建首页均 HTTP 200 |
| 实现修订 | `85fda01` |
| GitHub push | 随本里程碑关闭提交一并验证 |
| SSH deployment | 不适用（用户当前测绘范围） |

## 6. 已知边界

- `completed` 仅表示声明的 nginx directives 与直接 shell invocation 已执行，不覆盖任意 Web server 或 shell 控制流；
- include 文件目前独立分析，尚未解析为跨文件配置图；
- nginx 变量、rewrite 正则和复杂 location precedence 尚未归一化；
- `auth_basic off` 被明确记录为 auth requirement 的关闭状态，不能解释为全局不需要认证；
- shell wrapper、条件执行、环境变量和 supervisor/systemd/uhttpd/Boa/lighttpd 尚未支持；
- 配置可证明 namespace 与 process wiring，但不能证明 route 注册或 handler binding。

## 7. 下一动作

进入 M1-06，优先解释 AC9 `dhttpd/httpd` 与 `/goform/*` 的后端 route/parameter getter 证据。Binwalk 继续作为隔离 Extraction Worker 的工具，不进入 Producer 进程。
