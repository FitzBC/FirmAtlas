# 固件通信测绘产品功能与验收手册

> 验收版本：R2-39
>
> 验收日期：2026-08-20
>
> 典型样本：原厂 Tenda AC9 V15.03.05.19(6318)
>
> 服务入口：`http://127.0.0.1:18789/`

## 1. 产品用途

固件通信测绘从原始固件或已解包 rootfs 冷启动，不依赖漏洞文本或人工接口 seed。系统联合前端、
Web 配置、脚本后端、Native ELF、访问策略和状态访问证据，发布不可变 Discovery Catalog，再把事实
投影为面向调查的可折叠力导图。每项事实保留来源制品、精确字节或行号定位、覆盖状态以及尚未解决
的证据义务。

`partial` 表示结果可用但仍有明确覆盖缺口；`unknown / not_recovered` 表示当前证据没有恢复出类型或
约束。二者都不会被界面伪装成完整发现。

## 2. 用户工作流

1. 点击右上角“上传新固件”，选择不超过 64 MiB 的制品，并填写厂商、产品、型号和版本。
2. 服务按 SHA-256 内容寻址保存制品，隔离执行解包和 AnalyzeRun，并发布不可变 Catalog/Graph。
3. 进入“接口调查”，确认顶部固件身份，或切换到另一个已分析固件。
4. 从固件根节点展开二进制或组件，例如 `bin/httpd`；再次点击展开它拥有的 Web 接口。
5. 点击接口展开参数组合；点击参数，在右侧查看类型、作用、代码约束、依赖和精确证据。
6. 使用搜索框把画布收敛到命中节点及其祖先，使用“重置自动布局”重新计算位置；节点可随时折叠。
7. 需要 UBUS/IPC 等内部调用时进入“高级图谱”或“原始证据”。它们不会混入默认 Web 接口图。

## 3. 已实现功能

| 功能 | 当前行为 | 证据或边界 |
| --- | --- | --- |
| 原始固件上传 | 64 MiB 有界、异步单 worker、内容寻址、完整设备身份持久化 | 固定摘要 Binwalk、禁网、只读输入/根、资源预算 |
| 固件身份 | 持续展示 release context、SHA 和覆盖状态，支持切换已分析固件 | 未登记身份显示“待确认”，不从文件名猜测 |
| 接口力导图 | 固件 → 二进制/组件 → Web 接口 → 参数，逐层展开/折叠 | 默认只呈现请求接口；UBUS/IPC 不冒充 Web URL |
| 自动布局与搜索 | 确定性力模拟、层级偏置、一键重置；搜索保留命中分支和祖先 | 首屏只展开组件，避免一次渲染数百接口 |
| 参数详情 | 语义、位置、数据类型及依据、约束、依赖、owner、EvidenceAtom | 只从字面域/selector 证据推断类型，不按参数名猜测 |
| 自动测绘编排 | Inventory → 多 Producer → Scheduler → Catalog → Graph | Producer 失败进入 coverage，不伪装为空成功 |
| 高级图谱 | 四种证据约束视图、精确焦点、跳数/节点/边预算 | 子图无悬空边，UBUS/IPC 在这里保留取证价值 |
| 潜在隐藏接口 | Native 注册集合减去 completed 客户端覆盖集合 | coverage 不完整时不发布“隐藏”结论 |
| 历史漏洞对照 | 历史 expectation 只读叠加，不改写固件事实 | 分开显示发现状态与版本适用性 |
| MiniMax 建议 | 有界脱敏证据包、Evidence ID 白名单、proposal-only | 默认关闭，不能改写 Catalog 或关闭义务 |

## 4. Tenda AC9 力导图验收

样本 SHA-256：`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`。当前 Catalog 为
`discovery-catalog:29081f8e9f48b65ee10c85b81cb73fbce5dffa26023726397ae691397e5373a4`。

接口调查读模型包含 422 个节点、421 条边：29 个组件、249 个请求接口、143 个输入参数。其中真实
Native 二进制为 `bin/httpd`（191 个接口）和 `bin/dhttpd`（2 个接口）；其余未绑定 Native owner 的
请求接口按前端来源模块保留。122 个仅由 Native 注册发现的接口保持 `native_registration_only`，
没有路径证据时显示 `path_status=unresolved`，不会擅自拼接 `/goform/...`。

### 4.1 固件根节点与二进制组件

![AC9 固件根节点与组件力导图](./screenshots/2026-08-20-r2-39-force-root.png)

初始画布只展开 29 个组件。右侧显示 Tenda、AC9、版本、SHA、Catalog 状态和覆盖义务；用户不会在
数百个接口之间失去入口。

### 4.2 展开 httpd 接口与参数

![httpd 接口与参数分支](./screenshots/2026-08-20-r2-39-httpd-interface-parameters.png)

展开 `bin/httpd` 后可查看其 191 个接口。搜索 `SetSysTimeCfg` 后，画布仅保留固件、`bin/httpd`
和目标接口；展开接口得到 `ntpServer`、`timePeriod`、`timeZone` 三个参数，并显示 handler
`fromSetSysTime`。

### 4.3 参数详情与证据边界

![timeZone 参数详情、约束与依赖](./screenshots/2026-08-20-r2-39-parameter-details.png)

点击 `timeZone` 后，侧栏同时给出 owner `/goform/SetSysTimeCfg`、所属 `bin/httpd`、依赖线索和
前端/Native 精确位置。当前证据没有恢复整数范围、长度、格式或时间边界，因此数据类型和代码约束
诚实显示 `unknown / not_recovered`。143 个参数中有 138 个仍为未知类型；这是后续代码使用点分析
的明确任务，不是 UI 缺数或推断失败。

## 5. 测试结果

| 验证层 | 命令或方式 | 结果 |
| --- | --- | --- |
| Python 力导图专项 | `PYTHONPATH=src python3 -m unittest tests.test_mapping_interface_force_graph tests.test_intelligence_api.IntelligenceApiTests.test_mapping_interface_force_graph_route` | 3/3 通过 |
| Python 全量回归 | `PYTHONPATH=src python3 -m unittest discover -s tests` | 最终 563/563 通过；首轮 3 个历史报告源码摘要失配已按当前源更新并复验 |
| Python 编译检查 | `python3 -m compileall -q src` | 通过 |
| Console 全量回归 | `pnpm test` | 33/33 通过，10 个测试文件 |
| TypeScript/生产构建 | `pnpm build` | 通过，1,802 modules transformed |
| API 验收 | AC9 force-graph endpoint | HTTP 200；422 nodes / 421 edges；响应约 1.06 MB，单节点 EvidenceAtom 最多 12 条 |
| 浏览器交互 | 展开/折叠、分支搜索、自动布局、参数侧栏 | 通过；页面 Console 0 errors |

真实浏览器回放验证：首屏 30/422 可见节点、29 条可见边；展开 `bin/httpd` 后为 221/422 节点、
220 条边；搜索目标后为 3 节点/2 边；展开接口后为 6 节点/5 边；折叠恢复为 3 节点/2 边。

## 6. 本地启动与 API 验收

先构建 Console，并使用同时保存漏洞情报、固件资产和测绘投影的主数据库 `var/firmatlas.db`：

```bash
cd apps/console && pnpm build && cd ../..
PYTHONPATH=src python3 -m firmatlas intelligence serve \
  --database var/firmatlas.db \
  --host 127.0.0.1 --port 18789 \
  --static-dir apps/console/dist \
  --mapping-workspace var/mapping-jobs \
  --mapping-runtime /usr/local/bin/docker \
  --mapping-binwalk-image-ref 'sha256:<pinned-image-id>' \
  --mapping-binwalk-version 3.1.0 \
  --mapping-upload-max-bytes 67108864 \
  --mapping-analysis-max-seconds 900
```

```bash
curl -fsS http://127.0.0.1:18789/api/health
curl -fsS http://127.0.0.1:18789/api/mappings/catalogs
curl -fsS 'http://127.0.0.1:18789/api/mappings/catalogs/<catalog-id>/interface-force-graph'
curl -fsS http://127.0.0.1:18789/api/mappings/corpus-report
curl -fsS http://127.0.0.1:18789/api/mappings/jobs
```

`/api/health` 只证明进程存活。恢复服务还必须确认漏洞情报、固件资产、Catalog、Graph 和 corpus gate
均非空或处于预期状态，不能用单轮研究数据库代替主库。

## 7. 解释与交付边界

- 不把静态注册等同于运行时可达、访问授权、漏洞或可利用性。
- 不按参数名称猜测类型、范围或业务含义；未知事实明确显示为未恢复。
- 不把没有路径证据的 Native selector 拼装成 `/goform/...`。
- 不把历史漏洞描述直接写成当前固件事实。
- 不把 UBUS/IPC 当作 Web 接口；它们仍可在高级取证视图分析内部调用关系。
- 不在仓库、日志或文档中保存模型 API Key，只从环境变量读取。
- 通信测绘范围按仓库例外执行本地完整验收、提交和 GitHub 推送，不部署到 `satc_cloud`。

架构决策、迭代修正、反事实失败模式和完整复验记录见
[R2-39 可折叠接口力导图记录](./progress/2026-08-20-r2-39-expandable-force-interface-graph.md)。
