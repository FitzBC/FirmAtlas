# 代表性通信类别与样本基线

> 基线版本：M1.3
> 数据观察日期：2026-08-09
> 机器可读清单：[representative-corpus.json](./representative-corpus.json)

已发布的样本过程说明：

- [Tenda AC9：M1 Snapshot 人工证据重放](./tenda-ac9-m1-walkthrough.md)；
- [Tenda AC9：M1-02 完整 rootfs 清单](./tenda-ac9-m1-inventory-walkthrough.md)。
- [Binwalk worker 合同中间输出](./binwalk-worker-contract-summary.json)：确定性 fake 证明父制品、命令证据和派生 Inventory 的谱系，不代表真实固件已解包。
- [M1-02B Binwalk 真实回放](./m1-02b-binwalk-real-replay-summary.json)：固定 Binwalk v3.1.0 本地验证镜像的 DIR-882 零产物负例与 DAP-3520 历史回放；其中 v1alpha1 symlink 结论由 M1-13 后续重放勘误。
- [M1-13 DAP-3520 chroot symlink 重放](./m1-13-dap3520-chroot-symlink-replay.json)：选定 rootfs 的 753 个节点全部处理；118 条 symlink 保留原始目标与固件内规范目标，15 条 `/dev/null` 链接作为未物化运行时设备目标记录，0 diagnostics。
- [Tenda AC9：M1-03 精确 EvidenceAtom](./tenda-ac9-m1-evidence-atoms.json)：从完整 `static_route.js` 回放出的字节、行列、摘要和稳定证据身份。
- [M1-04 Frontend Producer 中间输出](./m1-04-frontend-producer-summary.json)：两份 AC9 真实源文件与 HNAP/共享 CGI 合同 fixture 的请求、参数和 selector 对比。
- [M1-05 Web Configuration Producer 中间输出](./m1-05-web-configuration-summary.json)：AC9 真实 nginx 配置与启动脚本恢复出的 listener、docroot、FastCGI namespace 和服务链。
- [M1-06A Native Shallow Producer 中间输出](./m1-06a-native-shallow-summary.json)：AC9 `httpd/dhttpd` 的 ELF route-token、symbol 与 server hint 对照及未决 binding。
- [M1-06C Frontend/Native Correlation 中间输出](./m1-06c-frontend-native-correlation-summary.json)：AC9 7 个 frontend candidate 与 Native hint 的精确候选关联、负面对照和 14 个深分析义务。
- [M1-06B Script Backend Producer 中间输出](./m1-06b-script-backend-summary.json)：D-Link DSL 真实 ASP、空 HNAP 占位与 Shell CGI 的参数—状态链和保守路由边界。
- [M1-07 Obligation Scheduler 中间输出](./m1-07-obligation-scheduler-summary.json)：AC9 14 个 route/handler 义务在 discover 策略下的零高成本执行固定点与开放工作保留。
- [M1-08 AC9 Discovery Catalog 中间输出](./m1-08-ac9-discovery-catalog-summary.json)：三份前端/模板、配置、脚本、Native、关联和调度结果组装出的 395 个无 seed 候选、参数、覆盖与开放义务。
- [M1-10 Native Deep route-table 中间输出](./m1-10-native-deep-route-table-summary.json)：ARM ELF `{route_ptr, handler_ptr}` 正例的三段证据链、Scheduler 义务关闭、Catalog 投影，以及 AC9 无可信命名表的真实负面对照。
- [M1-10B AC9 ARM PIC call-site 中间输出](./m1-10b-ac9-arm-pic-callsite-summary.json)：从 `online_list.js` 的 5 个接口关联到 `httpd` 的 5 个 handler、共同 131-pair registrar、五段证据链和 10/10 义务关闭。
- [M1-11 代表性架构 corpus report](./m1-11-representative-corpus-report.json)：按 real/derived/fixture/external 四层证据区分 `/goform`、HNAP、共享 CGI、脚本后端和 Native-only；AC9、DAP-3520 与 X5000R 三类真实样本已验证，整个 gate 仍因脚本后端和 Native-only 缺口保持 `partial`。
- [M1-14 X5000R 共享 CGI 记录](../progress/2026-08-09-m1-14-x5000r-shared-cgi.md)：固定原始固件、隔离 Binwalk 谱系、completed Inventory、lighttpd CGI namespace、JSON selector、MIPS 目标与跨资源/handler 开放义务。
- [M1-15 X5000R Frontend Asset Graph](./m1-15-x5000r-frontend-asset-graph.json)：跨 `config.js/topicurl.js` 的唯一 endpoint binding、199 个 operation、逐候选双来源证据、动态 method 未决状态和 Native handler 开放义务；进度说明见 [M1-15 记录](../progress/2026-08-09-m1-15-frontend-asset-graph.md)。
- [M1-16 X5000R MIPS dispatcher](./m1-16-x5000r-mips-dispatch.json)：四张 `char[64]+handler` 导出表、138 registrations、123/199 selector binding、76/14 双向差集、重复注册和开放 value-flow 义务；进度说明见 [M1-16 记录](../progress/2026-08-09-m1-16-x5000r-mips-inline-dispatch.md)。
- [M1-17 X5000R MIPS handler value-flow](./m1-17-x5000r-mips-value-flow.json)：`setLanCfg` 无分支前缀内两条 `websGetVar(parameter) → nvram_set(state)` 五线证据链、首个条件分支边界与开放的 DHCP/sink 义务；进度说明见 [M1-17 记录](../progress/2026-08-09-m1-17-x5000r-mips-value-flow.md)。
- [M1-18 X5000R frontend/native 集合差异](./m1-18-x5000r-set-difference.json)：将 76 个 Frontend-only 与 14 个 Native-only operation 分为 38/38/3/1/10 五类证据形状，保留精确 token、suffix 变体负例和开放因果义务；进度说明见 [M1-18 记录](../progress/2026-08-09-m1-18-x5000r-set-difference.md)。
- [M1-11A DAP-3520 HNAP/PHP-XGI Catalog](./m1-11a-dap3520-hnap-xgi-catalog-summary.json)：273 个候选、1 个 `ACTION_POST` selector、288 个 EvidenceAtom，以及 `/HNAP1 → /www/HNAP1 → /usr/sbin/hnap` 与 XGI 状态树链；M1-13 重放后上游 Inventory 与 Catalog 均为 completed。
- [M1-12 AC9 research-case corpus](./m1-12-research-case-corpus.json)：将 `/goform` 与 nginx/FastCGI 分支不相交、httpd/dhttpd 候选对照和 ARM PIC 最终 binding 保存为内容寻址的证据时间线，并附反事实、论文用途和局限。

## 1. 为什么不能只选“最容易跑通”的样本

接口测绘工具最容易在 `/goform/<Action>` 上获得漂亮结果，但这会把“路径就是操作”的特殊情况误当成通用规律。基线必须同时覆盖共享 endpoint、selector、脚本控制器、Native route table、现代 API、SOAP/XML 和前端缺失场景。

样本按七个轴选择：

1. wire 形态；
2. dispatch 机制；
3. 前端是否存在；
4. 后端是脚本还是 Native；
5. 参数容器和 selector；
6. 固件样本是否可获得；
7. 是否有历史漏洞、版本和补丁证据。

“漏洞文本中出现接口”只用于发现候选类别，不能作为目标固件的测绘真值。

## 2. 当前平台类别分布

以下数字来自本地 FirmAtlas 当前语义观察，只用于确定测试优先级，未来 Feed 更新后会变化：

| 类别 / 子类 | 独立接口 | CVE | 厂商 |
| --- | ---: | ---: | ---: |
| goform 驼峰注册表 | 318 | 828 | 17 |
| 共享 CGI 分发器 | 6 | 331 | 7 |
| 未定型管理路由 | 133 | 142 | 68 |
| CGI 可执行注册表 | 55 | 111 | 23 |
| boafrm 处理器注册表 | 41 | 96 | 5 |
| 分层页面控制器 | 83 | 93 | 15 |
| goform 下划线注册表 | 56 | 79 | 10 |
| goform 小写注册表 | 17 | 68 | 9 |
| 扁平命名管理处理器 | 52 | 67 | 39 |
| 扁平页面控制器 | 50 | 60 | 11 |
| 外置 CGI 处理器 | 36 | 50 | 18 |
| HNAP 信封分发器 | 1 | 23 | 2 |
| 分层 CGI 模块 | 22 | 20 | 12 |
| 分层 API 命名空间 | 15 | 16 | 10 |

长尾类别仍需保留：版本化资源路由、UPnP 控制端点、SOAP 独立服务、框架 `.do/.action`、Servlet 页面和 goform 通配分发器。它们样本少，但对验证身份模型是否真正通用非常重要。

## 3. 首批样本层级

### Tier A：本地可回放

**Tenda AC9 / goform camel registry**

- 平台候选：`firmemuhub:BM-2024-00012`；
- 本地解包提示：`../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root`；
- 已核验前端：`static_route.js`、`online_list.js`；
- 已核验 Native：32-bit ARM stripped `bin/httpd`；
- 已自动回放 Native shallow：`httpd` 354 hints / 357 evidence，6 个选定 frontend action component 全部精确命中；`dhttpd` 0/6；
- 已核验 Web 配置链：nginx `:8180`、`/cgi-bin/luci/ → 127.0.0.1:8188`、`spawn-fcgi → app_data_center`；
- 可观察接口：`SetStaticRouteCfg`、`SetOnlineDevName`；
- 可观察参数：`list`、`mac`、`devName`。

它是开发样本，不进入最终无泄漏测试结果。

**D-Link DSL2877AL / vendor ASP + Shell CGI**

- 平台候选：`BM-2024-00096`；
- 本地来源：已有 Binwalk 派生 `squashfs-root`，本轮未把它冒充生产 worker 证明；
- `mt_admin.asp`：恢复 `button_type=1` selector、`admPass1` 和 6 次配置状态访问；
- `ad_routing.cgi`：识别为 Shell CGI program，但不从目录位置声明 route；
- `hnap.asp`：零字节负面对照，不从文件名创造 HNAP endpoint。

该样本补齐脚本后端类别，当前作为 development/cross-architecture contract 样本。

**D-Link DAP-3520 A1 / HNAP + PHP-XGI hybrid**

- 原始 Artifact SHA-256：`0de4c72f3d7ba1dc6419328be355b51e39d1dae0a8ad14918f0e4eb4699499f9`；
- 当前选定 `squashfs-root` Inventory v1alpha2 回放恢复 753 个节点；历史
  Extraction 目录回放是不同层级的制品身份，不与 rootfs Inventory 混用；
- `httpd.php` 明确绑定 `/HNAP1 → /www/HNAP1 → /usr/sbin/hnap`；
- 普通管理页使用 `ACTION_POST → __action.php → query/set` 的 PHP-XGI 配置链；
- 专用 Producer 已恢复 5 条 httpd 配置关系、266 条 XGI 状态访问与 5 个 `ACTION_POST` 操作值；Catalog 为 273 candidates / 288 evidence；
- 118 条 symlink 已按固件 chroot 语义安全解析，目标不会经链接打开；当前
  HNAP/XGI 真实样本为 `verified`。

### Tier B：平台已有固件候选

- Tenda AC18：同厂商 goform 家族验证；
- D-Link DIR-846 A1：`/HNAP1` 共享信封验证；
- D-Link DIR-823G：版本和历史漏洞丰富，保留为 holdout，冷启动阶段不得输入目标 PoC。

这些候选仍需经过下载、SHA-256 和内部版本核验后才能成为 Firmware Artifact。

### Tier C：类别存在但缺固件样本

- Totolink X5000R：`/cgi-bin/cstecgi.cgi`；
- nextu Fleta AX1500：`/boafrm/formFilter`；
- D-Link DAR-7000：PHP 页面控制器；
- Circle：`/api/CONFIG/restore`；
- TP-Link VN020：UPnP control endpoint；
- Wavlink NU516U1：独立 CGI executable。

Tier C 同时是样本获取工作队列。没有固件制品前，只能验证外部情报分类，不能用于声明 mapper 的固件内召回率。

## 4. 数据集角色

| 角色 | 用途 | 允许使用的信息 |
| --- | --- | --- |
| development | 调试 producer 和合同 | 可以人工阅读完整样本 |
| same-vendor validation | 检查同架构泛化 | 不把 development 标注作为目标事实输入 |
| cross-architecture validation | 检查身份模型 | 可以使用类别，不使用目标接口清单作为 seed |
| holdout | 论文主指标 | 隐藏目标 PoC、补丁后验和人工接口清单 |
| acquisition-gap | 推动样本建设 | 不计入固件测绘性能分母 |

## 5. 每轮样本验证流程

1. 冻结 Sample Candidate ID、下载证据和目标角色；
2. 下载并登记 Firmware Artifact，不信任文件名版本；
3. 在不提供接口清单的条件下运行 discover；
4. 保存原始 Snapshot、Coverage Ledger 和 Obligations；
5. 与人工标注比较，记录漏报、误报和身份拆分错误；
6. 只根据误差类别修改规则，不直接为单个路径加特例；
7. 对所有历史样本执行回归；
8. 更新主控文档、progress 记录和 corpus manifest。

如果一个修改提高 Tenda goform 结果却破坏 HNAP/CGI，不能称为优化；必须记录为架构特化或重新设计身份规则。

## 6. 当前缺口

- Tenda AC9 已完成 Inventory、Frontend、nginx/启动项、Native Shallow 与候选关联回放；D-Link DSL2877AL 已完成首轮 Script Backend 回放；
- AC9 `/goform/*` 未被 nginx 配置覆盖；该阶段形成的 ownership 义务已由 ARM PIC call-site 证据关闭为 `bin/httpd → formSetDeviceName` 等 5 个 binding，运行时可达性和认证状态仍未知；
- 其他候选尚未由新 Mapping Module 自动解包和分析；
- 当前类别来自漏洞文本路径规则，尚未由真实 dispatcher/binding 证据校准；
- 除 AC9 已验证的 5 个 route/handler 外，其他 Native 函数、参数 getter 和跨架构 binding 尚未建立真值；
- 缺少跨厂商 OEM/代码血缘明确标注；
- 数据许可和论文再分发范围仍需逐样本核查。
