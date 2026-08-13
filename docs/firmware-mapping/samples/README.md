# 代表性通信类别与样本基线

> 基线版本：M1.5
> 数据观察日期：2026-08-10
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
- [M1-19 X5000R 扩展前端范围](./m1-19-x5000r-expanded-frontend.json)：加入 `kr.js`、`wan_ie.html` 与 `advance/config.html`，恢复默认 URL + payload variable 与 multipart 两级 selector，使 operation 从 199 增至 203、范围缺口从 3 降至 0、差集变为 77/11；进度说明见 [M1-19 记录](../progress/2026-08-09-m1-19-x5000r-expanded-frontend.md)。
- [M1-11A DAP-3520 HNAP/PHP-XGI Catalog](./m1-11a-dap3520-hnap-xgi-catalog-summary.json)：273 个候选、1 个 `ACTION_POST` selector、288 个 EvidenceAtom，以及 `/HNAP1 → /www/HNAP1 → /usr/sbin/hnap` 与 XGI 状态树链；M1-13 重放后上游 Inventory 与 Catalog 均为 completed。
- [M1-12 通信架构 research-case corpus](./m1-12-research-case-corpus.json)：保存 AC9 split web stack 与 X5000R shared-CGI 的内容寻址证据时间线；X5000R 当前已演进到第 12 阶段，包含差集反向驱动范围扩展、三种请求架构、nested upload dispatch、请求保护范围、静态服务装配与潜在隐藏接口集合。
- [M1-21 X5000R 请求保护范围](./m1-21-x5000r-request-protection.json)：跨 `usr/sbin/lighttpd` 与 `www/cgi-bin/cstecgi.cgi` 保存 suffix/path gate、SESSION_ID 会话验证、302 enforcement、CGI 排除分类和 nested upload handler 链；进度说明见 [M1-21 记录](../progress/2026-08-09-m1-21-x5000r-request-protection.md)。
- [M1-22 X5000R 静态服务装配](./m1-22-x5000r-service-assembly.json)：从 `sbin/rc:init_router` 重放 service group、lighttpd argv/config、listener、document root、CGI namespace 与目标 ELF 的十一段证据；进度说明见 [M1-22 记录](../progress/2026-08-09-m1-22-x5000r-service-assembly.md)。
- [M1-23 X5000R 潜在隐藏接口](./m1-23-x5000r-potential-hidden-interfaces.json)：在 Source Inventory、Frontend 和 Set Difference completed 门槛下保存 10 条 native registration + handler + zero-observed-reference 信号，并固定非后门/非运行时结论边界；进度说明见 [M1-23 记录](../progress/2026-08-09-m1-23-potential-hidden-interfaces.md)。
- [M1-24 OpenWrt AC9 双版本差异](./m1-24-openwrt-ac9-version-diff.json)：固定两个官方 Artifact、Binwalk 谱系、不可变 release context 和 coverage-aware diff；Frontend Producer v0.4.0 恢复 53 个去重 LuCI/ubus 逻辑操作（含一个有界动态模板），并因其具体运行时实例未解析而保持 partial；进度说明见 [M1-24 记录](../progress/2026-08-09-m1-24-version-aware-mapping-diff.md)。
- [M1-25 OpenWrt AC9 ubus 后端图](./m1-25-openwrt-ac9-ubus-backend.json)：恢复 53 个去重逻辑操作（含 1 个动态模板），并分别发布 rpcd 执行主体、25 条静态 Lua binding、30 条 Native plugin candidate、72 条 ACL grant 和未决 owner/registration-table 义务；进度说明见 [M1-25 记录](../progress/2026-08-09-m1-25-ubus-backend-graph.md)。
- [R2-15 AC9/AC18 DLNA feature pivot](./r2-15-vendor-tenda-ac9-ac18-dlna-feature-pivot.json)：以 AC9 为主样本，保存 3 条相邻 USB 状态 pivot、0 条 DLNA 配置 binding，并用官方 AC18 启用 build 的 17 条 DLNA pivot 与 3 条真实 binding 作同家族阳性对照；不迁移 owner 或漏洞状态。
- [R2-16 AC9/AC18 DLNA frontend reachability](./r2-16-vendor-tenda-ac9-ac18-dlna-reachability.json)：以 AC9 为主样本，逐请求区分顶层声明、有界活动路径与已声明但未达；AC18 仅作同家族正控，静态分类不提升为运行时执行或漏洞结论。
- [R2-17 AC9/AC18 DLNA communication graph](./r2-17-vendor-tenda-ac9-ac18-dlna-communication-graph.json)：从同一 Catalog 生成证据、覆盖和义务可下钻的焦点图；AC9 69 节点/121 边且 4 条 owner 义务保持开放，AC18 92 节点/183 边并独立确证 3 条 route→handler，`refreshDLNA` 继续为真实阴性。
- [R2-18 AC9 persisted graph query](./r2-18-vendor-tenda-ac9-graph-query.json)：持久化 completed 的 AC9 全图（5,674 节点/7,212 边），关闭重开后回放 interface/parameter/completeness/minidlna component/dlnaEn evidence 五类查询；所有结果保留 facet、Coverage Ledger、EvidenceAtom 与预算状态。
- [R2-19 AC9 HTTP/Console graph](./r2-19-vendor-tenda-ac9-http-console-graph.json)：从 AC9 rootfs 独立重建同一 completed 图，经真实 HTTP Adapter 检索 4 个 DLNA 接口并聚焦 `SetDlnaCfg` 的 23 节点/22 边；Console 回放参数证据与 4 条开放 owner 义务，双进程报告逐字节一致。
- [R2-20 AC9 historical graph overlay](./r2-20-vendor-tenda-ac9-historical-graph-overlay.json)：把 13 条版本化历史接口/参数期望作为只读上下文链接到 AC9 的 5,674 节点图；8 条结构观察到、5 条因其他版本不可判定，2 条 exact-artifact 期望均发现，同时保留 71 条产品漏洞分母和跨版本非漏洞结论边界；双进程报告逐字节一致。
- [R2-21 AC9 historical coverage queue](./r2-21-vendor-tenda-ac9-historical-coverage-queue.json)：对 71 条产品漏洞分母生成 57 条内容寻址开放任务；原始来源已把 CVE-2021-42659 升级为第 3 条 exact-artifact observed，剩余两条 parameter-only 被纠正为 configuration-key sink，并保留当前制品 route clue 与未知 HTTP ingress 的边界。配套输入和回放见 [semantic clues](./r2-21-vendor-tenda-ac9-historical-semantic-clues.json)、[expectation supplement](./r2-21-vendor-tenda-ac9-historical-expectation-supplement.json)和[历史 replay](./r2-21-vendor-tenda-ac9-historical-replay.json)。
- [R2-22 AC9 configuration ingress](./r2-22-vendor-tenda-ac9-configuration-ingress.json)：`auto-v14` 从 `POST /cgi-bin/UploadCfg`、multipart 字段 `filename` 恢复独立六项 ARM 字符串分发表，并确证 `UploadCfg → bin/httpd@0x3b850`；机器报告另保存 `libtpi → cfm → libCfm` 的跨二进制人工 continuation 与尚待自动化的 persistence obligation。
- [R2-23 AC9 cross-ELF persistence](./r2-23-vendor-tenda-ac9-cross-elf-persistence.json)：`auto-v15` 自动恢复 `httpd → libtpi:tpi_sys_cfg_upload`、精确 `cfm Upload` literal、`gCtlCmdArr[Upload] → libCfm:UploadValue → SendMsg/RecvMsg`；同名 `doSystemCmd` owner 不唯一时显式未决。
- [R2-24 AC9 configuration-image state flow](./r2-24-vendor-tenda-ac9-configuration-blob-flow.json)：`auto-v16` 从 `UploadValue` 的 opcode `14`、2016-byte frame、offset `516`、literal `0` 跨进程匹配 `cfmd → atoi → RestoreMTD`，发布整镜像 `configuration_partition[0]` 与 `writes_state`；不创建伪 HTTP 参数。
- [R2-25 AC9 configuration text import correction](./r2-25-vendor-tenda-ac9-configuration-text-import.json)：`auto-v17` 深入 `RestoreMTD` 实现并回溯上传 writer，证明 `/webroot/default.cfg` 的 `key=value → hash_insert` 导入，发布 1013 个唯一 configuration-state 节点及 `imports_state`；明确否定 R2-24 的 whole-image granularity，同时保留其冻结回放。

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
- 现作为首要典型样本：冻结的 `auto-v1` 基线有 3461 candidates、130 parameters、4025 EvidenceAtom；`auto-v2` 新增跨资源 RouterPage method 证明后有 4056 EvidenceAtom，并自动证明 45 条 ARM PIC route→handler。基线见 [R2-02](./r2-02-vendor-tenda-ac9-auto-profile.json)，最新报告见 [R2-04](./r2-04-vendor-tenda-ac9-framework-history.json)。
- R2-03 从 13 条版本化历史漏洞 expectation 反推并修复对象载荷参数覆盖缺口：当前目录增至 130 parameters / 4025 EvidenceAtom，exact-artifact 两条均观察到；[expectation manifest](./r2-03-vendor-tenda-ac9-historical-expectations.json) 与[完整差异报告](./r2-03-vendor-tenda-ac9-historical-diff.json)分别保存外部声明和当前固件证据，不能混作漏洞结论。
- R2-04 用 `public.js` 的 `$.post(pageModel.setUrl, ...)` 为 31 个页面接口提供跨文件 method 证据，13 条结构化 expectation 达到 8 observed / 5 version-out-of-scope。另以 [71 条产品级全集](./r2-04-vendor-tenda-ac9-vulnerability-scope.json)守住分母：13 条可比较接口、3 条仅参数、9 条无结构化通信、46 条尚未语义分析；平台对当前 FirmEmuHub 样本另有 30 条高置信 `reproduced_on` 关联，两者不可混算。13 条历史路由中目前仅 3 条有验证过的 route→handler binding。
- R2-20 将这组历史期望固化为可发布、可查询的图谱覆盖层：`auto-v13` 仍为 8 observed / 5 out-of-scope-not-assessable，但原生深化已把路由对照推进到 5 条预期 handler 验证、4 条路由验证、1 条 handler mismatch 和 3 条未观察绑定。Console 明确并列展示 status 与 applicability；跨版本结构存在不会被提升为当前固件漏洞。
- R2-21 以原始披露纠正三条 parameter-only：`occurs` 是 NLP 假阳性，真实 HTTP body 字段为 `list`；两个 2026 字段是配置键而非请求参数。加入单条 immutable supplement 后，14 条 expectation 为 9 observed / 5 not-assessable，3 条 exact-artifact 全部观察到；其余队列为 2 parameter repair、9 structured extraction、46 semantic analysis。
- R2-22 关闭“未知配置入口”但没有伪造 key flow：HTML form 给出 `POST multipart filename`，`httpd` 的独立 CGI token switch 给出六项 family 证明和 `UploadCfg@0x3b850` handler。人工审计继续观察到配置文件 split 与 `cfm Upload` IPC；该后半链保留为下一轮自动 Producer 义务。
- R2-05 发现 Samba 所在注册块使用 ARM `LDR [PC, -offset]` 回指 literal pool；`auto-v3` 增加双向 PC-relative 解析后，绑定从 45 增至 59、开放义务从 89 降至 61，并证明 `SetSambaCfg → formSetSambaConf`。历史路由 binding 覆盖从 3/13 提升至 5/13；机器输出见 [R2-05](./r2-05-vendor-tenda-ac9-bidirectional-pic.json)。
- R2-06 移除前端/history anchor 对 Native 枚举范围的限制：`httpd` 183 条、`dhttpd` 2 条，共恢复 185 条 registrar binding。限定 `/goform/` 前端 action 后得到 110 条 Native-only、5 条 Frontend-only；只有 Inventory、Frontend、Native 与 Set Difference coverage 全部 completed，才发布 110 条[潜在隐藏接口](./r2-06-vendor-tenda-ac9-registrar-inventory.json)。它们包含 `QuickIndex/WizardHandle/MfgTest/telnet/ate` 等研究目标，但不代表后门、运行时可达或漏洞。
- R2-07 识别 handler-first/r2-route ARM 调用布局，恢复 `GetUpnpCfg → formGetUpnpLists` 与 `GetSySLogCfg → formGetSysLog`；registrar 185→187、开放义务 61→57、Frontend-only 5→3。剩余 `GetDlnaCfg/SetDlnaCfg/refreshDLNA` 在 287 个 Native 辅助制品中均无精确 token，继续保持版本残留或缺失组件义务；见 [R2-07](./r2-07-vendor-tenda-ac9-handler-first.json)。

它是开发样本，不进入最终无泄漏测试结果。

**Tenda AC18 / same-family enabled-DLNA positive control**

- 官方版本：`V15.03.05.19(6318)`，ZIP SHA-256 `359d2feac6a7d28bd45a11e60a7062945152f516978deb7d54daea84d9211410`；
- `CONFIG_DLNA_SERVER=y`，携带 `minidlna` 与配置；
- 确定性恢复 `GetDlnaCfg → getDLNAserverCfg`、`SetDlnaCfg → formDLNAserver`、`expandDlnaFile → formExpandDlnaFile`；
- `refreshDLNA` 仍为 Frontend-only，是防止“同页面即同型后端”误推理的真实阴性；
- 角色：same-vendor validation，只用于验证结构迁移和 feature/component 差分，不把 AC18 事实迁移为 AC9 owner 或漏洞结论。

**OpenWrt Tenda AC9 target / Lua route → LuCI JSON-RPC/ubus 版本迁移**

- 真实版本：OpenWrt `18.06.7` 与 `19.07.8` 官方 bcm53xx/generic target；
- 两个 Artifact 均以固定 Binwalk 3.1.0 禁网容器解包，Inventory completed；
- 18.06.7 恢复 18 条 Lua route；19.07.8 恢复 53 个去重 `ubus://object/method` 逻辑操作（含 1 个动态模板）；
- 旧版 `/admin/status/realtime/*`、network status 与 flashops 路由消失，同时新版出现 system/network/file/uci/iwinfo/luci-rpc 操作；
- `hostapd.%s` 已被界定为 `{dynamic}` 操作族，但具体实例与 owner 未解析，使新版 Catalog 为 partial、整体 diff 为 coverage-confounded。
- 19.07.8 的 4 个 sectionless ARM32 rpcd 插件已从原始 ELF 注册表重放，31 条 LuCI operation 晋级为 verified Native handler binding，30 条 registration obligation 关闭；动态 `hostapd.{dynamic}` owner 仍保持未决。报告见 [M1-26](./m1-26-openwrt-ac9-native-ubus-registration.json)。

该例用于验证“通信架构迁移不能被降维成 URL 增删”。它支持静态迁移假设，但不证明功能等价、补丁因果、漏洞修复或运行时可达。

R2 起该例作为原厂 Tenda AC9 的同硬件控制面对照，而非主样本。Auto Profile 报告见 [R2-02 OpenWrt AC9](./r2-02-tenda-ac9-auto-profile.json)。

**TOTOLINK X5000R / shared CGI + multipart nested dispatch + custom protection scope**

- 前端请求：`POST /cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting`；
- 外层 selector：`action=upload`；内层 selector：`setting/setUploadSetting`；
- 原生 dispatcher：`main@0x0042e390`，上传解析器 `cutUploadFile`；
- suffix 规范化：`setting/setUploadSetting → setUploadSetting`；
- 精确注册：`set_handle_t@0x0044a124 → handler@0x0042bf14`；
- 请求保护：lighttpd 对 `.asp/.html/.htm/config.dat/login.cgi` 进入 `SESSION_ID` 会话门，但 `/cgi-bin/cstecgi.cgi` 被该门排除；
- 静态服务装配：`init_router → start_services_once → start_httpd → _eval(lighttpd -f lighttpd.conf) → /cgi-bin/ → cstecgi.cgi`；
- 潜在隐藏接口首个集合：前端覆盖完成后仍有 10 个 operation 具备 native registration、handler 与差集证据，但没有已观察前端引用；
- 中间报告：[M1-20 Nested Dispatch](./m1-20-x5000r-nested-dispatch.json)；
- Catalog：697 candidates / 223 parameters / 1684 EvidenceAtom。

该例用于验证同一物理 CGI 内多层 selector、原生表分发、跨二进制保护范围和静态服务装配。10 个 `no_frontend_reference` 是需要跨固件持续沉淀的“潜在隐藏接口”，但仍可能来自动态/隐藏客户端、废弃代码或其他未纳入范围的调用者，不能据此断言后门、真实运行时可达、外部授权策略或漏洞可利用性。

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

R2 已新增完整 rootfs 的统一编排回放：[OpenWrt AC9 AnalyzeRun](./r2-01-openwrt-ac9-analysis-run.json)。它从 1103 个 Inventory 节点自动选择 269 个 producer 输入，发布 720 candidates、220 parameters、1105 EvidenceAtom 与 100 条保留义务，并记录每阶段 coverage。

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
