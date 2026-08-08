# 代表性通信类别与样本基线

> 基线版本：M1.0  
> 数据观察日期：2026-08-08  
> 机器可读清单：[representative-corpus.json](./representative-corpus.json)

已发布的样本过程说明：

- [Tenda AC9：M1 Snapshot 人工证据重放](./tenda-ac9-m1-walkthrough.md)；
- [Tenda AC9：M1-02 完整 rootfs 清单](./tenda-ac9-m1-inventory-walkthrough.md)。
- [Binwalk worker 合同中间输出](./binwalk-worker-contract-summary.json)：确定性 fake 证明父制品、命令证据和派生 Inventory 的谱系，不代表真实固件已解包。

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
- 可观察接口：`SetStaticRouteCfg`、`SetOnlineDevName`；
- 可观察参数：`list`、`mac`、`devName`。

它是开发样本，不进入最终无泄漏测试结果。

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

- 只有 Tenda AC9 已在本地完成源文件级人工回放与自动完整 rootfs Inventory；
- 其他候选尚未由新 Mapping Module 自动解包和分析；
- 当前类别来自漏洞文本路径规则，尚未由真实 dispatcher/binding 证据校准；
- Native 函数、参数 getter 和 route binding 尚未建立真值；
- 缺少跨厂商 OEM/代码血缘明确标注；
- 数据许可和论文再分发范围仍需逐样本核查。
