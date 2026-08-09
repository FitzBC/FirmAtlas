# R2-03：Tenda AC9 历史漏洞 expectation diff 与参数闭环

> 主样本：Tenda AC9 V15.03.05.19
> 制品 SHA-256：`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`
> 分析原则：历史漏洞是待比较的外部声明，不是当前固件事实

## 1. 研究问题与版本边界

本轮回答三个不同问题：历史漏洞提到的接口是否出现在当前 Discovery Catalog；参数与
transport shape 是否同时恢复；未命中究竟是当前制品的 analyzer gap，还是漏洞针对另一个
AC9 版本。历史库中有明确通信接口的 13 条 AC9 记录被固化为版本化 expectation manifest。

当前制品是 `15.03.05.19`，只有 `CVE-2025-22946` 与 `CVE-2025-22949` 同时声明该版本，
因此只有这两条可进入 exact-artifact recall。其余 11 条声明 `15.03.05.14`、
`15.03.05.14_multi`、`15.03.05.18` 或 `15.03.02.13`，只作为跨版本架构线索；即使当前
制品未观察到，也不能称为 mapper 漏检或漏洞修复。

输入见 [AC9 历史 expectation manifest](../samples/r2-03-vendor-tenda-ac9-historical-expectations.json)，
完整输出见 [AC9 历史差异报告](../samples/r2-03-vendor-tenda-ac9-historical-diff.json)。

## 2. 固化的工具合同

新增 `firmatlas.mapping.historical_expectation`：

- `HistoricalInterfaceExpectation` 保存 CVE、接口、method、参数、handler、声称版本、来源和
  applicability basis；
- `compare_historical_expectations(catalog, expectations)` 只读取不可变 Catalog，返回稳定、
  内容寻址的 `HistoricalExpectationDiff`；
- 状态区分 `observed / partial / missing / not_assessable`；
- 归因区分参数未观察、method 未观察、Native dispatcher 线索尚未形成接口、catalog coverage
  不完整、artifact scope 未知与明确 out-of-scope；
- `compare-history ROOT --artifact-sha256 ... --expectations ... --output ...` 把全根分析与差异报告
  组成一个用户可运行入口。

这个合同不会把历史描述晋级为 EvidenceAtom，也不会从“路径存在”推断漏洞存在、运行时可达或
可利用性。

## 3. 初次对照与失败解释

初次运行（尚未改进 Frontend Producer）得到：

| 状态 | 数量 | 含义 |
| --- | ---: | --- |
| observed | 4 | 接口及声明参数均出现 |
| partial | 4 | 接口出现，但声明参数未关联 |
| not_assessable | 5 | 都是其他版本声明，当前制品不能计算 miss |

四个参数缺口集中在 `SetIPTVCfg/list`、`AdvSetLanip/lanMask`、
`WifiBasicSet/security`、`SetRemoteWebCfg/remoteIp`。源码复核发现它们都实际存在，但 AC9
不是用已有 Producer 支持的查询串表达，而是放在：

- `R.pageModel.beforeSubmit` 内的对象载荷；
- `R.moduleModel.getSubmitData` 内的对象载荷。

因此这四条不是固件缺少参数，而是**Frontend 参数语法覆盖缺口**。新增有界对象提取后，参数
总数从 79 增至 130，EvidenceAtom 从 3966 增至 4025；前三个参数缺口关闭，RemoteWeb 只剩
历史记录明确声明 POST、当前局部 page-model 文件尚未独立证明 method 的 transport-shape gap。

## 4. 改进后结果

| 指标 | 结果 |
| --- | ---: |
| 历史 expectation | 13 |
| exact-artifact expectation | 2 |
| exact-artifact observed / gap | 2 / 0 |
| 全部 observed / partial / not assessable | 7 / 1 / 5 |
| 当前 Catalog candidates / parameters / evidence | 3461 / 130 / 4025 |

- `CVE-2025-22946 → /goform/SetOnlineDevName`：接口、`mac/devName` 和 ARM handler binding
  都存在；历史记录未声明具体参数，本报告不外推漏洞机制；
- `CVE-2025-22949 → /goform/SetSambaCfg`：接口及当前 payload 参数集合存在；历史记录未声明
  具体参数；
- 跨版本的 `SetIPTVCfg/list`、`AdvSetLanip/lanMask`、`WifiBasicSet/security` 现在均由当前
  制品源码证据观察到，但只说明架构线索在 `.19` 仍存在；
- `QuickIndex` 接口未观察到，但 `bin/httpd` 的 `formQuickIndex` Native symbol 已进入 Catalog，
  保存为跨版本 dispatcher 中间线索；
- `exeCommand`、`DownloadCfg.jpg`、`WizardHandle` 均属于其他版本声明。原始 `bin/httpd`
  分别在 file offset `0xdc954`、`0xd2568`、`0x47d1` 存在相近字符串
  `exeCommand`、`/cgi-bin/DownloadCfg`、`fromWizardHandle`，但它们不足以证明历史接口 identity；
  其中 `.jpg` 后缀差异尤其不能被静默归一化。

## 5. TDD 与迭代时间线

1. RED：缺少 historical expectation 模块；GREEN：接口+参数精确命中并保留 Catalog evidence；
2. RED：参数缺口没有独立原因；GREEN：`parameter_not_observed`；
3. RED：Native route clue 被当作完全未知；GREEN：dispatcher clue 与接口缺口分离；
4. RED：跨版本未命中被当作 miss；GREEN：artifact scope 与 coverage 双护栏；
5. RED：报告不可直接持久化；GREEN：内容寻址 JSON contract 与 `compare-history` CLI；
6. RED：真实 AC9 对象 payload 参数未恢复；GREEN：有界 `beforeSubmit/getSubmitData` 对象键提取；
7. 真实样本回放固定 exact 2/2、参数证据和跨版本 Native clue。

## 6. Research casebook 评估

本例接受进入 casebook：初始“历史参数未发现”在读取页面语法后转变为“Producer 语法覆盖缺口”，
并由新 analyzer 关闭。反事实是只看最终 130 个参数会误写成原分析已经完整；只看历史文本又会把
不同版本接口误报成 `.19` 的漏检。论文可用于展示 version-scoped oracle、阶段性 obligation 和
history-guided analyzer development；限制是历史描述本身可能不完整，且未进行运行时或漏洞复现。

## 7. 下一步

- 用 `public.js` 中 `$.post(pageModel.setUrl, ...)` 建立跨资源 framework-semantics 证据，谨慎关闭
  `SetRemoteWebCfg` 的 method gap；
- 把 expectation diff 作为持久化 Analyze Job 的派生 read model，并为图谱 UI 增加“历史声明 / 当前
  事实 / 未决义务”三层展示；
- 对 `QuickIndex` 等 out-of-scope Native clue 做版本对照，不把旧版本 handler 名直接当当前接口；
- 在 DAP-3520、X5000R 上复用同一合同，验证 HNAP/shared-CGI 的 selector 与参数 namespace。

## 8. 回归验证记录

- Historical expectation 与 CLI 合同、真实 AC9 回放：11 项通过；Frontend + historical 定向
  回归共 43 项通过；
- `make test`：386 项通过；
- Console Vitest：9 个文件、19 项通过；TypeScript 检查与 Vite production build 通过；
- R2-01、OpenWrt R2-02、原厂 AC9 R2-02、历史 diff R2-03 四份报告均由脚本重新生成并逐字段
  相等；
- expectation manifest SHA-256：`23cf63519fd0365ae04dbb4e90576a1a40db39931af6488a69b9494033db4b72`；
- historical diff SHA-256：`779bad967f1b5e14139aa1e71d6cbef6b4b5de2368a6c02c7ed268455e1ba30f`；
- 原厂 AC9 R2-02 更新报告 SHA-256：`465462a274c0c47eae7d0ea46a98731b8d4ad9415d4276ba2ce14bb2c885c3b7`；
- `git diff --check` 与 JSON/py_compile 检查通过；仓库凭据扫描未发现用户提供的 MiniMax key
  片段。

本轮属于固件通信测绘研究，按用户要求不执行 SSH 部署。
