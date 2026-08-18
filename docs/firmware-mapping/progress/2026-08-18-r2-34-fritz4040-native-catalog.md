# R2-34：FRITZ!Box 4040 直接 Native UBUS Catalog

> 日期：2026-08-18
> 状态：实现、全量回归、真实页面验收完成；Git 修订见本文末尾
> 范围：`firmatlas.mapping`、Console、测试与 `docs/firmware-mapping`；SSH 部署不适用

## 1. 本轮问题与结论

R2-33 已证明 OpenWrt 19.07.10 FRITZ!Box 4040 的 4 个 ARM rpcd plugin 可由
`NativeUbusRegistrationProducer` 完整恢复为 4 objects、24 methods、60 EvidenceAtom，
但全量 Catalog 仍只有 20 个 verified native operation。根因不是 acquisition，也不是 Producer
失败，而是 Catalog 只有 `Frontend operation -> UBUS backend` 入口；没有前端引用的注册方法
无法进入目录。

本轮新增一个纯投影 Adapter：

```text
NativeUbusRegistrationResult
  -> DiscoveryProducerBatch.native_ubus_registration
  -> runtime principal + request interface + backend binding + native handler
  -> Communication Graph binds_handler edge
```

Adapter 不读取 rootfs、不重新反汇编 ELF，也不制造 EvidenceAtom，只复用 Producer 的对象、方法、
handler 和证据身份。partial Producer 不得发布候选；completed Producer 可以形成独立 completed
scoped Catalog。默认 Profile/Registry 冻结为 `auto-v21/builtin-v21`，旧版本继续可回放。

## 2. 状态变化时间线

| 阶段 | 状态 | 证据与解释 |
| --- | --- | --- |
| R2-33 一手筛选 | acquisition closed | 官方 sysupgrade 与 4 个 rpcd plugin SHA 已固定 |
| Producer 实测 | producer completed | 4 objects / 24 methods / 60 EvidenceAtom |
| 旧 auto-v20 Catalog | orchestration gap | 1210 candidates、8475 evidence、117 obligations；只发布 20/24 native methods |
| Adapter 合同红灯 | 失败 | `DiscoveryProducerBatch` 无 direct native registration Interface |
| Adapter 与图合同绿灯 | completed | 每方法 operation/binding/handler；binding 精确连接 handler |
| 独立 holdout | completed | 76 candidates、60 evidence、0 open obligations |
| 完整 auto-v21 | partial | 1286 candidates、8475 evidence、117 obligations；Native stage 24/24 completed |
| AC9 回归首轮 | 暴露继承缺陷 | 新 Profile 未进入旧字符串白名单，漏掉 `expandDlnaFile?` |
| AC9 回归修复 | restored | 改为 profile version 下界语义，v21 自动继承 v6/v10 前端和差集能力 |

这条时间线不会把“Producer 已完成但 Catalog 无出口”或 AC9 首轮回归失败重写成从未发生。

## 3. 真实样本与中间输出

一手来源与字节谱系：
[R2-34 primary-source research](../research/2026-08-18-r2-34-fritz4040-native-catalog-primary-sources.md)。

机器报告：
[r2-34-openwrt-fritz4040-native-catalog.json](../samples/r2-34-openwrt-fritz4040-native-catalog.json)。

生成命令：

```bash
PYTHONPATH=src python3 scripts/build_fritz4040_native_catalog_report.py \
  docs/firmware-mapping/samples/r2-34-openwrt-fritz4040-native-catalog.json \
  --analysis-output var/mapping-work/r2-34-fritz4040/analysis-run-v21.json \
  --graph-output var/mapping-work/r2-34-fritz4040/communication-graph-v21.json
```

关键结果：

| 输出 | 结果 |
| --- | ---: |
| Inventory | completed，1061 entries，SHA `a8c4722264d6abb5d918db514d65c243f743a5dd23d376d6e9e3eeeeb48d8f1c` |
| 独立 Native Catalog | completed，76 candidates / 60 evidence / 0 obligations |
| direct operations / bindings / handlers | 24 / 24 / 24 |
| `binds_handler` edges | 24 |
| 完整 auto-v21 Catalog | partial，1286 candidates / 8475 evidence / 117 obligations |
| 完整通信图 | completed projection，1746 nodes / 2429 edges |

旧 Frontend 驱动链漏掉、现已进入 Catalog 的四条 operation 是：

- `ubus://iwinfo/devices`
- `ubus://iwinfo/info`
- `ubus://iwinfo/phyname`
- `ubus://iwinfo/survey`

这只证明静态注册和 handler 绑定，不证明运行时可达、ACL、未授权访问、漏洞或可利用性。

## 4. Corpus、Capability 与案例库

FRITZ 样本现在以 `independent-holdout` 进入代表性 corpus，范围只包含 24 个 direct request
candidate；禁止 capability `constructs_request`，因此不能借 Frontend 证据通过。原始 Producer
能力为 `registers_ubus_method/binds_ubus_handler`，分类门限使用
`mentions_endpoint/binds_handler`。本轮没有改写 EvidenceAtom，而是把 alias 固定为
`firmatlas.mapping.corpus-capability-policy/v1`，报告 schema 升为 v1alpha3，policy 参与内容身份。

本例符合“非平凡架构分裂 + 义务状态变化”准入条件，已作为
`openwrt-fritz4040-frontend-native-ubus-split` 加入 research-case corpus。案例保留三阶段、
原始 locator、反事实、论文用途与限制；4 cases 的 corpus validation 为 `paper_ready=true`。

## 5. Console 与解释边界

Console 的语料门禁视图现在显示样本角色；FRITZ 明确标为“独立 holdout”，展示 24 候选、
60 证据和 capability policy。解释文案不再说 FRITZ “尚未发布”，并继续声明 gate passed 不等于
所有厂商、ISA 或子类型已经泛化。完整 FRITZ Catalog/Graph 另作为产品查询对象发布，可搜索
上述四条操作并下钻 operation -> binding -> handler。

## 6. 验证、发布与交接

本轮 TDD 红—绿覆盖 direct Adapter、图边、独立作用域 corpus、真实 FRITZ AnalyzeRun、
checked-in 报告和 Console。最终验证记录：

- Python 全量回归：559 项通过，耗时 559.15 秒；首次全量为 556 通过、3 个冻结 Console
  source SHA 失败，重建 R2-19/R2-20/R2-29 验收报告后最终全量通过；
- Console 测试：29 项通过；
- TypeScript app/node 两套检查通过；Vite production build 通过，1801 modules；
- FRITZ 报告、Corpus 和 Research Case 均连续双生成逐字节一致，SHA-256 分别为
  `4f5a84e98f70d123cc25729d6a2ff570a1aeab52d3c0e93754f4c640c95773e6`、
  `73c582d858bdfe9220f9244176f6dbbc3895dbedabc2393b35801566aa8f0dbb`、
  `a7846db9728ce0060394a3c2dea2e6b4ce3687102d310ef62b5dd222d4e05120`；
- 本地服务继续运行于 `127.0.0.1:18789`。`/api/health`、Corpus v1alpha3、FRITZ Catalog
  1286/117 和 Graph 1746/2429 均经 HTTP 200 验证；
- 真实页面先验证 Corpus `5/5`、FRITZ “独立 holdout” `24 候选 / 60 证据` 和 capability
  policy；再在 FRITZ 图谱将 `ubus://iwinfo/devices` 收敛为 1/1，焦点为 12 nodes / 11 edges，
  可见 `native_registration`、`binds_handler`、handler `iwinfo.so@0x181c` 与 5 条原始证据；
  随后切换 AC9 图谱复验 1665 nodes / 2273 edges 并聚焦 `ubus://luci/getFeatures`，浏览器
  warning/error 日志为空；最终页面已切回 FRITZ 焦点并保留；
- AC9 主回归：direct UBUS 31 个 Frontend binding 与 24 个独立 binding 均保留；原厂 AC9
  `expandDlnaFile?` 和 disabled-feature 差集在修复 profile 继承后恢复；
- Git commit/push：待最终写入；
- SSH 部署：不适用，依据 `AGENTS.md` 的 firmware mapping research exception。

下一出口为 R2-35：受控重取 D-Link DAP-2695，走 raw artifact/rootfs -> AnalyzeRun -> Catalog，
验证 script backend 的独立跨厂商 holdout；随后增加非 ARM 原生注册样本。开始下一会话时先读
本记录、R2-34 一手研究、机器报告和 research casebook，不要把完整 Catalog 的 partial 覆盖
误写成 direct Native Adapter 失败。
