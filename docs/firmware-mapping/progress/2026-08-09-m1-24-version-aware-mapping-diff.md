# M1-24：覆盖感知的固件版本通信结构对比

> 日期：2026-08-09  
> 范围：Snapshot Diff、Release Context、LuCI RPC、Binwalk 实证、API/UI  
> 真实样本：OpenWrt 18.06.7 / 19.07.8，Tenda AC9 target

## 1. 为什么不能直接做 JSON diff

两个测绘目录的差异可能来自固件变化，也可能来自分析器版本、声明扫描范围、失败文件或动态语义未解析。M1-24 因此先比较 Coverage Ledger，再比较稳定的 candidate、parameter 和 potential-hidden-interface 身份。只有生产器 profile 相同且 required coverage 完成时，结构变化才标记为 `firmware_change_supported`；相同但不完整的范围标记为 `observed_scope_only`；范围或状态不同时标记为 `coverage_confounded`。

版本谱系同样不从文件名猜测。`MappingReleaseContext` 以不可变记录保存 vendor、product、device model、firmware version、source reference 和证据说明；两端 context 的固件家族相同后，UI 才显示已验证的同型号边界。

## 2. 公开接口

- 纯领域函数：`compare_mapping_catalog_documents(base, target, ...)`；
- SQLite：不可变 `mapping_catalog_release_contexts` 与 `repository.compare_catalogs()`；
- HTTP：`GET /api/mappings/compare?base=<catalog>&target=<catalog>`；
- Console：“通信测绘 → 版本对比”，包括版本选择、增删改指标、覆盖警告、差异时间线和 BASE/TARGET 证据详情。

候选对齐优先使用专属稳定身份：Native route token、nested operation、保护路径和集合差异方向；普通候选使用 kind + canonical identity。Evidence ID 不参与结构差异，避免同一事实因重放证据摘要变化被误报。

## 3. 真实双版本实证

两个固件均来自 OpenWrt 官方 release target，并使用固定 Binwalk 3.1.0 镜像、禁网容器与内容摘要解包：

| 版本 | Artifact SHA-256 | Inventory | Catalog | 资产 / 候选 |
| --- | --- | --- | --- | --- |
| 18.06.7 | `2911048377aa17b44683b5f406fe3f6e62a5247ba7d4ab72cd3cb91fbf2a3184` | completed | completed | 3 frontend assets / 43 candidates |
| 19.07.8 | `d40b191c95c5b6e43358785d6c6e9d7915296e9a954d27fbc1936bdf48568ec9` | completed | partial | 71 frontend assets / 97 candidates |

样本驱动修复了三类通用盲区：

1. `/etc/mtab → /proc/mounts` 属于运行时 kernel namespace，不再误报 rootfs 缺失；
2. sectionless stripped ELF 仍可发布 ELF metadata 与 printable hint，不再误判 malformed；
3. UCI `uhttpd` 配置可恢复 listener、docroot、CGI/Lua prefix。

更重要的是，19.07.8 大量使用 `rpc.declare({object, method, params})`。Frontend Producer v0.4.0 将其发布为 `ubus://object/method` 逻辑操作，保留 object/method selector、输入参数和精确 EvidenceAtom，而不伪造固定 HTTP URL。真实目录恢复 53 个去重 ubus 操作，包括 `ubus://system/info`、`ubus://network.interface/dump`、`ubus://uci/apply` 与有界模板 `ubus://hostapd.{dynamic}/del_client`。动态实例仍未解析，因此该版本保持 partial。

## 4. 可用于论文的案例观察

同型号 target 的差异显示：18.06.7 中 `/admin/status/realtime/*`、`/admin/network/*_status`、`/admin/system/flashops/*` 等 Lua controller 路由在 19.07.8 中消失；目标版本同时出现 LuCI 前端声明的 system、network、file、uci、iwinfo 与 luci-rpc ubus 操作。这支持“控制面从服务端 Lua 路由向前端 JSON-RPC/ubus 迁移”的静态架构假设。

该案例说明，单独比较 URL 会把迁移误写为功能删除；必须联合前端调用声明、脚本路由、Web 配置、Native/服务主体和覆盖状态，才能区分通信入口重组与分析缺失。当前由于一个动态 RPC 操作未解析，整体 diff 正确标记为 `coverage_confounded`，不能用于声称完整功能增删、补丁因果、漏洞修复或运行时可达性。

## 5. 重放

```bash
PYTHONPATH=src python3 scripts/extract_firmware_artifact.py \
  --input /path/to/firmware.trx --output var/mapping-work/extraction

PYTHONPATH=src python3 scripts/build_openwrt_ac9_version_diff.py \
  --database var/firmatlas.db \
  > docs/firmware-mapping/samples/m1-24-openwrt-ac9-version-diff.json
```

机器报告：[M1-24 OpenWrt AC9 版本差异](../samples/m1-24-openwrt-ac9-version-diff.json)。本轮按用户对通信测绘工作的明确约定不部署 SSH 环境。

## 6. 验证结果

- Python 全量回归：352 tests passed；
- Console：9 个测试文件、19 tests passed，TypeScript 检查与 Vite production build 通过；
- 本地 API：`/api/health` 返回 ok；版本对比接口确认同固件家族，返回 256 项差异与 3 项覆盖变化；
- 本地浏览器：目录选择、覆盖警告、差异分类、检索过滤和证据详情均完成交互检查。

## 7. 后续义务

- 恢复 LuCI `request.get/post/request`、`L.url(...)` 和 CGI base 组合；
- 把 `hostapd.%s` 等动态 ubus object 表达为带模板约束的操作；
- 将脚本 route 与 ubus object/method 绑定到 rpcd plugin / executable owner；
- 在 coverage 等价后形成可用于统计的接口、参数和潜在隐藏接口版本迁移矩阵；
- 加入有明确安全公告或补丁边界的同型号厂商版本，研究漏洞机制路径变化。
