# M1-25：LuCI/ubus 后端执行主体与访问策略图

## 1. 目标

把前端 `rpc.declare` 发现的逻辑操作继续映射到 rpcd 插件、静态分发方法和 ACL 策略，同时严格区分“可验证绑定”“Native 候选”“授权声明”和“未找到 owner”。动态 `String.format('%s')` 只归一化为有界 `{dynamic}` 模板，不伪造具体实例。

## 2. 深模块与不变量

- `ubus_operation_references_from_frontend()` 只接收 `ubus://object/method` 候选；
- Lua `usr/libexec/rpcd/<object>` 必须同时具有 list/call 协议和静态 methods 表，才发布 `static_plugin_dispatch`；
- Native `usr/lib/rpcd/*.so` 只发布 candidate，并要求插件 stem 与 object 命名一致或为其命名子空间；
- ACL wildcard 可匹配动态 object 模板，但只发布 read/write grant；
- 没有静态 owner 时保留 `resolve_ubus_runtime_owner`；Native candidate 保留 `resolve_ubus_registration_table`；
- Candidate Detail 沿 binding 的 `principal_id` 返回 runtime principal，UI 分层展示执行主体、绑定和策略。

## 3. 真实 AC9 19.07.8 回放

官方 OpenWrt AC9 制品在 Binwalk 3.1.0 离线解包树上得到：

| 信号 | 数量 |
| --- | ---: |
| 前端 ubus candidate / 去重 logical operation | 73 / 53 |
| 动态 operation template | 1 |
| runtime principal | 4 |
| static Lua exec-plugin binding | 25 |
| Native plugin candidate | 30 |
| ACL access grant | 72 |
| runtime-owner / registration-table obligation | 18 / 30 |

代表链包括：

- `ubus://luci/getFeatures → usr/libexec/rpcd/luci`：静态 method-table binding；
- `ubus://luci-rpc/getBoardJSON → usr/lib/rpcd/luci.so`：Native candidate，等待注册表；
- `ubus://file/read → usr/lib/rpcd/file.so`：排除 `luci.so` 偶然字符串共现后保留的 candidate；
- `ubus://hostapd.{dynamic}/del_client → hostapd.* write ACL`：策略可证，owner 仍开放。

机器报告：[M1-25 AC9 ubus 后端图](../samples/m1-25-openwrt-ac9-ubus-backend.json)。

## 4. 验证与边界

新增 Producer/Repository 合同覆盖动态适配、Lua binding、Native 候选、误共现负例、ACL wildcard、Catalog 投影和 principal 下钻。Frontend Producer 升级为 `0.4.0` 后，所有受影响机器报告与研究案例 Evidence ID 均从真实样本确定性重放。

本轮不声称运行时可达、认证结果、Native handler、漏洞存在或可利用性。按通信测绘工作约定，本轮不部署 SSH 环境。
