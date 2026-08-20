# R2-38：以固件为中心的组件—Web 接口—参数约束调查

> 日期：2026-08-20
>
> 主样本：原厂 Tenda AC9 `V15.03.05.19(6318)` / `981ae43f…bf296`
>
> 对照样本：OpenWrt 19.07.8 Tenda AC9 / `d40b191c…68ec9`

## 问题与架构判断

R2-37 的默认通信图把 `ubus://file/exec` 等 logical operation 与 Web URL 放在同一“接口”层，
同时把上传藏在最后一个页签、把固件身份退化成 SHA。这个问题不是文案问题，而是三种领域对象被
压平：浏览器暴露面、组件间 RPC、原始证据图。

R2-38 冻结新的主调查顺序：固件身份 → 通信组件 → Web 接口 → 参数组合 → 依赖/约束 → 证据。
UBUS/IPC 继续作为重要实现证据，但只能从“内部 RPC · 实现细节”显式进入；原通信图保留为高级
取证工具。

## 分析阶段时间线

1. 初始复核最新 OpenWrt 图：98 个 interface 几乎全部是 `endpoint_shape=logical_operation` 的
   `ubus://` 操作；该 Catalog 没有证明对应浏览器 transport，不能把它们标成 Web URL。
2. 增加上传 release context：厂商、产品、型号、版本进入作业快照、SQLite 迁移、幂等摘要和
   Catalog context；部分身份拒绝提交，避免生成半真半假的标签。
3. 前端改成三栏接口调查并先以现有 OpenWrt 数据验证正反例：默认不出现 UBUS，内部视图仍能
   展开 7 个 `file` 操作。
4. 发现用 OpenWrt 控制样本无法证明主流程，于是重新运行原厂 AC9 `auto-v21`：4,950 candidates、
   14,370 evidence、696 parameters、73 obligations，Graph 为 7,126 nodes / 9,329 edges。
5. 发布原厂 Catalog/Graph 和 release context 后，浏览器实测 `Web 模块 · dlna` →
   `/goform/SetDlnaCfg` → `deviceName / scanList / dlnaEn` → 未决义务闭环。
6. 首轮全量回归 560 项中 3 项失败，原因是三个历史验收报告故意绑定了被修改前端源码的 SHA；
   更新对应 source digest 后重跑，而没有降低断言或删除守卫。

## 反事实失败模式

- 若仅把 `ubus://` 改名为“接口”，用户仍会误以为它是可直接请求的 URL。
- 若根据 source path 猜浏览器 transport，会把 OpenWrt 内部 RPC 错写成 `/ubus` 或 LuCI route。
- 若只显示文件名或 SHA，跨发行版的相同设备无法区分；若从文件名自动猜版本，又会产生无证据身份。
- 若只保留原始图谱，参数和约束虽存在于节点中，但用户必须先理解投影内部本体才能完成普通调查。

## 限制与后续义务

- 当前“组件”优先采用确定性来源模块名；当接口详情存在 Native binding/runtime principal 时在右栏
  展示后端执行链。后续应增加专用后端 projection，把前端模块与 Native owner 统一成显式 component。
- 参数组合目前表示同一接口观察到的参数集合、命名空间、selector/literal 与义务；条件表达式、
  互斥组、长度/范围验证器仍需新的约束 Producer，不能由模型补写成事实。
- 原厂 AC9 Catalog 为 `partial`，73 个开放义务继续可见；Graph `completed` 只表示投影闭包完成。

## 本轮验收证据

- [接口调查总览](../screenshots/r2-38-interface-explorer.png)
- [DLNA 参数与约束](../screenshots/r2-38-dlna-parameter-constraints.png)
- [内部 RPC 边界](../screenshots/r2-38-internal-rpc-boundary.png)
- [上传与身份表单](../screenshots/r2-38-firmware-upload.png)
- 产品功能与命令：[product-guide.md](../product-guide.md)

SSH 部署不适用：本轮范围限于 `firmatlas.mapping` 作业元数据、测绘 Console、映射 API/测试和
`docs/firmware-mapping`，适用仓库中的 firmware mapping research exception；完成后仍需提交并推送。
