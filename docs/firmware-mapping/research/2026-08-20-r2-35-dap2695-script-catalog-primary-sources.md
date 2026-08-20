# R2-35：DAP-2695 Script-backend Catalog 一手来源与证据边界

> 日期：2026-08-20
>
> 范围：D-Link DAP-2695 Rev.A 1.20B20 RC101 的官方制品来源、字节身份、raw artifact 重放、PHP-XGI source scope 与 Catalog 边界
>
> 方法：厂商一手目录/声明 + 受控下载字节哈希 + 本地确定性 Producer/Catalog 重放

## 1. 结论

D-Link 德国官方归档仍列出
[`DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip`](https://ftp.dlink.de/dap/dap-2695/archive/driver_software/DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip)。
归档目录把该文件列为 10,414,440 bytes，目录时间为 2019-10-11；版本
`1.20B20 RC101` 来自文件名。文件名尾部 `20190115` 只能记为 datecode，不能与目录时间混成
一个未经发布说明证明的“发布日期”。

受控下载的外层 ZIP SHA-256 为
`5a1a4e7f45b0a6fa2d58da0142a76dc153f3e3d3fe99bc1fdf99ecc0aae77f8e`；其中
`DAP-2695_120B20RC101.bin` SHA-256 为
`11479c2dcce46af141954a067a0c0355d76bd49ed1793894b1d5960ac5300609`。这些是本地对官方
URL 返回字节计算的身份，不应写成厂商发布的 checksum：官方目录没有给目标 ZIP 提供
SHA-256 或签名。

当前公开 raw artifact 入口能从该 BIN 选中 SquashFS rootfs，并以 `auto-v21` 发布完整
Catalog/Graph。完整 Catalog 为 `partial`；全部 485 个 PHP 文件组成的显式 source scope 则
形成独立 completed Script-backend Catalog。两者是不同分母，不能相互覆盖。

## 2. 厂商一手来源

### 2.1 固件

- [DAP-2695 archive / driver_software](https://ftp.dlink.de/dap/dap-2695/archive/driver_software/)
- [目标 Rev.A 1.20B20 RC101 ZIP](https://ftp.dlink.de/dap/dap-2695/archive/driver_software/DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip)

同一归档还并列 1.17、1.20B02/B03/B17/B19 和 2.00 系列制品。它能证明目标文件处在
D-Link DAP-2695 官方发行目录，不证明各版本 rootfs、接口或漏洞行为相同。

### 2.2 GPL source package

- [当前 driver_software 目录](https://ftp.dlink.de/dap/dap-2695/driver_software/)
- [Rev.A GPL code package](https://ftp.dlink.de/dap/dap-2695/driver_software/DAP-2695_sw_reva_GPLcode.tar.gz)
- [D-Link GPL Code Statement](https://tsd.dlink.com.tw/GPL.asp)

目录列出的通用 Rev.A GPL 包为 199,749,540 bytes，目录时间 2016-03-30，早于目标 RC101
归档条目。公开索引只将其描述为 Rev.A GPL source，没有目标版本、内层固件 hash 或构建
manifest 将二者绑定。因此：

1. GPL 包可用作家族构建结构与第三方组件的辅助线索；
2. 不能把它称为 RC101 的精确对应源码；
3. 不能用它替代目标固件字节进行接口/参数结论；
4. D-Link 官方声明说明 FTP 软件可能聚合第三方与 D-Link 程序，只有被指定为 GPL/LGPL
   的部分适用相应许可，不能推成整个固件或专有页面已开源。

## 3. 字节身份与受控摄取

正式样本保留在 Git 忽略目录：

```text
var/mapping-work/r2-35-dap2695/acquisition/
├── DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip
└── DAP-2695_120B20RC101.bin
```

复核命令：

```bash
shasum -a 256 \
  var/mapping-work/r2-35-dap2695/acquisition/DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip \
  var/mapping-work/r2-35-dap2695/acquisition/DAP-2695_120B20RC101.bin
```

结果：

```text
5a1a4e7f45b0a6fa2d58da0142a76dc153f3e3d3fe99bc1fdf99ecc0aae77f8e  ...zip
11479c2dcce46af141954a067a0c0355d76bd49ed1793894b1d5960ac5300609  ...bin
```

固件和解包 rootfs 都不进入 Git。可提交的事实制品只包含哈希、内容寻址结果、数量与有界
evidence locator。

## 4. Raw artifact 重放

使用 R2-30 已冻结的容器镜像：

```text
k4l1xx/binwalk@sha256:03d1560ae439250f69a73f3d0bacff45cf1c04d8b0d0cbdf7d0170aa7e0cf303
```

镜像内 Binwalk 版本为 `2.2.1`。第一次误将 expected version 设为 `3.1.0` 时，probe 按约
fail closed；改为真实固定版本后：

- extraction：`partial_success`；
- selected root：`_firmware.bin.extracted/squashfs-root`；
- artifact analysis：`firmware-artifact-analysis:715c0e35…226a`；
- AnalyzeRun：`mapping-analysis-run:ba8afbdc…342f`；
- Catalog：`discovery-catalog:eb73cdcd…d69ab`；
- Graph：`communication-graph:87b5d91e…6d7c`。

完整 `auto-v21` 结果：5,999 candidates、9,522 EvidenceAtoms、91 open obligations；Graph
projection completed，7,301 nodes / 9,362 edges。完整 coverage 为 `partial`，直接原因包括：

- Inventory：`inventory.symlink_target_missing`；
- Frontend / Frontend Reachability：`frontend.invalid_utf8`；
- 不完整 Frontend 上游传播到 Feature Gate、correlation 和最终 Catalog。

这不是 Script Backend 获取缺口，也不是把 `partial` 改成 `completed` 的理由。

## 5. Script-backend 完整分母

Source Plan 选择 485 个 PHP 文件进入 `script_backend`；stage 为 `completed`，无 diagnostic，
输入 485、输出 3,909。为了把这一 producer universe 转成可独立验收的 Catalog，benchmark
Adapter 建立 `firmatlas.mapping.selected-source-inventory/v1`：

- 每个源固定 canonical path、size、content SHA-256；
- 每个文件必须是普通文件并被逐字节读取；
- 任一 result 非 completed 即拒绝整批；
- scope 为空即拒绝；
- source inventory identity 参与 Catalog 内容身份。

结果 Catalog：

| 字段 | 值 |
| --- | --- |
| Catalog | `discovery-catalog:2cc162721e60a07cf412923ac975daa7301af3b39e7815ac3ee868ade2246774` |
| source inventory | `799eff9743eb67ee1098f0420adb30aa9efd7f6ed6b55a8d0a8a55a4a338bf41` |
| coverage | completed |
| candidates | 3,978 |
| evidence | 4,021 |
| obligations | 0 |
| capabilities | reads/writes configuration、reads parameter、selects operation |

这里的 `**/*.php` 是构建报告所声明的逻辑 scope 标签；实际输入由 rootfs 下全部
`.php` 普通文件确定性枚举而来。它不表示浏览器路由可达性，也不表示非 PHP 文件已完成。

## 6. 典型文件 `www/__action.php`

目标文件 SHA-256：
`54612f24bed8c83f20b2429b39e17956a7627bbedfbb8bb7d38c3e1816335f57`。

确定性结果：

- 1 `script_source` + 338 `state_access` = 339 candidates；
- 356 EvidenceAtoms；
- 参数 `ACTION_POST`，namespace `form`，operation selector；
- capabilities 同时覆盖 `reads_parameter`、`selects_operation`、
  `reads_configuration`、`writes_configuration`；
- 页面可下钻到精确字节范围与行号，例如 `ACTION_POST` 在
  `text_utf8:bytes=188-213;lines=5:4-5:29`。

R2-33 的 producer-only 观察因此被 raw artifact → retained rootfs → AnalyzeRun → immutable
Catalog → Graph/API/Console 全链取代，而不是被事后改写为“当时已经完成”。

## 7. Corpus 与反事实

DAP-2695 以 `independent-holdout`、`real_firmware`、预期 inner BIN SHA-256 加入
`firmatlas.mapping.corpus/m1.5`。所需能力为 `reads_parameter`、`writes_configuration`；禁止
`constructs_request`，避免借 Frontend 证据通过。结果为 3,978 candidates / 4,021 evidence /
0 obligation，status `verified`。

如果继续沿用以下做法，会得到不可信结论：

- 只分析 `__action.php`：无法证明其他 484 个 PHP 文件没有 coverage failure；
- 直接使用完整 partial Catalog：会把无关的 dangling symlink/invalid UTF-8 当成 Script
  Backend 不完整，独立 dialect holdout 永远无法归责；
- 忽略完整 partial：会伪装成整固件完成；
- 借 DAP-3520 的 scope/evidence：会把同厂商旧样本冒充跨版本泛化；
- 将通用 GPL 包视为目标精确源码：会破坏字节谱系和版本边界。

当前双 Catalog 设计同时避免上述五个错误。

## 8. 限制与下一步

- 静态 PHP-XGI 事实不证明 Web server route、认证状态、运行时 action 可达性、漏洞或可利用性；
- 完整固件仍有 91 个 Frontend/correlation obligations；
- 非 UTF-8 页面是否是编码支持缺口、二进制伪装文本或资源误分类，需要独立样本归因；
- dangling symlink 可能是正常固件装配行为，不能直接修成不存在的问题；
- 官方未发布目标 checksum/signature，当前身份依赖对官方 URL 返回字节的本地 hash；
- GPL 包与目标版本无精确绑定，不能用于覆盖目标二进制的反事实。

本轮已足够关闭 Script-backend 独立 holdout，不应继续无休止添加同类 PHP 样本。下一步应
进入收敛审计：固定可发布的 Binwalk 镜像身份、增加一个非 ARM native registration holdout，
并从 AC9/DAP/FRITZ 中选择最小运行时可达验证。
