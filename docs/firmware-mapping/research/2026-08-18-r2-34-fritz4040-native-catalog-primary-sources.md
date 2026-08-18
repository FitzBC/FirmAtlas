# R2-34：FRITZ!Box 4040 Native Catalog 一手来源与证据边界

> 日期：2026-08-18
>
> 范围：OpenWrt 19.07.10 / AVM FRITZ!Box 4040 的官方制品、包谱系、native rpcd 注册表与 Catalog holdout 边界
>
> 研究基线：Git `d4968420dda0e52c2c3814d7438b9da1e8ced872`
>
> 结论状态：官方 acquisition 与 Producer 级证据已复核；independent Catalog gate 尚未闭合

## 1. 结论先行

OpenWrt 19.07.10 的 FRITZ!Box 4040 sysupgrade image 是适合 R2-34 的独立
`native_only` holdout，且已经不存在制品获取或身份不明问题：

- OpenWrt 官方 `sha256sums` 与 `profiles.json` 都把同一个 sysupgrade image 绑定到
  `cc34c5449138fd2f247cbd448922df01093b754ed0b9ca02150f302e044c0f00`；
- 官方 target manifest 明确包含 `rpcd-mod-file`、`rpcd-mod-iwinfo`、`rpcd-mod-luci`、
  `rpcd-mod-rrdns`；官方 package index 又给出这四个 `.ipk` 的版本、架构、大小和 SHA-256；
- 对四个 identity-matched `.ipk` 解包得到的 `usr/lib/rpcd/*.so`，与官方 sysupgrade rootfs
  中相同路径的文件逐字节同哈希；
- 当前 `discover_native_ubus_registrations(...)` 不接收 frontend candidate，直接从四个 ELF
  恢复 4 objects、24 methods、24 executable handlers，60 个 EvidenceAtoms，全部
  `completed` 且 0 diagnostics。

但这还不是一个通过 gate 的 Catalog。当前 `analysis_run` 虽执行
`native_ubus_registration`，却没有把该结果作为独立 `DiscoveryProducerBatch` 发布；只有
frontend 已经提出 ubus operation 时，`ubus_backend` 才会用 native registration 验证该
operation。对本样本的完整 rootfs 复跑显示，现有路径仅发布 24 个 native methods 中的 20 个，
以下四个没有 frontend seed，因而没有进入 Catalog：

```text
ubus://iwinfo/devices
ubus://iwinfo/info
ubus://iwinfo/phyname
ubus://iwinfo/survey
```

因此 R2-34 的正确出口不是继续寻找固件，也不是放宽 gate，而是增加一个证据保持的 direct
native-registration → Catalog Adapter，并用这四个未被 frontend 驱动路径发布的方法作为
independent holdout 的最小反例。

## 2. 事实分层

| 层级 | 已成立 | 未由该层证明 |
| --- | --- | --- |
| OpenWrt 官方事实 | release、target/profile、设备名、supported device、image 名与 SHA、target manifest 中的包版本、package index 中的 IPK 身份 | 本次是否真的下载到相同字节；rootfs 解包是否成功；FirmAtlas Producer/Catalog 是否完成 |
| 本地可重放实测 | 下载 SHA 匹配；IPK 安装路径与 rootfs 文件哈希一致；4 个 Producer 结果 completed；selected-root Inventory completed；一次完整 `auto-v20` Catalog 的真实 partial 状态 | 运行时可达、ACL/认证结果、实际调用者、漏洞存在或可利用性 |
| 尚待 R2-34 验收 | direct Adapter、24/24 独立 operation 投影、normalized capability、0 relevant obligation、completed gate Catalog、双次确定性重放 | 不能在实现前写成 verified；也不能把“未见 frontend reference”写成“隐藏/未认证接口” |

## 3. 官方制品身份与 Profile

### 3.1 Release target

- 官方 target 目录：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/>
- 官方 sysupgrade image：
  <https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/openwrt-19.07.10-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin>
- 官方 SHA 清单：
  <https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/sha256sums>
- 官方签名文件：
  <https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/sha256sums.asc>
- 官方 usign 签名文件：
  <https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/sha256sums.sig>
- 官方 profile：
  <https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/profiles.json>
- 官方 target manifest：
  <https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/openwrt-19.07.10-ipq40xx-generic.manifest>

官方制品身份为：

| 字段 | 值 |
| --- | --- |
| Release / revision | `19.07.10` / `r11427-9ce6aa9d8d` |
| Target | `ipq40xx/generic` |
| Package architecture | `arm_cortex-a7_neon-vfpv4` |
| Profile key | `avm_fritzbox-4040` |
| Title | `AVM Fritz!Box 4040` |
| Supported device | `avm,fritzbox-4040` |
| Filesystem / image type | `squashfs` / `sysupgrade` |
| Artifact size（本地下载） | 5,243,157 bytes |
| Artifact SHA-256（官方与本地一致） | `cc34c5449138fd2f247cbd448922df01093b754ed0b9ca02150f302e044c0f00` |
| `profiles.json` SHA-256（官方清单） | `5be7bf4788ff1447b21eb23b53e5a9ba329d2971dceebd1743284e5b5c322e1f` |
| target manifest SHA-256（官方清单） | `3956731cc2b222d1f728bacceaf139857c10c5314709afb14426c0ce0c121c96` |

`profiles.json` 还列出 `fritz-tffs` 与 `fritz-caldata` 两个 device packages。它同时记录
同型号 EVA image，但本轮只分析上表 sysupgrade image；不能把 EVA、initramfs 与 sysupgrade
的 SHA 或分析结果混用。

OpenWrt 官方 [release signature 指南](https://openwrt.org/docs/guide-user/security/release_signatures)
与[公钥列表](https://openwrt.org/docs/guide-user/security/signatures)把 19.07 release 绑定到：

- GPG fingerprint：`D9C6 901F 45C9 B868 5868 7DFF 28A3 9BC3 2074 BE7A`；
- usign Key-ID：`f94b9dd6febac963`。

官方 keyring 中也保留对应
[GPG 公钥](https://git.openwrt.org/keyring/plain/gpg/2074BE7A.asc)与
[usign 公钥](https://git.openwrt.org/keyring/plain/usign/f94b9dd6febac963)。独立复核解析
`sha256sums.sig` 得到相同 Key-ID，但当前环境没有 GnuPG/usign 验证程序；因此签名文件与 key
身份已确认，不等于本轮已经完成密码学验签。本轮只断言官方发布清单中的 SHA 与重新下载字节
相等；正式 acquisition ledger 还应记录签名验证工具、key fingerprint 和验证结果。

### 3.2 官方 manifest 的通信栈范围

target manifest 给出以下与本轮直接相关的精确版本：

```text
iwinfo             2019-10-16-07315b6f-1
libubus-lua        2022-02-21-b32a0e17-1
libubus20210603    2022-02-21-b32a0e17-1
luci               git-22.099.58928-786ebc9-1
rpcd               2020-05-26-67c8a3fd-1
rpcd-mod-file      2020-05-26-67c8a3fd-1
rpcd-mod-iwinfo    2020-05-26-67c8a3fd-1
rpcd-mod-luci      20201107
rpcd-mod-rrdns     20170710
ubus / ubusd       2022-02-21-b32a0e17-1
uhttpd             2020-10-01-3abcc891-1
```

manifest 是 target 级 build package 清单，不是 FRITZ!Box 4040 专属的逐文件 SBOM。一个可见
边界是 profile 的 `fritz-tffs`、`fritz-caldata` 没有出现在该 manifest 中；所以不能仅凭 manifest
断言某一 profile image 的全部 rootfs 内容。它可以证明 target build 的 rpcd 模块版本范围，
安装路径由下一节中官方 package index 固定的 `.ipk` 字节做本地解包验证，最终是否进入本次
sysupgrade artifact 则由实际 rootfs 文件哈希确认。

## 4. 官方 package identity 与预期 rootfs 路径

官方 package index：

- base feed：
  <https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/base/Packages.gz>
- luci feed：
  <https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/luci/Packages.gz>

四个 package 的官方身份和从其 `data.tar.gz` 解出的唯一 rpcd plugin 如下：

| Package | 官方 IPK SHA-256 | 官方 size | IPK 内安装路径 | 安装文件 SHA-256 |
| --- | --- | ---: | --- | --- |
| `rpcd-mod-file_2020-05-26-67c8a3fd-1_arm_cortex-a7_neon-vfpv4.ipk` | `8ef629ad7cd8f89d3c4e5ce1082fa9935c5bb01ed1e17c45aec3b057addb07aa` | 7,011 | `usr/lib/rpcd/file.so` | `91163cbcc4ae596288f29e3b513db2f57989784094c17e9ce126967e030c3379` |
| `rpcd-mod-iwinfo_2020-05-26-67c8a3fd-1_arm_cortex-a7_neon-vfpv4.ipk` | `7e5a14eace10cbc08bb4285a0eedf16b8296ded1b6fde75f362b5fc57c3a9ce3` | 7,159 | `usr/lib/rpcd/iwinfo.so` | `82afa783fc8e2f485742bb52823bea7833618be5f04198bd7f72da50bca91695` |
| `rpcd-mod-luci_20201107_arm_cortex-a7_neon-vfpv4.ipk` | `cd9e7114c2c059c9e94a1a32dff82327f289a30ca825da5dfe1c39c800ead800` | 12,854 | `usr/lib/rpcd/luci.so` | `1fa7d49d50408365cfd175206f811d4ffdf36d6fd6b9d3a5c7834ff45b23fc60` |
| `rpcd-mod-rrdns_20170710_arm_cortex-a7_neon-vfpv4.ipk` | `9b113e23fa0add2a821513d2d8e2c094579110cde201d5a81d5d757339a6fe24` | 4,304 | `usr/lib/rpcd/rrdns.so` | `3d726800cd7f2d0a204101eaac962cbafb05ff6c1a7682d139a758b456575a3b` |

对应 `.ipk` 的官方直链是在上述 feed 目录后追加 Filename，例如：

- <https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/base/rpcd-mod-file_2020-05-26-67c8a3fd-1_arm_cortex-a7_neon-vfpv4.ipk>
- <https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/base/rpcd-mod-iwinfo_2020-05-26-67c8a3fd-1_arm_cortex-a7_neon-vfpv4.ipk>
- <https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/luci/rpcd-mod-luci_20201107_arm_cortex-a7_neon-vfpv4.ipk>
- <https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/luci/rpcd-mod-rrdns_20170710_arm_cortex-a7_neon-vfpv4.ipk>

官方 index 对 `rpcd-mod-file` 和 `rpcd-mod-iwinfo` 的描述分别是 file/directory operation 与
iwinfo data 的 ubus calls；对 `rpcd-mod-luci` 的描述是 LuCI backend ubus RPC operations；
`rpcd-mod-rrdns` 是批量 reverse DNS lookup。这里的描述只用于通信类别归类，不能代替二进制
注册表证据。

隔离解包后的 sysupgrade rootfs 恰好包含上述四个 `usr/lib/rpcd/*.so`，每个 rootfs 文件哈希
都与 identity-matched IPK 内文件相同。这条相等关系把“官方 manifest 声称包含包”收紧为
“实际分析的 artifact 内确实是官方 package 的同一 plugin 字节”。四个文件均为 little-endian
ELF32 ARM EABI5 shared object，正好落在当前
`openwrt-rpcd-arm32-static-object/v1` Profile 的适配范围内。

官方 feed 另外发布 `rpcd-mod-rpcsys`，但 19.07.10 target manifest 没有 `rpcd-mod-rpcsys`，
本次 sysupgrade rootfs 的 `/usr/lib/rpcd` 也没有 `rpcsys.so`。feed 中“可安装”不能升级为本
artifact 中“已安装”；本轮四插件 denominator 由 manifest 与实际 rootfs 的交集确定。

### 4.1 官方 rpcd 源码对插件位置的定义

OpenWrt v19.07.10 的
[rpcd package Makefile](https://github.com/openwrt/openwrt/blob/v19.07.10/package/system/rpcd/Makefile#L13-L18)
把源码固定到完整 commit
`67c8a3fda26e441d3ec4a19f50ac72eca8deb14b`。同一 Makefile 的
[BuildPlugin/install 规则](https://github.com/openwrt/openwrt/blob/v19.07.10/package/system/rpcd/Makefile#L56-L97)
把模块 `.so` 安装到 `/usr/lib/rpcd/`。该精确 commit 的官方 rpcd 源码进一步定义：

- [`plugin.h`](https://github.com/openwrt/rpcd/blob/67c8a3fda26e441d3ec4a19f50ac72eca8deb14b/include/rpcd/plugin.h#L41-L45)：
  可执行插件目录是 `/usr/libexec/rpcd`，动态库插件目录是 `/usr/lib/rpcd`；
- [`plugin.c` dynamic plugin scan](https://github.com/openwrt/rpcd/blob/67c8a3fda26e441d3ec4a19f50ac72eca8deb14b/plugin.c#L505-L543)：
  遍历 `/usr/lib/rpcd` 的 regular files 并交给 `dlopen()`，源码不以 `.so` 后缀作为语义门；
- [`plugin.c` executable discovery](https://github.com/openwrt/rpcd/blob/67c8a3fda26e441d3ec4a19f50ac72eca8deb14b/plugin.c#L416-L469)：
  可执行插件通过 `plugin-path list` 给出 JSON 方法描述；
- [`plugin.c` executable call](https://github.com/openwrt/rpcd/blob/67c8a3fda26e441d3ec4a19f50ac72eca8deb14b/plugin.c#L200-L235)：
  运行形态是 `plugin-path call <method>`，请求 JSON 经 stdin 输入，stdout 作为 JSON 结果解析。

这些源码是“rpcd 支持哪些插件位置/调用协议”的一手事实，不证明本 artifact 实际包含
`/usr/libexec/rpcd` executable plugin。本轮 rootfs denominator 只包含已实测存在的四个 dynamic
plugins；若后续发现 executable plugin，必须按另一类 Producer/证据门处理，不能套用 ELF
registration table 的 completed 状态。

## 5. 本地隔离重放

### 5.1 临时工作区与 Extraction

本轮只读验证使用仓库外的一次性临时目录：

```text
/tmp/firmatlas-r2-34-fritz.BrvvVG/
  openwrt-19.07.10-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin
  extracted/_firmware.bin.extracted/squashfs-root/
  fritz-analysis.json

/tmp/firmatlas-r2-34-ipk.AeiLnM/
  rpcd-mod-*.ipk
```

这些路径不是 retained corpus cache，不可进入 corpus identity，也不保证跨会话仍存在。若仍在
本机，可用于本轮后续只读复核；正式测试必须从官方 URL 重新摄取到受控的非 Git cache，并以
官方 artifact SHA 为入口断言。

固定 Binwalk 2.2.1 容器完成了 SquashFS 解包，exit code 0，execution fingerprint 为
`4201ad94bb221b6b01e2439a2a837429c94a376f2642d787e9def2be4771cc0e`。若把整个
Binwalk wrapper destination 当 inventory root，会因为 7 个 rootfs-internal symlink 被错误地
相对 wrapper 解析而得到 partial；选择真正的 `squashfs-root` 后，Inventory 为：

| 指标 | 结果 |
| --- | --- |
| Coverage | `completed`，0 diagnostics |
| Entry / observed / processed | 1,061 / 1,061 / 1,061 |
| Processed bytes | 8,829,901 |
| Inventory SHA-256 | `a8c4722264d6abb5d918db514d65c243f743a5dd23d376d6e9e3eeeeb48d8f1c` |

这说明制品可解包且 selected root 可完整 inventory；同时也提示 raw-artifact workflow 必须保留
`artifact → selected root` lineage，不能把 wrapper-level partial 静默改写为 success。

### 5.2 Native registration 精确结果

当前 Validator 的证据门为：

```text
rpc_plugin dynamic symbol
→ executable init pointer
→ verified ubus_add_object PLT call
→ object / object-type method table agreement
→ bounded object and method strings
→ executable handler pointer
```

四个结果均为 `completed`、`registration_coverage_complete=true`、0 diagnostics：

| Source | Object / type | Methods 与 handler identity | EvidenceAtoms |
| --- | --- | --- | ---: |
| `usr/lib/rpcd/file.so` | `file` / `luci-rpc-file` | `read@0x00001b4c`, `write@0x000021dc`, `list@0x00001d4c`, `stat@0x00002120`, `md5@0x00001f20`, `remove@0x00002080`, `exec@0x00002354` | 17 |
| `usr/lib/rpcd/iwinfo.so` | `iwinfo` / `luci-rpc-iwinfo` | `devices@0x0000181c`, `info@0x00001300`, `scan@0x00001fe8`, `assoclist@0x00002404`, `freqlist@0x000021e4`, `txpowerlist@0x00001ae8`, `countrylist@0x00001b14`, `survey@0x00002210`, `phyname@0x00000d40` | 21 |
| `usr/lib/rpcd/luci.so` | `luci-rpc` / `rpcd-luci` | `getNetworkDevices@0x000035e4`, `getWirelessDevices@0x00002be4`, `getHostHints@0x00004adc`, `getDUIDHints@0x00004804`, `getBoardJSON@0x00002a60`, `getDSLStatus@0x000036d8`, `getDHCPLeases@0x00004440` | 17 |
| `usr/lib/rpcd/rrdns.so` | `network.rrdns` / `rpcd-rrdns` | `lookup@0x0000124c` | 5 |

总 capability 分布：

```text
identifies_rpcd_plugin_init = 4
calls_ubus_add_object       = 4
registers_ubus_object       = 4
registers_ubus_method       = 24
binds_ubus_handler          = 24
```

四个结果按 artifact SHA、source identity、对象、方法、handler 和 evidence ID 规范化后的 replay
SHA-256 为
`b759f2d513008737b4e71c9be9d3bed17f8ddab6caa80c087429f3b6e1bd5d17`。
它是本轮本地重放摘要，不是 OpenWrt 官方哈希。

## 6. 完整 Catalog 复跑揭示的真实缺口

对 selected root 运行 `firmatlas.mapping.profile/auto-v20`，不是只运行四个插件，得到：

| 指标 | 结果 |
| --- | --- |
| Analysis run | `mapping-analysis-run:263d16062d560d35937220263cfaebf40b4c2c80cbf2dd64a5eabd075d232288` |
| Catalog | `discovery-catalog:1c5abc919cc75fe79f85a87ece71cc75f3993d7a3daf86811bdc9f068f1cc6ec` |
| Catalog coverage | `partial` |
| Candidates / parameters / evidence | 1,210 / 220 / 8,475 |
| Open obligations | 117 |
| Native registration stage | `completed`, 4 inputs / 4 outputs |
| Ubus backend stage | `partial`, 8 inputs / 56 bindings |

该 JSON 的本地文件 SHA-256 为
`72ddaf7c0208421a6a5b510f265e4521e9029391cf75219accf59091b5708484`。
它同样只是当前代码与临时路径下的可重放输出身份，不是应提交的 golden。

Catalog 内有 20 个 unique `verified_native_registration` logical operations，且其 evidence 引用
native registration atoms；但它们都是先由 frontend operation 提出，再被 native result 验证。
直接比较 24 个注册方法与这 20 个 Catalog identity，差集正是第 1 节四个 `iwinfo` operation。

代码路径与结果一致：

1. `analysis_run` 独立执行 `native_ubus_registration`；
2. 随后从 frontend 结果构造 `operations`；
3. 只有 `operations` 非空才调用 `discover_ubus_backend_graph(...)`；
4. Catalog batches 只包含 `ubus_backend`，没有 direct native-registration batch。

所以当前系统已经能“验证前端已知的 native owner”，但不能“从 native registrar 独立发布完整
operation universe”。这不是字符串匹配精度问题，也不是新的 acquisition gap。

本次全量 Catalog 还因 LuCI frontend template coverage、frontend reachability、set-difference hit
budget 和未关闭义务而 partial。因此不能只加四个 candidates 就宣称整个 `auto-v20` Catalog
completed。R2-34 可以采用明确的 native holdout profile/scope，或者同时解决所有 required batch
coverage；无论采用哪条路径，corpus gate 仍要求 Catalog 本身 completed。

## 7. Independent native-only 的证据边界

### 7.1 已可支持的主张

- 四个官方 package plugin 在该官方 sysupgrade artifact 中存在且字节身份可交叉核验；
- 当前 ARM32 rpcd Profile 对这四个文件完整处理，没有 partial/unsupported；
- 每个 object/method 都有注册表与 executable handler pointer 证据；
- Producer discovery 本身不需要 frontend candidate；
- 至少四个注册 operation 未被当前 frontend-driven Catalog seam 发布，可稳定检验 direct Adapter。

### 7.2 不能支持的主张

- “该固件没有 LuCI/frontend”：manifest 和 rootfs 明确包含 LuCI；
- “四个 operation 没有任何调用者”：这里只完成当前静态 frontend scope 的负引用比较；
- “隐藏接口”“未认证接口”或“漏洞”：未做 runtime reachability、ACL effective policy、认证与
  exploit 验证；
- “24 个接口均可经 HTTP 调用”：ubus object registration 不等于 HTTP bridge 暴露；
- “签名已验证”：本轮只核对官方 SHA，未完成 release signature verification；
- “Catalog 已完成”：当前全量 Catalog 明确为 partial、117 open obligations。

因此文档和 UI 中宜使用“native registration without frontend reference in completed comparison
scope”，不能简化成“hidden endpoint”。

## 8. 建议的 direct Catalog Adapter 验收契约

Adapter 应是命名空间与 Catalog 投影层，不应重新解释 ELF：

```text
input
  = completed NativeUbusRegistrationResult
  + source belongs to current firmware artifact / selected-root inventory

candidate identity
  = ubus://<object_name>/<method_name>

candidate claim
  = supported only when object + method + executable handler proof are all present

evidence
  = reuse original init / ubus_add_object / object / method / handler EvidenceAtom IDs
  = do not synthesize evidence bytes and do not accept string-only native hints

capabilities
  = preserve registers_ubus_object, registers_ubus_method, binds_ubus_handler
  = normalize endpoint/handler semantics for the existing corpus contract only through
    an explicit versioned mapping to mentions_endpoint and binds_handler

frontend dependency
  = forbidden for candidate creation
  = frontend comparison may add attribution, but may not decide candidate existence
```

最小验收断言：

1. artifact SHA 必须等于官方 sysupgrade SHA；selected-root Inventory 必须 completed；
2. `usr/lib/rpcd/{file,iwinfo,luci,rrdns}.so` 四个 source SHA 必须与第 4 节一致；
3. direct Adapter 必须发布 4 objects / 24 unique `ubus://` methods / 24 handler identities；
4. 第 1 节四个 `iwinfo` operation 必须在不传 frontend result 时仍存在；
5. 任一 source mismatch、partial registration、method handler 非 executable 时 fail closed；
6. scoped Catalog coverage 为 completed，相关 open obligations 为 0；
7. corpus sample 要求 `mentions_endpoint + binds_handler` 且禁止 `constructs_request`，不得靠
   frontend evidence 满足 forbidden-capability 负断言；
8. 同一输入连续运行两次，Catalog ID、candidate IDs、evidence IDs 和 report SHA 完全一致；
9. 再用已有 OpenWrt AC9 19.07.8 做同 Profile regression，但 FRITZ 保持独立 holdout，不能
   用 AC9 或 X5000R 的 pass 状态替代。

## 9. 可重复核验命令

```bash
research_dir=/path/to/non-git-cache/r2-34-fritz4040
mkdir -p "$research_dir"

target_base=https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic
artifact=openwrt-19.07.10-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin

curl -fsS "$target_base/sha256sums" | rg "$artifact"
curl -fL "$target_base/$artifact" -o "$research_dir/$artifact"
shasum -a 256 "$research_dir/$artifact"

curl -fsS "$target_base/profiles.json" \
  | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["profiles"]["avm_fritzbox-4040"], indent=2))'
curl -fsS "$target_base/openwrt-19.07.10-ipq40xx-generic.manifest" \
  | rg '^(rpcd|rpcd-mod|libubus|ubus|ubusd|iwinfo|luci|uhttpd)'

base_feed=https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/base
luci_feed=https://archive.openwrt.org/releases/19.07.10/packages/arm_cortex-a7_neon-vfpv4/luci
curl -fsS "$base_feed/Packages.gz" | gzip -dc \
  | awk 'BEGIN{RS=""} /Package: rpcd-mod-(file|iwinfo)/ {print}'
curl -fsS "$luci_feed/Packages.gz" | gzip -dc \
  | awk 'BEGIN{RS=""} /Package: rpcd-mod-(luci|rrdns)/ {print}'
```

解包与 AnalyzeRun 应继续使用仓库固定、隔离且禁网的 Extraction Worker。正式记录必须包含
artifact SHA、image digest、tool version、execution fingerprint、selected root、Inventory SHA、
profile ID、AnalysisRun ID、Catalog ID 与两次输出摘要；不要把官方固件、解包 rootfs 或 `.ipk`
提交到 Git。

## 10. 与既有记录的关系

- [M1-26 Native rpcd/ubus 注册表](../progress/2026-08-09-m1-26-native-ubus-registration.md)
  定义了 registrar/table/handler 证据门，但其代表性结果是 OpenWrt AC9；
- [R2-33 一手来源研究](./2026-08-18-r2-33-representative-corpus-primary-sources.md)
  首次把 FRITZ!Box 4040 选为新 holdout，并指出 direct Adapter 缺口；
- [R2-33 scope-aware corpus gate](../progress/2026-08-18-r2-33-scope-aware-corpus-gate.md)
  已用现有 DAP-3520/X5000R 样本关闭当前五类 gate，但明确不能把该 pass 状态当作 FRITZ
  holdout 已完成；
- [`representative-corpus.json`](../samples/representative-corpus.json) 中的
  `openwrt-fritz4040-native-only-holdout` 已固定官方 artifact SHA 和 pending 状态。

本轮新增的关键证据是官方 IPK → 安装文件 → sysupgrade rootfs 的逐字节谱系，以及完整
`auto-v20` 复跑得到的 20/24 frontend-driven 投影差集。它们把 R2-34 从“候选建议”收紧为一个
可写成测试的 Adapter acceptance contract，同时保留 partial Catalog 与 117 条义务的真实阶段，
没有把未解决状态改写成 hindsight-only success。
