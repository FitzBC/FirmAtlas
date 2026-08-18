# R2-33：代表性 Corpus Gate 原始来源研究

> 日期：2026-08-18
> 范围：只研究 `script_backend` coverage gap 与 `native_only` acquisition gap 的真实固件候选
> 结论状态：候选与获取路径已收敛；本文不修改 corpus、Producer 或产品代码
> 研究起点：Git `76354804488b1a43068e66d6f689665f828e9a11`

## 1. 结论先行

不需要再把两个缺口都当成“尚未找到固件”。一手来源勘查得到一个独立、仍可下载且能被
当前分析器消费的最强组合；仓库已有 OpenWrt AC9 制品则提供低成本复核与失败回退：

| Gate 类别 | 首选真实制品 | 结论 | 仍需的工程动作 |
| --- | --- | --- | --- |
| `script_backend` | D-Link DAP-2695 Rev.A `1.20B20 RC101` | **首选新真实样本**。厂商固件与 GPL source package 仍在线；`__action.php` 的 `$ACTION_POST`/XGI dispatcher 被当前 Producer 完整解析，直接具备 `reads_parameter` 与 `writes_configuration`。 | 正式摄取时固定外层 ZIP 与内层 BIN 双哈希，跑完整 Inventory/AnalyzeRun/Catalog；只有 completed + 0 obligation 才晋级。OpenWrt AC9 18.06.7 可作为已经完成的 LuCI fallback。 |
| `native_only` | OpenWrt 19.07.10 / AVM FRITZ!Box 4040 | **首选新真实样本；acquisition 已解决**。官方签名清单与 SHA 可核验；4 个 ARM rpcd `.so` 在没有前端 anchor 的情况下独立恢复 4 objects / 24 methods / handlers，全部 completed。 | 增加 direct native-registration Catalog Adapter，以原 EvidenceAtom 发布 native operation/handler facts；现有 frontend-driven ubus backend seam 不能代表 independent discovery。OpenWrt AC9 19.07.8 是同 Profile 的复核样本。 |

因此，R2-33 最小且证据最强的路径是：用 DAP-2695 增加 vendor PHP-XGI dialect，用
FRITZ!Box 4040 验证独立 Native registry，再用已有 AC9 结果做跨设备/同 Profile 复核。
`native_only` 应从 acquisition gap 收紧为一个明确的 Adapter/coverage 工作项；无需继续寻找
不明来源的镜像。

## 2. Gate 判定口径

[M1-11 记录](../progress/2026-08-09-m1-11-representative-corpus-gate.md)和
[`corpus_report.py`](../../../src/firmatlas/mapping/corpus_report.py)要求 real firmware 同时满足：

1. Catalog 的 firmware Artifact SHA-256 与样本声明一致；
2. Catalog coverage 是 `completed`；
3. required evidence capabilities 全部存在，forbidden capabilities 全部缺席；
4. 没有 open obligation。

合成 fixture、漏洞文本、只剩 rootfs 的派生目录都不能把类别晋级为 `verified`。当前机器报告
仍将 `script_backend` 记为 `coverage_gap`、`native_only` 记为 `acquisition_gap`，见
[M1-11 report](../samples/m1-11-representative-corpus-report.json)。这份状态是在 M1-24/26
之前的样本编排决定下形成的，不等于仓库后来没有取得更强制品和证据。

## 3. `script_backend` 首选：D-Link DAP-2695 Rev.A

### 3.1 厂商制品、源码与身份

- 厂商归档目录：<https://ftp.dlink.de/dap/dap-2695/archive/driver_software/>
- 固件 ZIP：<https://ftp.dlink.de/dap/dap-2695/archive/driver_software/DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip>
- Rev.A GPL/source 目录：<https://ftp.dlink.de/dap/dap-2695/driver_software/>
- GPL source package：<https://ftp.dlink.de/dap/dap-2695/driver_software/DAP-2695_sw_reva_GPLcode.tar.gz>
- 版本：`1.20B20 RC101`；ZIP 名称标记 `20190115`，厂商目录记录该归档文件。
- 本次下载 ZIP SHA-256：
  `5a1a4e7f45b0a6fa2d58da0142a76dc153f3e3d3fe99bc1fdf99ecc0aae77f8e`。
- ZIP 内 `DAP-2695_120B20RC101.bin` SHA-256：
  `11479c2dcce46af141954a067a0c0355d76bd49ed1793894b1d5960ac5300609`。

2026-08-18 从厂商 HTTPS 端重新下载后的 ZIP 为 10,414,440 bytes；内层 BIN 为
10,412,224 bytes。D-Link 目录未发布对应 SHA 或签名，因此这两个摘要是本次 acquisition
identity，不应写成“厂商签名证明”。正式摄取必须重新计算并要求双哈希一致；Catalog 的
`firmware_artifact_sha256` 应绑定实际分析的内层 BIN，而 archive hash 进入 acquisition lineage。

后台完整解包使用一次性临时工作区，验证后已清理，没有可引用的 retained rootfs；独立来源
复核当前只暂存下载 ZIP 于 `/tmp/firmatlas-r2-33.jjFx51/dap2695.zip`，它不是稳定缓存或提交
制品。可重复 rootfs 内路径是 `<dap2695-rootfs>/www/__action.php`。正式 AnalyzeRun 必须按
官方 URL 重新摄取到受控、非 Git 的 mapping workspace，不能把临时路径写入 corpus identity。

### 3.2 为什么它精确覆盖现有缺口

隔离解包可恢复 SquashFS 4.0/LZMA rootfs，包含 485 个 PHP 与 96 个 shell 文件。
`www/__action.php` 的 SHA-256 为
`54612f24bed8c83f20b2429b39e17956a7627bbedfbb8bb7d38c3e1816335f57`，包含
`$ACTION_POST` dispatcher 和 `query/queryEnc/set/setEnc` XGI 状态访问构造。用当前
`discover_script_backend(...)` 对该文件做只读重放得到：

| 指标 | 结果 |
| --- | ---: |
| Coverage / diagnostics | `completed` / 0 |
| Parameters | 1 |
| State accesses | 338 |
| EvidenceAtoms | 356 |
| `reads_parameter` / `selects_operation` | 9 / 9 |
| `reads_configuration` / `writes_configuration` | 145 / 193 |
| 参数化写入 | 76 |

静态 selector 包括 `__sample`、`st_ap`、`st_ap_test`、`st_logs`、`sys_setting`、
`tool_admin`、`tool_sntp`。这与旧 corpus sample 对 script backend 的
`reads_parameter + writes_configuration` 门限精确一致，而且是厂商原始固件，不是
Binwalk-derived-only 目录。

它现在仍只是**最强候选**，不是已通过 gate：正式实现还必须跑完整 Extraction/Inventory/
AnalyzeRun/Catalog，证明 input scope completed 且 0 open obligation。单文件 Producer 的
completed 不能代替整机 Catalog completed。研究阶段没有生成 DAP-2695 Catalog ID；可复现的
Catalog 前置数据是 outer/inner artifact hash、关键脚本 hash、上述 Producer counts 与
0 diagnostics，不能用“尚无 Catalog”伪装成空 Catalog 或 completed Catalog。

### 3.3 已有 OpenWrt AC9 18.06.7 fallback

若新制品摄取暴露非脚本范围的 Extractor/Catalog 缺口，仓库已有的 OpenWrt 18.06.7 / Tenda
AC9 可先关闭 LuCI 子类，同时保留 DAP-2695 为 vendor-XGI holdout：

- 官方制品：<https://downloads.openwrt.org/releases/18.06.7/targets/bcm53xx/generic/openwrt-18.06.7-bcm53xx-tenda-ac9-squashfs.trx>
- 官方 SHA：<https://downloads.openwrt.org/releases/18.06.7/targets/bcm53xx/generic/sha256sums>
- Artifact SHA-256：`2911048377aa17b44683b5f406fe3f6e62a5247ba7d4ab72cd3cb91fbf2a3184`；
- [M1-24 报告](../samples/m1-24-openwrt-ac9-version-diff.json)：Inventory completed
  1,131 entries；7 Lua controllers；18 `script_route`；43 candidates、19 parameters、
  0 obligations；Catalog completed；
- capabilities：`registers_route`、`binds_handler`、`reads_parameter`、
  `maps_namespace`、`listens_on`、`mentions_endpoint`。

该 fallback 已满足 real-firmware gate，但代表 LuCI/Lua dialect，不覆盖 vendor XGI 的大量配置
读写。优先执行 DAP-2695 可增加真正独立的架构与厂商覆盖。

### 3.4 其他备选

1. **DAP-3520 1.17 RC047**：仓库已有 artifact SHA
   `0de4c72f3d7ba1dc6419328be355b51e39d1dae0a8ad14918f0e4eb4699499f9` 的
   real-firmware Catalog，包含 273 candidates、288 evidence、0 obligation 和完整 XGI
   read/write capability，但没有固定仍在线的同版本官方 URL。
2. **DAP-3520 1.16 RC040**：官方固件与 GPL package 仍在线于
   <https://ftp.dlink.de/dap/dap-3520/driver_software/>，但其 big-endian SquashFS 3.0 需要
   当前固定 Binwalk Worker 未包含的 `sasquatch`；选择它会把 corpus gate 变成 extractor
   compatibility 工作，故不如 DAP-2695 收敛。
3. **DSL-2877AL A1 1.00.19AU/1.00.20AU**：vendor ASP 与 Shell CGI 很有价值，继续作为
   holdout；当前不能作为首选 acquisition，原因见第 5 节。

## 4. `native_only` 首选：OpenWrt 19.07.10 / FRITZ!Box 4040

### 4.1 官方制品与可验证身份

- 官方归档：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/>
- 原始制品：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/openwrt-19.07.10-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin>
- 官方 `profiles.json`：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/profiles.json>
- 官方 SHA 文件：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/sha256sums>
- 签名文件：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/sha256sums.asc>
- 包清单：<https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/openwrt-19.07.10-ipq40xx-generic.manifest>
- Artifact SHA-256：`cc34c5449138fd2f247cbd448922df01093b754ed0b9ca02150f302e044c0f00`。

2026-08-18 官方制品 HEAD 返回 HTTP 200、content length 5,243,157 bytes。官方
`profiles.json` 将 image title 标为 `AVM Fritz!Box 4040`，并给出相同 SHA；manifest 列出
`rpcd`、`rpcd-mod-file`、`rpcd-mod-iwinfo`、`rpcd-mod-luci`、`rpcd-mod-rrdns`、
`libubus`、`ubus` 与 `ubusd`。这三项一手来源共同确定设备、release、包范围和制品字节身份。
隔离下载重新计算出的 SHA 与官方值相同；本研究没有把“签名文件存在”写成“已经完成 GPG
验签”。正式摄取应按 OpenWrt 官方
[release signature 指南](https://openwrt.org/docs/guide-user/security/release_signatures)验证
`sha256sums.asc` 或 `sha256sums.sig`，并记录使用的 signing-key fingerprint。

### 4.2 精确 Native registry 重放

[M1-26 Validator](../progress/2026-08-09-m1-26-native-ubus-registration.md)从 ELF32 ARM
原始字节恢复
`rpc_plugin → init → ubus_add_object → object/type/method table → executable handler`；
接口不接收 frontend candidate。对 FRITZ!Box 4040 rootfs 中全部 4 个适配范围内 rpcd native
plugin 的独立重放结果为：

| 插件 | Object | 精确 Method | 结果 |
| --- | --- | --- | --- |
| `usr/lib/rpcd/file.so` | `file` | `read`, `write`, `list`, `stat`, `md5`, `remove`, `exec` | completed / 0 diagnostics |
| `usr/lib/rpcd/iwinfo.so` | `iwinfo` | `devices`, `info`, `scan`, `assoclist`, `freqlist`, `txpowerlist`, `countrylist`, `survey`, `phyname` | completed / 0 diagnostics |
| `usr/lib/rpcd/luci.so` | `luci-rpc` | `getNetworkDevices`, `getWirelessDevices`, `getHostHints`, `getDUIDHints`, `getBoardJSON`, `getDSLStatus`, `getDHCPLeases` | completed / 0 diagnostics |
| `usr/lib/rpcd/rrdns.so` | `network.rrdns` | `lookup` | completed / 0 diagnostics |

总计 4 objects、24 methods、60 EvidenceAtoms。每个 object/method/handler 都有原始字节
EvidenceAtom，capability 分布为：

```text
identifies_rpcd_plugin_init = 4
calls_ubus_add_object       = 4
registers_ubus_object       = 4
registers_ubus_method       = 24
binds_ubus_handler          = 24
```

代表接口包括 `ubus://file/read`、`ubus://file/exec`、`ubus://iwinfo/scan`、
`ubus://luci-rpc/getBoardJSON` 与 `ubus://network.rrdns/lookup`。这里证明的是“Native 注册表
可以不依赖前端线索独立发现”，不是说固件没有 LuCI、这些操作一定无前端消费者，或它们运行时
可达/未认证/有漏洞。

完整下载与 rootfs 也只存在于一次性临时工作区并已清理，没有 retained FRITZ image/rootfs
绝对路径。可重复的内部目标是
`<fritz4040-rootfs>/usr/lib/rpcd/{file,iwinfo,luci,rrdns}.so`；复跑必须从官方 URL 下载并先
验证 artifact SHA，再交给固定 Extraction Worker。

### 4.3 当前缺的不是固件，而是 Catalog Adapter

当前 `analysis_run` 仅在存在 frontend ubus logical operation 时组装 `ubus_backend`；
`NativeUbusRegistrationResult` 没有一个独立、证据保持的 Catalog 投影。直接 registration 发布
`registers_ubus_method` / `binds_ubus_handler`，而旧 `native_only` lead 的抽象门限仍是
`mentions_endpoint` / `binds_handler`。因此今天不能把“Validator completed”直接写成“corpus
sample verified”。建议的 Adapter 契约是：

```text
input                   = completed NativeUbusRegistrationResult only
frontend anchor         = forbidden
candidate identity      = ubus://<object>/<method>
normalized capabilities = mentions_endpoint, binds_handler
preserved capabilities  = registers_ubus_object, registers_ubus_method,
                          binds_ubus_handler
evidence provenance     = 原 registration/method/handler EvidenceAtom IDs
coverage                = 所有适配范围内 rpcd *.so completed；0 adapter obligation
```

Adapter 只能做命名空间归一化与 EvidenceAtom 复用，不能把 native 字符串共现升级为 handler，
也不能依赖 frontend reference 才构造 operation。这样才能真正把 acquisition gap 变成可审计的
verified native registry。

### 4.4 AC9 同 Profile 复核

仓库已有 OpenWrt 19.07.8 / Tenda AC9 官方制品
`d40b191c95c5b6e43358785d6c6e9d7915296e9a954d27fbc1936bdf48568ec9`，同样恢复 4 个
completed rpcd 插件和 24 个注册方法。现有 71 个 JS/HTML 静态 scope 与 registrar 结果比较后，
有 4 个 `iwinfo` operation 没有静态前端 pair：

- `ubus://iwinfo/devices → usr/lib/rpcd/iwinfo.so@0x0000181c`
- `ubus://iwinfo/info → usr/lib/rpcd/iwinfo.so@0x00001300`
- `ubus://iwinfo/survey → usr/lib/rpcd/iwinfo.so@0x00002210`
- `ubus://iwinfo/phyname → usr/lib/rpcd/iwinfo.so@0x00000d40`

该 negative-reference 只针对 completed static scope，不代表隐藏或不可达。AC9 非常适合做
Adapter 的同 Profile regression；FRITZ!Box 4040 则避免把 native-only gate 再次绑定到唯一 AC9
设备家族。

### 4.5 其他阳性与负控

- **TOTOLINK X5000R**：已有 residual native-only 与 scope-aware positive，适合当前 corpus 的
  既有阳性；但部分 MIPS inline binding 由 frontend selector anchor 驱动，不能替代 FRITZ 的
  independent-registry holdout。
- **OpenWrt 24.10.1 / FRITZ!Box 4040**：官方制品
  <https://downloads.openwrt.org/releases/24.10.1/targets/ipq40xx/generic/openwrt-24.10.1-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin>
  的 SHA-256 是
  `3628542533a9f0bd333c404e576412da1d5226b8b28a4915a83ff1e02db6423c`。同四个插件继续
  completed，但新增 `ucode.so` 使用不同 init 语义而被当前 Validator 标为 partial。它是很好
  的现代升级负控：在增加 ucode plugin 语义前，gate 必须 fail closed。
- **仅凭 native 字符串或漏洞接口名**：没有 registrar/table/callsite/handler 链，不能满足
  `binds_handler` 或 `binds_ubus_handler`。

## 5. DSL-2877AL：高价值 dialect holdout，但当前下载失效

D-Link Australia 官方目录仍列出：

- `Firmware_1.00.19AU_20161003`
- `Firmware_1.00.20AU_20180327`

目录：<https://files.dlink.com.au/products/DSL-2877AL/REV_A/Firmware/>。
D-Link 官方安全公告也明确指向 1.00.20AU 的原始 URL：
<https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10122>。

但是在 2026-08-18，两个版本子目录与公告给出的 `.bin` 直链均返回 HTTP 404。仓库只有
BM-2024-00096/00134 的既有 Binwalk 派生 rootfs，没有可重新哈希并与厂商下载核对的原始
`.bin`。因此：

- 官方目录与公告足以证明型号、版本、发布日期和历史原始 URL；
- 它们不足以证明当前本地 rootfs 的 raw Artifact SHA 或当前可重复 acquisition；
- [M1-06B 结果](../samples/m1-06b-script-backend-summary.json)应继续保持
  `derived_firmware`，不能因路径/版本吻合而改成 `real_firmware`。

D-Link 的官方 GPL 页面
<https://tsd.dlink.com.tw/gpl2008.asp>说明：找不到在线源码时，可按 SKU 书面请求相应 GPL/LGPL
源码，厂商可收取介质/邮寄成本。该书面 offer 只保证适用 GPL/LGPL 的对应源码，不保证会提供
完整 proprietary firmware、ASP 控制器或与当前 BM rootfs 字节一致的 raw image；所以它是合法
获取补充路径，不是 corpus identity 的替代品。

## 6. 法律与制品治理

OpenWrt 官方 license 页面 <https://openwrt.org/license>说明 build environment 默认 GPLv2，
预编译镜像还捆绑采用多种开源许可证或 public-domain 条款的第三方组件；具体组件应以 source
archive/package license 为准。官方源码仓库也保留 GPL-2.0 与其他 license 文本：
<https://git.openwrt.org/openwrt/openwrt/tree/LICENSES>。

对本 corpus 的工程约束是：

1. 分析可以固定官方 URL、官方 SHA、下载日期和本地 SHA；
2. 不把“OpenWrt 镜像总体可下载”简化成“每个组件均为同一许可证”；
3. 若重新分发镜像、插件或源码，逐组件履行对应许可证和 notice/source 义务；
4. D-Link proprietary raw firmware 不提交到本研究仓库，除非厂商条款或明确授权允许；研究库
   只保存身份、来源和可重放摘要；
5. D-Link GPL written request 获得的材料需保留请求时间、SKU、交付介质、原始哈希和 license
   文件，且不能把 GPL source package 冒充设备 raw firmware。DAP-2695 当前在线的 Rev.A GPL
   archive 早于本次 2019 firmware 文件，也不能在没有源码版本/构建谱系核对时宣称字节对应。

## 7. 建议的 R2-33 验收顺序

1. 从厂商 URL 重新摄取 DAP-2695，核对 outer ZIP / inner BIN 双哈希；完整重放两次并固定
   Extraction fingerprint、Inventory SHA、Catalog ID、coverage、candidate/evidence/obligation
   counts。只有 completed + 0 obligation 才把它加入 `script_backend` real-firmware sample。
2. 若 DAP-2695 整机范围出现与 script backend 无关的阻塞，用已经 completed 的 OpenWrt
   18.06.7 AC9 Catalog 先关闭 LuCI 子类；DAP-2695 保持 vendor-XGI holdout，不能被遗忘。
3. 为 direct Native registration 增加证据保持的 Catalog Adapter；用 FRITZ!Box 4040 的 4 个
   `.so` 验证 discovery 不接收 frontend anchor、24 methods 全部投影且 0 adapter obligation。
4. X5000R scope-aware native-only 可以作为当前已有阳性并帮助 gate 收敛，但其 frontend-seeded
   MIPS 路径限制必须可见；FRITZ 是独立 registry holdout/下一 Adapter 出口，不能被 X5000R
   的 pass 状态替代。
5. Gate 通过后仍保留 DSL-2877AL vendor ASP、OpenWrt 24.10.1 ucode partial、厂商 AC9
   registrar 为 holdout/负控；它们验证 dialect、ABI、ISA 与升级泛化。
6. 每步运行 corpus 专项、全量 Python/Console/build，并通过本地 API 与浏览器检查类别状态；
   当前研究轮不改代码，所以本文不声称 gate 已通过。

## 8. 可重复核验命令

```bash
research_dir=/path/to/non-git-mapping-cache/r2-33
mkdir -p "$research_dir"

curl -fL \
  https://ftp.dlink.de/dap/dap-2695/archive/driver_software/DAP-2695_fw_reva_120b20rc101_ALL_en_20190115.zip \
  -o "$research_dir/dap2695.zip"
shasum -a 256 "$research_dir/dap2695.zip"
unzip -p "$research_dir/dap2695.zip" \
  'DAP-2695_fw_reva_120b20rc101_ALL_en_20190115/DAP-2695_120B20RC101.bin' \
  > "$research_dir/DAP-2695_120B20RC101.bin"
shasum -a 256 "$research_dir/DAP-2695_120B20RC101.bin"

curl -fsS \
  https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/sha256sums \
  | rg 'avm_fritzbox-4040-squashfs-sysupgrade.bin'
curl -fL \
  https://archive.openwrt.org/releases/19.07.10/targets/ipq40xx/generic/openwrt-19.07.10-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin \
  -o "$research_dir/openwrt-19.07.10-fritzbox-4040.bin"
shasum -a 256 "$research_dir/openwrt-19.07.10-fritzbox-4040.bin"

# 已有 AC9 fallback / 同 Profile regression
curl -fsS \
  https://downloads.openwrt.org/releases/18.06.7/targets/bcm53xx/generic/sha256sums \
  | rg 'tenda-ac9-squashfs.trx'

curl -fsS \
  https://downloads.openwrt.org/releases/19.07.8/targets/bcm53xx/generic/sha256sums \
  | rg 'tenda-ac9-squashfs.trx'

shasum -a 256 \
  var/mapping-work/ac9-version-diff/downloads/openwrt-18.06.7-bcm53xx-tenda-ac9-squashfs.trx \
  var/mapping-work/ac9-version-diff/downloads/openwrt-19.07.8-bcm53xx-tenda-ac9-squashfs.trx

PYTHONPATH=src python3 scripts/build_openwrt_ac9_version_diff.py
PYTHONPATH=src python3 scripts/build_mapping_corpus_report.py
```

`research_dir` 必须替换为操作者显式选择的非 Git 路径，不能原样运行；不要把厂商 ZIP、BIN 或
rootfs 加入提交。最后两条分别重放现有 AC9 证据与当前 gate；在 R2-33 实现提交前，旧 gate
仍应诚实返回 `partial`。
