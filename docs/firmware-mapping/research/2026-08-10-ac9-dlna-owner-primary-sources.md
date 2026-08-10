# Tenda AC9 DLNA 后端归属：原始固件与第一方来源研究

> 日期：2026-08-10
> 研究状态：AC9 本体归属仍未闭合；邻近型号实现已得到确定性证明
> 研究对象：`GetDlnaCfg`、`SetDlnaCfg`、`expandDlnaFile`、`refreshDLNA`
> 证据纪律：只使用当前 AC9 制品、Tenda 官方发布页与官方 CDN 固件、固件内原始文件、
> FirmAtlas 确定性分析器和 CVE Program 官方记录。CVE 记录只作型号、版本、接口与参数线索，
> 不代替二进制归属证明。

## 1. 结论先行

目前最符合证据的解释不是“AC9 中存在一个尚未被识别的同名动态 dispatcher”，而是：

1. AC9 与 AC18 共用了同一份 DLNA 前端模板和响应 fixture；
2. AC18 的 DLNA 产品开关为 `y`，同时携带 `minidlna`，其 `httpd` 明文注册了三个接口；
3. AC9 的产品开关为 `n`，不携带 `minidlna` 与 `minidlna.conf`，其 `httpd` 也不包含三个
   route token 或对应 handler symbol；
4. `refreshDLNA` 在 AC18 的启用 build 中仍然只有前端定义，且点击绑定被注释，因此它更像
   跨产品模板中的未接通/遗留客户端动作，而不是当前缺失的第四个后端注册。

对 AC18 `V15.03.05.19(6318)` 官方固件运行通用 `auto-v11` 后，工具确定性恢复：

| route | AC18 handler | handler 地址 | registration 地址 |
|---|---|---:|---:|
| `GetDlnaCfg` | `getDLNAserverCfg` | `0x000b0e70` | `0x000438dc` |
| `SetDlnaCfg` | `formDLNAserver` | `0x000b1fdc` | `0x000438c0` |
| `expandDlnaFile` | `formExpandDlnaFile` | `0x000b1984` | `0x000438f8` |

三者由同一 registrar `0x000171ec` 注册；该 registrar 有 170 个结构化 pair。工具没有为
`refreshDLNA` 生成 Native binding，而是将其保持为 `frontend_only`。

这显著提高了“同产品族模板 + 按 build 裁剪后端组件”假设的可信度，但**不能**据此把 AC18
的 handler 地址、符号或漏洞状态迁移成 AC9 事实。AC9 的核心义务仍应保持 open。

## 2. 研究问题与判定边界

本轮要回答：

- 四条前端操作在 AC9 当前制品中是否由 `httpd`、另一个进程或条件组件拥有？
- 如果当前制品没有直接 owner，邻近型号/版本能否说明它们来自何种产品族实现？
- 现有 mapper 应如何利用邻近 build，而不把相似性误写为本体事实？

以下证据强度严格分层：

- **本体事实**：只由 AC9 当前制品中的精确字节或通用分析结果支持；
- **邻近实现事实**：只由 Tenda 官方 AC18 固件自身支持；
- **迁移假设**：AC9/AC18 的同构文件与版本关系只能提高调查优先级，不闭合 AC9 owner；
- **版本线索**：CVE Program 记录只用于选样和核对接口/参数，不作为 AC9 可达性或漏洞证明。

## 3. 来源账本与版本身份

### 3.1 AC9 当前主样本

| 项 | 值 |
|---|---|
| 本地制品 | `../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/0.zip` |
| SHA-256 | `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296` |
| 大小 | `35,417,922` bytes |
| 分析根 | `../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root` |
| benchmark 身份 | `BM-2024-00012` / Tenda AC9 / `V15.03.05.19` / ARM |
| 固件内身份 | `etc_ro/fireversion.cfg`: `ac9_V2.0.0.0(6318)_cn`；`bin/httpd` 含 `V15.03.05.19` |
| `httpd` SHA-256 | `2fd5c92e15f8c9c0b45047c77af080539237d7b99a9b35fe43dc2a9d5a57702b` |

制品与 metadata 来源：

- [FirmEmuHub BM-2024-00012 benchmark.yml](https://github.com/a101e-lab/FirmEmuHub/blob/main/Benchmark/BM-2024-00012/benchmark.yml)
- [FirmEmuHub AC9 制品](https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/Benchmark/BM-2024-00012/emulation/firmware/tenda_ac9.zip)
- [Tenda 官方 AC9 产品页](https://www.tendacn.com/product/no-AC9)
- [Tenda 官方 AC9 支持页](https://www.tendacn.com/product/support/no-AC9)

重要限制：这个 benchmark 制品是一个已解包 rootfs 的 ZIP，而不是本轮从 Tenda 官方 CDN
取得的原始升级镜像。其哈希和嵌入身份可稳定复现当前研究，但来源等级低于下面两份官方
AC18 raw firmware。2026-08-10 检查当前官方 AC9 支持页时，页面将 AC9 归入 EOL，嵌入的
download records 只有文档，没有可用于本轮校验的 firmware record。

### 3.2 Tenda 官方 AC18 `V15.03.05.19(6318)`

| 项 | 值 |
|---|---|
| 官方发布页 | [AC18 升级软件 V15.03.05.19(6318)](https://www.tenda.com.cn/download/detail-2683.html) |
| 页面发布日期 | `2017-05-27` |
| 官方 CDN | [ac18_kf_V15.03.05.19(6318_)_cn.zip](https://static.tenda.com.cn/tdcweb/download/uploadfile/AC18/ac18_kf_V15.03.05.19%286318_%29_cn.zip) |
| ZIP SHA-256 | `359d2feac6a7d28bd45a11e60a7062945152f516978deb7d54daea84d9211410` |
| ZIP 大小 | `10,554,472` bytes |
| ZIP member | `ac18_kf_V15.03.05.19(6318_)_cn.bin` |
| BIN SHA-256 | `7f226515e19d9f8243068e880da74135da495df78821d6044a92f40af29811a5` |
| BIN 大小 | `10,555,456` bytes |
| 固件内身份 | `bin/httpd` 两处 `V15.03.05.19`；`etc_ro/fireversion.cfg` 为 `ac18_V2.0.0.0(6318)_cn` |
| `httpd` SHA-256 | `addecb1e2d5e7befe200b75d925c52d84f3d60db5f18c1071136648e0f70d388` |

原始 BIN 使用仓库固定的 Binwalk 3.1.0 容器提取：

- image digest：`sha256:a22e83ed3465eea9a009a33b01a68233253dc420bcad2b791a48c80444f0880a`
- execution fingerprint：`25282d9f20306b5c3207b92dc6be2609ee0b279c0c8f015e570a121d3325f14d`
- inventory SHA-256：`e5397333b6473660f52c41a0ca841a99c622f93fe16f5c293ed49af4d5ecbde9`
- extraction status：`partial_success`；Binwalk exit code `0`；无 extraction diagnostic。

`partial_success` 来自安全 inventory 对 symlink 等对象的保守覆盖状态，不影响本文引用的已哈希
regular files；它不应被提升成“完整镜像所有内容均已证明可提取”。

### 3.3 Tenda 官方 AC18 `V15.03.05.05` 复核样本

| 项 | 值 |
|---|---|
| 官方发布页 | [AC18 升级软件 V15.03.05.05](https://www.tenda.com.cn/download/detail-2610.html) |
| 页面发布日期 | `2017-01-06` |
| 官方 CDN | [US_AC18V1.0BR_V15.03.05.05_multi_TD01.zip](https://static.tenda.com.cn/tdcweb/download/uploadfile/AC18/US_AC18V1.0BR_V15.03.05.05_multi_TD01.zip) |
| ZIP SHA-256 | `ef138d0c36e41692c3d749b292f5f23c0a7e1afc6b94d8eacaeec748a669ff8a` |
| BIN SHA-256 | `81670748a21ad8b8cd48a17a151d6b1947c498c2e180645c3b35efa369b453e9` |
| `httpd` SHA-256 | `69961109c2afabca1c858b0415afd8cf622a2ac9b52197b5fa1a7e99d32f75b4` |
| extraction fingerprint | `bb06233a10d114b73d9f5ca6656253a2a7bed0d0e1089eb3842574dec08b8532` |
| inventory SHA-256 | `a77036035e1449d859bcb2d4bdb4649289df73c160ad2e13b9f494271eb427a8` |

该版本用于检验 handler 名与注册结构是否只在一个 release 中偶然出现。

### 3.4 官方漏洞记录仅作版本和接口线索

- [CVE-2022-38325 官方 JSON](https://cveawg.mitre.org/api/cve/CVE-2022-38325)：记录 AC15/AC18
  `V15.03.05.19_multi`、`/goform/expandDlnaFile` 与 `filePath`。
- [CVE-2024-10661 官方 JSON](https://cveawg.mitre.org/api/cve/CVE-2024-10661)：记录 AC15
  `15.03.05.19`、`/goform/SetDlnaCfg` 与 `scanList`。
- [CVE-2024-28550 官方 JSON](https://cveawg.mitre.org/api/cve/CVE-2024-28550)：记录 AC18
  `V15.03.05.05` 的 `formExpandDlnaFile` 与 `filePath`。
- [CVE-2025-14993 官方 JSON](https://cveawg.mitre.org/api/cve/CVE-2025-14993)：记录 AC18
  `15.03.05.05`、HTTP Request Handler、`/goform/SetDlnaCfg` 与 `scanList`。

这些记录帮助选出两个官方 AC18 固件。本文关于 route/handler 的阳性结论来自随后对官方固件
字节的独立结构化分析，而不是把 CVE 描述当成二进制证明。它们也不证明 AC9 包含相同漏洞。

## 4. 阳性结果：AC18 的实际 owner

### 4.1 同版本族 `V15.03.05.19(6318)`

对 `bin/httpd`（SHA-256 `addecb…d388`）运行公共
`discover_arm_pic_registrar_bindings`，profile 为 `arm32-pic-r0-r1-bl/v4`，结果：

- coverage：`completed`
- binding count：189
- diagnostics：0
- 目标 registrar：`0x000171ec`
- registrar pair count：170

精确 EvidenceAtom locator：

| route | route literal locator | handler symbol | symbol locator | registration proof locator |
|---|---|---|---|---|
| `SetDlnaCfg` | `binary:bytes=882148-882158` | `formDLNAserver@0x000b1fdc` | `binary:bytes=24564-24572` | `binary:bytes=243880-243908` |
| `GetDlnaCfg` | `binary:bytes=882160-882170` | `getDLNAserverCfg@0x000b0e70` | `binary:bytes=24972-24980` | `binary:bytes=243908-243936` |
| `expandDlnaFile` | `binary:bytes=882172-882186` | `formExpandDlnaFile@0x000b1984` | `binary:bytes=23892-23900` | `binary:bytes=243936-243964` |

三个 proof span 的 excerpt SHA-256 分别为：

- `SetDlnaCfg`: `24f1c9f6884478f966901b404657ad23c235297b26f64e3dbb66a4974df953c1`
- `GetDlnaCfg`: `2680f977e011db0db6f0679d1fb7c2eac1a72619686b058b74f27be9e19b3e`
- `expandDlnaFile`: `fa15299d07af284f20f0468e98093aa695f9495f450403e498003ff027b97245`

这五类原子同时存在：route literal、PIC base、动态符号、registrar callsite、handler binding。
因此这里是邻近 AC18 的确定性 owner 证明，不是简单 `strings` 共现。

### 4.2 旧版 `V15.03.05.05` 独立复核

同一公共 producer 在第二份官方固件中也完成分析，0 diagnostics，190 个 bindings；三个接口仍由
同名 handler 拥有，只发生一致的地址平移：

| route | handler | handler 地址 | registration 地址 | registrar |
|---|---|---:|---:|---:|
| `GetDlnaCfg` | `getDLNAserverCfg` | `0x000b0d90` | `0x0004380c` | `0x00016fe4` |
| `SetDlnaCfg` | `formDLNAserver` | `0x000b1efc` | `0x000437f0` | `0x00016fe4` |
| `expandDlnaFile` | `formExpandDlnaFile` | `0x000b18a4` | `0x00043828` | `0x00016fe4` |

registrar pair count 为 171。两版符号稳定而绝对地址变化，说明 mapper 应迁移“结构模板和符号候选”，
不应迁移固定地址。

### 4.3 通用整根分析复核

官方 AC18 `V15.03.05.19(6318)` 使用默认 `auto-v11/builtin-v11` 独立分析得到：

- analysis run：`mapping-analysis-run:8a672e41ec78e171548b99ffb40c7e47cbecc9c7d530ce419c1ae233f9f53621`
- catalog：`discovery-catalog:f7c18d0ed0dd9f3b5b81c2c89c6a14444028dd7d8dbee6ed1332c3b6772a8d6b`
- frontend：130 inputs / 134 outputs / `completed`
- feature gate：3 outputs / `completed`，`CONFIG_DLNA_SERVER=y`
- ARM PIC callsite：76 outputs / `completed`
- ARM PIC registrar：191 outputs / `completed`
- set difference：89 outputs / `completed`
- catalog：1,907 candidates；全局状态为 `partial`，原因是 inventory symlink 与未关闭义务，
  不是上述 producer 失败。

公共 Catalog 中三条 binding 与直接 producer 的结果一致；`refreshDLNA` 则被稳定发布为
`frontend_operation_native_absent`，开放义务是检查替代 dispatch、脚本或其他 runtime principal。

## 5. AC9/AC18 家族差分

### 5.1 前端与 fixture 是同一模板族

AC9 与官方 AC18 `V15.03.05.19(6318)` 的 `webroot_ro/js/dlna.js` 只有三处静态资源
cache-buster 变化。将 32 位十六进制资源哈希规范化为 `<ASSET_HASH>` 后，两文件字节一致，
规范化 SHA-256 均为：

`29cb6c509bfbb016ee1f0de2cd5b013114f3d61947a2acd3a910da0b6f2b14ec`

三个 fixture 更强：未经规范化就逐字节相同。

| 相对路径 | AC9 与 AC18 共同 SHA-256 |
|---|---|
| `webroot_ro/goform/GetDlnaCfg.txt` | `5ca0c81a03950ce1aee475f18f6381c82c9d87e6e71adca107469b6cc6585bcc` |
| `webroot_ro/goform/SetDlnaCfg.txt` | `fe30f8de191a71df7b9555df04533daf32360e1e3198b32d65fe2d43390a7e7b` |
| `webroot_ro/goform/expandDlnaFile.txt` | `f08d9e5c7d08b9a937905fa575e95b57f11ce109a15f2295a4e304452a4943a0` |

这证明共享前端 contract/template，非常适合产生跨样本候选；但 fixture 仍然不是运行时 route 证明。

### 5.2 产品开关和组件发生一致分裂

| 检查项 | AC9 当前制品 | 官方 AC18 `V15.03.05.19(6318)` |
|---|---|---|
| `CONFIG_DLNA_SERVER` | `n` | `y` |
| `bin/minidlna` | absent | present，SHA-256 `1bf1328ac0b0e2a55efecb3cc23a2df546fca9ab6af95fe9a288e18795607c6a` |
| `etc_ro/minidlna.conf` | absent | present，SHA-256 `54b8ce5bd9d613f08781f59c1c61da0205bf8e2151a24e12b2a0cc0dd34a167f` |
| `GetDlnaCfg` in `httpd` | absent | present + registered |
| `SetDlnaCfg` in `httpd` | absent | present + registered |
| `expandDlnaFile` in `httpd` | absent | present + registered |
| `refreshDLNA` in `httpd` | absent | absent |

AC9 并非完全没有 DLNA 相邻状态：`httpd` 仍含 `killall -9 minidlna`、`dlna.en`、
`/var/etc/upan`，`rcS` 也建立并挂载 `/var/etc/upan`。这些字符串说明共享控制面残留或相邻
USB 状态路径，但它们不能给四条请求创建别名。

### 5.3 `refreshDLNA` 是重要反例

AC18 `dlna.js` 与 AC9 一样：

- 定义 `refreshDLNA()`，内部 POST `/goform/refreshDLNA` 与 `action=1`；
- `$("#refresh").on("click", refreshDLNA)` 这一绑定被注释；
- 整根官方 AC18 rootfs 中，精确 token 只存在于 `webroot_ro/js/dlna.js`；
- 启用 build 的 `httpd` registrar 仍没有该 route。

因此不能把“四条前端操作属于同一页面”转换成“四条都应有同型 handler”。前三条在 AC18 有
结构化 owner；第四条跨启用/禁用 build 都表现为前端遗留。这个负样本应进入 mapper 回归。

## 6. 替代假设排序

| 假设 | 当前评价 | 支持/反证 |
|---|---|---|
| H1：共享产品族前端模板，AC9 build 关闭 DLNA 并裁剪实际后端 | **最强** | 同版本族、规范化前端相同、fixture 相同；AC18 `y` + handlers + `minidlna`，AC9 `n` + 三者均 absent |
| H2：AC9 handler 在缺失的条件组件/另一分区 | **仍开放但降低** | AC9 benchmark 是 repacked rootfs，不能证明原始 flash 所有分区；但已分析根中没有组件，且 feature 为 `n` |
| H3：AC9 使用哈希/生成式 dispatcher 或 route alias | **低但未排除** | 同家族 AC18 使用明文 registrar；AC9 无精确 route/handler symbol。仍需二进制 value-flow 或 runtime 才能彻底排除 alias |
| H4：AC9 rootfs 与 UI/版本配套错误 | **低到中** | 嵌入版本、`6318`、文件时间与模板高度一致；但 AC9 不是本轮从官方 raw image 重提取，故不能归零 |
| H5：`refreshDLNA` 是死/未接通客户端动作 | **强** | 两个 build 中绑定均被注释；AC18 启用 build 仍无 Native route |

## 7. 对 mapper 的可执行建议

### 7.1 新增 `family-variant-diff` producer

输入必须是各自独立分析完成的、带 provenance 的两个或多个 catalog。建议发布：

- `normalized_asset_equivalence`：只规范化可解释的 cache-buster，保留规范化规则和双边原始 hash；
- `fixture_byte_equivalence`：精确文件 hash 相等；
- `feature_state_transition`：如 `CONFIG_DLNA_SERVER: n -> y`；
- `component_presence_transition`：如 `minidlna/conf: absent -> present`；
- `route_binding_transition`：如三个 route `absent -> httpd handler`。

输出只能是 `family_template_candidate` 或 `variant_packaging_hypothesis`，不得直接解决目标样本的
handler-owner 义务。

### 7.2 把组件存在性纳入差集归因

当前 `frontend_feature_disabled` 已解释 UI 路径。下一步可要求至少四项联合证据：完整 feature gate、
同家族启用 build、邻近 build 中精确 route binding、运行组件 presence delta。满足后把 AC9 三条
operation 从笼统 `frontend_operation_native_absent` 细分为
`family_variant_component_omitted_candidate`，同时保持 owner open。

### 7.3 增加前端可达性层

当前 request lexer 会发现函数体中的字面量，但不区分事件绑定是否被注释或函数是否有活动调用者。
应新增保守的 `frontend_invocation_reachability`：

- 识别注释中的 event registration，不将其计为 active edge；
- 为函数定义、活动调用点、定时器和事件绑定分别建边；
- 没有活动调用者时发布 `declared_but_unreached`，而不是删除 request candidate；
- 用 AC18 `refreshDLNA` 作为真实阴性回归样本。

### 7.4 跨样本迁移符号，不迁移地址

两个 AC18 版本证明 handler symbol 稳定而地址整体变化。邻近样本只能提供：

- route token；
- handler symbol 候选；
- registrar 布局与 feature/component 条件；

不得 seed 固定 handler address。对 AC9 应以 `formDLNAserver/getDLNAserverCfg/formExpandDlnaFile`
作为有界 symbol/relocation/函数形状调查目标；若目标 binary 完全无符号和 route token，输出明确
阴性证据，不能降级成模糊字符串相似即匹配。

### 7.5 强化制品 provenance gate

跨版本结论至少记录：厂商发布页、直链、下载时间、archive hash、member hash、嵌入型号/版本、
提取工具 digest、execution fingerprint 和 inventory status。AC9 这种 benchmark rootfs ZIP 应显式
标记 `repacked_rootfs`，不能与官方 raw firmware 赋予相同的“缺失组件”置信度。

### 7.6 加入两个真实回归样本

1. AC18 `V15.03.05.19(6318)`：公共 `auto-v11` 必须恢复 3 个 enabled DLNA bindings，
   `refreshDLNA` 必须保持 Frontend-only；
2. AC18 `V15.03.05.05`：逐 asset 调用当前 frontend producer 时，
   `etc_ro/nginx/conf/test.html` 会触发
   `ValueError: evidence byte range must be nonempty and within source`。这不是 DLNA 归属结果，
   但它说明新增官方 holdout 后发现了真实 parser 边界缺陷；修复时应先冻结该文件及失败 span 的
   RED 测试，避免用“跳过整个页面”掩盖 evidence locator 错误。

## 8. 可复现检查

核心检查使用下列命令形状；URL、hash 和相对路径均已在上文冻结：

```sh
# 下载与 hash
curl -L --fail '<official-cdn-url>' -o '<artifact.zip>'
shasum -a 256 '<artifact.zip>'
unzip -l '<artifact.zip>'

# 整根精确 token 范围
rg -a -l -F 'GetDlnaCfg' '<rootfs>'
rg -a -l -F 'SetDlnaCfg' '<rootfs>'
rg -a -l -F 'expandDlnaFile' '<rootfs>'
rg -a -l -F 'refreshDLNA' '<rootfs>'

# 只规范化已确认的静态资源 cache-buster
sed -E 's/[0-9a-f]{32}/<ASSET_HASH>/g' '<rootfs>/webroot_ro/js/dlna.js' \
  | shasum -a 256
```

Native binding 通过仓库公共 API `discover_arm_pic_registrar_bindings` 或完整
`analyze_extracted_root(..., profile=MappingAnalysisProfile.auto())` 重放。研究时仓库 HEAD 为
`b8fc322e87606920c48b762d0b974223bd91133c`；未使用 AC9 专用 route seed。

## 9. 限制与下一步

- 没有对任何设备执行动态请求；本文不声明运行时可达、认证要求或可利用性。
- AC18 的确定性 owner 不能直接解决 AC9 owner；它只说明产品族中已知的正常实现方式。
- AC9 样本是 benchmark repacked rootfs；应继续寻找与 hash/身份可核对的 Tenda 官方 AC9 raw
  firmware，再执行分区级提取差分。
- “没有精确 token”不排除位置编码、hash dispatcher、别名或跨进程协议；只是这些假设相对
  “组件按 build 裁剪”已获得更低优先级。
- `minidlna` 是媒体服务进程；本轮证明的 Web route owner 是 `httpd`。不能把进程存在性本身
  当成 Web handler binding。
- 下一轮最有信息增益的工作是：取得官方 AC9 同 build raw image；在 AC18 三个 handler 上恢复
  参数 value-flow 与组件启动链；将其函数形状作为 AC9 的有界反事实搜索目标；为
  `refreshDLNA` 建立活动调用边的阴性证明。
