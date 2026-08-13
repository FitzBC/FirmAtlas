# Tenda AC9 URL 日常 IPC、`urlgroup.*` 跨域分裂与 loader 激活负证据

> 日期：2026-08-13
>
> 唯一样本：Tenda AC9 `15.03.05.19`，固件制品 SHA-256
> `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`
>
> 证据范围：本地解包固件字节、ELF 动态符号/重定位、ARM32 反汇编与仓库已有第一方
> R2-26 记录；不使用相邻型号、函数名相似性或二手描述补边

## 1. 结论先行

本轮可以把 URL 日常业务链从 client 一直闭合到独立 hash/flash store：

```text
bin/httpd / bin/cfm
  -> libCfm client: Get/Set/UnSet/Commit/Show URL
  -> /var/cfm_socket，固定 2016-byte message
  -> bin/cfmd dispatcher@0xa504
  -> libCfm server wrapper@0x56b8..0x5788
  -> url_mib_* / save_url_mib
  -> cfm/url_mib/* <-> CFM_URL
```

五类请求/响应 opcode、消息字段偏移、daemon 分支、wrapper 和 store primitive 都有直接静态
证据。`httpd` 有 25 个 URL client 调用点，`cfm` 有 5 个 CLI 调用点。

但本轮同时发现两个不能被“URL 名称”掩盖的边界：

1. `urlgroup.*` 并不天然等于 URL store。`urlgroup.list*`、`urlgroup.class*` 等走 URL IPC，
   而同一函数后半段的 `urlgroup.rule.*`、`urlgroup.flag` 走普通 `GetValue/UnSetValue/CommitCfm`
   主配置通道。这是**同前缀、同消费者、不同状态域**的确定性架构分裂。
2. URL store 的日常 IPC 完整，不等于 `/webroot/default_url.cfg` loader 被激活。287 个 ELF 中
   257 个可解析对象的复扫仍只找到 `reload_url_mib@0x8e08` 内部两处 loader 调用；没有 importer、
   direct call、URL opcode 分支或初始化边指向 `reload_url_mib`。当前只能发布“日常 IPC supported、
   文档导入 activation unresolved”。

## 2. 来源账本与复核方法

解包根为 `../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root`。

| 制品内路径 | SHA-256 | 用途 |
|---|---|---|
| `lib/libCfm.so` | `163f8d4a470116288385bee4d65009db1a393773567d08decd91f72b9b195d09` | URL IPC client/server wrapper、hash/flash primitive、loader |
| `bin/cfmd` | `5483f90689f6f068d924d1043bc219560b31e6b4a75b634ce1d55a1b596abede` | 2016-byte message dispatcher、初始化入口 |
| `bin/httpd` | `2fd5c92e15f8c9c0b45047c77af080539237d7b99a9b35fe43dc2a9d5a57702b` | URL store 业务消费者与 `UploadWebsite`/`DownloadWebsite` selector |
| `bin/cfm` | `913e1a916cf2fd54772f1cd56932bdc6cbd25b0df7307c9a2cb2fe26b3b688f5` | `urlSet/urlUnSet/urlGet/urlshow` CLI consumer |

复核使用 ELF `.rel.plt` 将 ARM PLT stub 绑定到 import，再扫描普通 ARM `BL`；对动态 export
用地址与 symbol size 定界，对 stripped `httpd` 则只发布函数地址区间，不用最近的宽大动态符号
冒充函数 owner。全制品覆盖仍为 287 个 ELF、257 个成功解析、30 个 parser boundary；30 个失败项
中没有目标 symbol/path 原始字节命中。

## 3. 固定消息布局与 client 行为

五个 client 都向 `SendMsg`/`RecvMsg` 传入同一个 2016-byte 栈对象，并严格要求返回长度等于
2016。ARM 地址计算直接恢复如下布局：

```c
/* 字段语义由访问偏移证明；不是从头文件抄录的类型名。 */
struct cfm_message_2016 {
    uint32_t opcode;       /* +0 */
    char key_or_path[512]; /* +4 */
    char value[1500];      /* +516 */
};
```

- `SetUrlValue@0x4a80` 在 `0x4b0c/0x4b50` 分别把两个入参复制到 `+4/+516`，在
  `0x4b5c` 写 opcode 30；两个入参均在 `0x4ad4..0x4b38` 被限制为 `strlen <= 511`。
- `GetUrlValue@0x4820` 在 `0x48f8/0x4918` 把 key 复制到请求 `+4`，`0x4924` 写 32；
  响应必须为 33 且 `+4` 回显 key（`0x49b4..0x4a2c`），才把 `+516` 复制给调用者。
- `UnSetUrlValue@0x4c54` 把 key 写入 `+4`，`0x4ce8` 写 36；响应必须为 37 且回显 key。
- `ShowUrlValue@0x4de0` 把非空 filename/`stdout` selector 写入 `+4`，`0x4e80` 写 38；
  响应必须为 39 且回显该字符串。
- `CommitUrlCfm@0x3788` 无业务 payload，`0x37e4` 写 34；它接受响应 35 或通用 16。
  该函数在 `0x38bc..0x38c4` 无条件返回 1，所以 mapper 不应把其 C 返回值解释成精确的
  flash 成功/失败结论；可观察的协议响应仍应保留 35/16 两分支。

所有 client 在连接前后调用同一 mutex/connection 包装；`ConnectCfm@0x36b0` 经
`ConnectServer` 使用固件字面量 `/var/cfm_socket`，并设置 timeout。由此可以安全发布本地 Unix
socket channel，而不能仅凭文件名把它泛化成网络 TCP/UDP。

## 4. opcode、daemon 与 store primitive 的闭环

`cfmd` 的单消息 dispatcher 为 `0xa504..0xaa80`。它先在 `0xa534` 调 `RecvMsg`，并在
`0xa540` 检查 2016，然后按 `message+0` 分派：

| 操作 | client request / response | `cfmd` branch/callsite | server wrapper | 最终 primitive |
|---|---:|---|---|---|
| Get | `32 / 33` | `0xa874..0xa8d0`, call `0xa8a8` | `GetCfmUrlValue@0x56b8` | `url_mib_get_value@0x83c4 -> hash_find` |
| Set | `30 / 31` | `0xa8d4..0xa930`, call `0xa908` | `SetCfmUrlValue@0x5718` | `url_mib_set_value@0x8510` |
| Unset | `36 / 37` | `0xa934..0xa97c`, call `0xa954` | `UnSetCfmUrlValue@0x5748` | `url_mib_unset_value@0x8674 -> hash_remove` |
| Commit | `34 / 35`，wrapper 返回 0 时为 `16` | `0xa980..0xa9cc`, call `0xa98c` | `SaveCfmUrl2Flash@0x5770` | `save_url_mib@0x8ec0 -> nvram_cfm_url_commit` |
| Show | `38 / 39` | `0xa9d0..0xaa18`, call `0xa9f0` | `ShowCfmUrlValue@0x5788` | `url_mib_list@0x7f74` |

参数布局在 dispatcher 端得到独立印证：Get/Set 分支把 `message+4` 与 `message+516` 传给
wrapper；Unset/Show 只传 `message+4`；Commit 不传业务字段。各分支再把 response opcode 写回
同一 buffer 并调用 `SendMsg`。这使 opcode 与字段语义不是仅由 client 单边猜测。

`GetCfmUrlValue@0x56b8` 通过 `url_mib_get_value` 取得指针后复制到输出；Set/Unset 是到
`url_mib_set_value/url_mib_unset_value` 的薄 wrapper；Save 到 `save_url_mib`；Show 在 selector
为 `stdout` 时列到标准输出，否则以 `w` 打开调用者给出的路径并调用 `url_mib_list`。因此
Show 的 `+4` 应建模为内部输出 selector/path，不应误标为 HTTP 参数。

## 5. caller 清单与 `httpd` 业务 consumer

### 5.1 CLI caller

`bin/cfm` 的命令字面量直接给出 `urlSet`、`urlUnSet`、`urlGet`、`urlshow`。在其 stripped
dispatcher 区间内稳定恢复：

| callsite | import |
|---:|---|
| `0x9220` | `SetUrlValue` |
| `0x9240` | `CommitUrlCfm` |
| `0x9350` | `UnSetUrlValue` |
| `0x9a94` | `GetUrlValue` |
| `0x9d30` | `ShowUrlValue` |

`.data.rel.ro` command table还把 `urlSet/urlUnSet/urlGet/urlshow`（file offsets
`0x36bc/0x3700/0x377c/0x37f8`）分别绑定到 `0x91bc/0x92fc/0x9a30/0x9cdc`，所以上述
callsites 不是仅凭相邻字符串归名。全 287 ELF 的 relocation 复核表明五个 client API 的 importer
恰为 `bin/cfm` 与 `bin/httpd`（`ShowUrlValue` 只有 `bin/cfm`），五个 server wrapper 的 importer
恰为 `bin/cfmd`。

### 5.2 HTTP 进程中的 URL-store consumers

`bin/httpd` 共恢复 16 个 Get、6 个 Set、2 个 Unset、1 个 Commit URL callsite。按真实函数边界
和相邻格式字面量可分组为：

| 函数区间 | URL IPC callsites | 已证明的 key/template |
|---|---|---|
| `0x3d6c0..0x3de34` | Get `0x3d84c,0x3d8cc,0x3d9ec,0x3da08,0x3da70,0x3db1c` | `urlgroup.sysnum`, `urlgroup.list%d`, `urlgroup.class%d.listnum`, `urlgroup.class%d.sysnum`, `urlgroup.class%d.list%d`；输出 `/etc/website.cfg` |
| `0x3de7c..0x3df48` | Get `0x3ded4` | `urlgroup.list%d` |
| `0x3df54..0x3e0c0` | Get `0x3dfe0,0x3dff8`; Set `0x3e078,0x3e0ac` | `urlgroup.listnum`, `urlgroup.sysnum`, `urlgroup.list%d` |
| `0x3e0d4..0x3e538` URL 段 | Get `0x3e184,0x3e19c,0x3e23c,0x3e250,0x3e304,0x3e3fc`; Set `0x3e350,0x3e44c`; Unset `0x3e2d4,0x3e3e4` | `urlgroup.listnum/sysnum`, `urlgroup.class%d.listnum/sysnum/list%d`, `urlgroup.list%d` |
| `0x3e564..0x3ea54` | Get `0x3e900`; Set `0x3e970,0x3e984`; Commit `0x3e9d0` | `urlgroup.class%d.listnum/list%d`; selector literal `UploadWebsite` |

外层 `webs_Tenda_CGI_BIN_Handler` 在 `0x3aad8..0x3ab44` 对请求 selector 做有界比较：
`DownloadWebsite` 命中后 `0x3ab08 -> 0x3d6c0`，`UploadWebsite` 命中后
`0x3ab40 -> 0x3e564`。这证明两个 selector 到业务函数的 direct edge；但该 dispatcher 不是已
恢复的 `formDefineTendDa` route registration，故本轮只发布 selector token，不自行补成
`/goform/UploadWebsite` 或假定 HTTP method。

### 5.3 必须保留的同前缀跨 store 分裂

`0x3e0d4..0x3e538` 是本轮最重要的反误归因案例：

- 到 `0x3e44c` 为止的 list/class 段使用 `GetUrlValue/SetUrlValue/UnSetUrlValue`；
- `0x3e46c` 开始读取 `urlgroup.rule.listnum`，但 call `0x3e480` 的 import 是普通
  `GetValue`，不是 `GetUrlValue`；
- 循环删除 `urlgroup.rule.list%d` 的 call `0x3e4d0`、删除 listnum 的 `0x3e4fc`、删除
  `urlgroup.flag` 的 `0x3e50c` 都解析为普通 `UnSetValue`；
- `0x3e510` 调的是 `CommitCfm`，不是 `CommitUrlCfm`。

所以以下状态归属可直接确定：

```text
urlgroup.list*, urlgroup.class* -> cfm/url_mib/*
urlgroup.rule.*, urlgroup.flag  -> cfm/default_mib/*
```

`urlgroup.name` 字面量在 upload parser 的比较/路径控制附近出现，但本轮没有逐 callsite 证明它由
URL-store primitive 读写，因此不能把它加入上述任一状态归属集合。

前缀、消费者进程甚至函数相同，都不能覆盖实际调用的 storage primitive。R2-26 研究记录中把
`urlgroup.rule.*`/`flag` 概括为 URL store 的表述应以本轮更深证据为准；这不是 hindsight
重写，而是从“consumer 线索”推进到“逐 callsite store binding”后发生的状态修正。

## 6. `load_url_mib` / `reload_url_mib` 激活审计

### 6.1 已证明的初始化反例

`cfmd@0x9f68` 调 `InitCfm@0x540c`。后者在 `0x5450` 以参数 0 调 `load_mib`，只初始化主
MIB；没有调用 `load_url_mib` 或 `reload_url_mib`。`InitDefaultCfm@0x5480` 同样只在
`0x54d0` 以参数 1 调主 `load_mib`。`RestoreMTD@0x588c` 的 `0x5978` 也只到
`InitDefaultCfm`。因此“cfmd 启动会顺便加载 URL 文档”与“opcode 14 restore 会加载 URL
文档”均被当前静态调用图直接反驳。

### 6.2 loader 唯一静态 caller

`reload_url_mib@0x8e08..0x8e6c` 的两条分支都传 0 调 `load_url_mib`：

- 未初始化分支：`0x8e30 -> load_url_mib(0)`；
- 已初始化分支：先在 `0x8e3c` 清理 URL hash，再在 `0x8e54 -> load_url_mib(0)`。

这进一步说明 `reload_url_mib` 本身是 flash-first/fallback-file 的 mode 0 reload，不是 R2-26
开放义务中期待的 `load_url_mib(1)` upload import。当前完整固件没有任何 direct call 给
`load_url_mib(1)`。

### 6.3 全制品负证据

同一 287/257 ELF scanner 的结果为：

- `load_url_mib` callsite 只有 `lib/libCfm.so@0x8e30/0x8e54`；
- `reload_url_mib` importer 0、direct callsite 0；
- `close_url_mib` importer 0、direct callsite 0；
- `cfmd` 的 URL dispatcher 只覆盖 opcode 30、32、34、36、38，没有 URL reload/import opcode；
- 30 个 parser boundary 制品没有上述 symbol 或 `/webroot/default_url.cfg` 原始 byte 命中；
- 固件树仍没有静态 `default_url.cfg` 文件。

该负证据能证明“当前静态方法与当前 rootfs 未找到 activation”，不能证明运行时绝无
`dlsym`、未解析间接函数指针、启动前引导阶段或外部升级逻辑。没有动态 trace 前，activation
义务应保持 open，不能因日常 URL IPC 已闭合而自动关闭。

## 7. 证据等级与禁止推断

### Supported

- `/var/cfm_socket` 上 2016-byte URL IPC 及五类 opcode；
- `client -> cfmd dispatcher -> wrapper -> url_mib primitive -> CFM_URL`；
- `bin/cfm` 与 `bin/httpd` 的上述 direct PLT callsites；
- `DownloadWebsite`/`UploadWebsite` selector 到 `0x3d6c0/0x3e564` 的 direct branch；
- `urlgroup.*` 的跨 store 分裂；
- cfmd 初始化、主 restore 不调用 URL loader。

### Deterministic negative evidence / unresolved

- 257 个可解析 ELF 无 `reload_url_mib` importer/caller；
- 无 `load_url_mib(1)` direct call；
- 30 个 parser boundary 仍是 coverage limitation；
- 上传文档到 loader 的执行边未闭合。

### 不得宣称

- 所有 `urlgroup.*` 都位于 `cfm/url_mib/*`；
- `UploadWebsite` 已等价于 `/goform/UploadWebsite` 或某个 HTTP method；
- URL IPC 的 key template 就是缺失 `default_url.cfg` 的声明键；
- `CommitUrlCfm` 的 C 返回值能精确表示 flash commit 成功；
- 日常 IPC 存在即证明 upload/restore loader activation；
- 任一 URL consumer 本身构成历史漏洞或可利用接口。

## 8. 对 mapper、Catalog、图谱与回归的可执行建议

1. 新增通用的 fixed-message IPC producer，至少发布 endpoint、message size、opcode pair、字段
   offset/role、client/server callsite、wrapper、primitive 与 state scope；不要把本轮硬编码成
   AC9 专用字符串表。
2. 将五类操作建模为同一 channel 下独立 operation：Get 为 `reads_state`，Set/Unset 为
   `mutates_state`，Commit 为 `persists_state`，Show 为 `exports_state`。消息的 key/path/value
   是 IPC 字段，不是 HTTP query/body 参数。
3. consumer key 归属必须由“callsite 最终绑定的 store primitive”决定。增加反向测试：
   `urlgroup.rule.*` 与 `urlgroup.flag` 不得落到 `cfm/url_mib/*`；`urlgroup.class*` 不得因前者
   分裂而被迁回主 MIB。
4. stripped function owner 应用 prologue/epilogue 或 direct-call boundary 表示
   `httpd@0x...`，不得把 25 个调用都归给横跨大区间的 `webs_Tenda_CGI_BIN_Handler` 动态符号。
5. selector 与 HTTP route 分层：本轮可发布 `UploadWebsite -> httpd@0x3e564` supported selector
   edge；没有 registrar/path/method 证据时保留 route-binding obligation。
6. URL daily IPC 与 URL document import 必须是两个 flow family。前者已 supported，后者继续保留
   `binds_configuration_url_loader_activation`，避免“相关组件出现即传递闭合”。
7. 图谱详情应展示 `2016 bytes: opcode@0, key/path@4, value@516`、request/response pair 及
   channel `/var/cfm_socket`；对同前缀跨域键显示明显的 split badge/并列状态域，防止用户把搜索
   前缀误读成统一存储。
8. 增加覆盖回归：当前样本必须恢复 `16 Get + 6 Set + 2 Unset + 1 Commit` 个 httpd URL callsite、
   5 个 CLI callsite和 5 个 cfmd wrapper callsite；同时不得生成 `InitCfm/RestoreMTD ->
   load_url_mib` 或 `UploadWebsite -> load_url_mib`。
9. activation 下一步只接受能改变证据状态的材料：真实启动/上传 trace、间接调用表的 relocation
   proof、或取得真实第二文档及其消费时序。重复函数名/literal 搜索只能加强负证据，不能将
   candidate 升为 supported。

## 9. 本轮相对 R2-26 的状态变化时间线

1. R2-26 已证明 writer、latent loader、URL hash/flash store 与若干 consumer 线索，但把
   `urlgroup.rule.*`/`flag` 与相邻 URL calls 一并概括成 URL-store consumer。
2. 本轮先闭合 client packet、opcode 与 daemon wrapper，再逐 callsite 绑定 key formatting 和
   PLT import。
3. 深入到 `httpd@0x3e46c` 后发现 primitive 从 URL API 切换到普通 CFM API，故义务状态从
   “待细化的 URL consumer”变为“已证明的跨 store split”。
4. 同时确认 `reload_url_mib` 只传 mode 0，且 cfmd 启动只走主 `load_mib`；activation 义务没有
   获得足够证据，继续保持 open。

反事实：若只用 `urlgroup.` 前缀聚类，会把 rule/flag 错投影到 URL state；若只用 URL IPC 的
完整性反推初始化，会虚构一条 loader activation。两种错误都会让“接口/参数完整性”看似提高，
却降低状态归属和执行关系的真实性。
