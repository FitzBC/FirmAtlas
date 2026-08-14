# Tenda AC9 `UploadWebsite`：HTTP namespace、二级 selector 与 URL-store consumer

> 日期：2026-08-13
>
> 唯一样本：Tenda AC9 `V15.03.05.19(6318)`；固件制品
> `../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/0.zip` SHA-256
> `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`
>
> 证据范围：当前固件字节、ELF dynamic symbol/relocation、ARM32 direct branch、固件内 Web
> 资源，以及 GoAhead 2.1.8 原始源代码的 handler contract；不使用函数名或相邻型号补造路径、
> method 或 loader activation

## 1. 结论先行

本轮把 R2-27 尚未闭合的外层 HTTP route binding 推进为如下分层结构：

```text
HTTP URL-handler registry@httpd:0x178f0
  /cgi-bin namespace
    -> webs_Tenda_CGI_BIN_Handler@0x3a678
       -> 从 handler 的 path 参数提取第二段 selector
       -> internal selector dispatcher@0x3a9a0
          -> UploadWebsite compare@0x3ab14..0x3ab40
             -> body/parser consumer@0x3e564..0x3ea54
                -> GetUrlValue / SetUrlValue / CommitUrlCfm
                -> /var/cfm_socket -> cfmd -> cfm/url_mib/*
```

因此可以把规范化路径 `/cgi-bin/UploadWebsite` 发布为**确定性派生的 route binding**：它不是固件
中的完整字符串字面量，而是由 `/cgi-bin` registrar、handler 对 `path` 的段解析和
`UploadWebsite` selector 分支三份独立静态证据组合得到。它不能改写成
`/goform/UploadWebsite`。

HTTP method 仍未闭合。整个 selector dispatcher 与 `0x3e564` handler 没有 GET/POST 比较；
handler 确实读取请求长度/内容并进入上传解析器，只能证明它消费 HTTP body，不能据此把 POST
晋级为 supported method。

`load_url_mib` activation 也没有状态变化：`UploadWebsite` 只调用日常 URL API；全固件仍没有
`UploadWebsite -> load_url_mib/reload_url_mib` 静态边，没有 `load_url_mib(1)` direct call。

## 2. 来源账本与样本身份

解包根为
`../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root`。

| 制品内路径 | SHA-256 | 用途 |
|---|---|---|
| `bin/httpd` | `2fd5c92e15f8c9c0b45047c77af080539237d7b99a9b35fe43dc2a9d5a57702b` | HTTP registrar、path parser、selector dispatcher 与 URL consumer |
| `lib/libCfm.so` | `163f8d4a470116288385bee4d65009db1a393773567d08decd91f72b9b195d09` | URL daily IPC client、loader 与 URL store primitive |
| `bin/cfmd` | `5483f90689f6f068d924d1043bc219560b31e6b4a75b634ce1d55a1b596abede` | URL IPC daemon dispatcher、启动初始化反例 |

固件内身份还由 `etc_ro/fireversion.cfg:1` 的
`fireversion=ac9_V2.0.0.0(6318)_cn` 与 `webroot_ro/default.cfg:295` 的
`sys.targets=AC9` 交叉确认；唯一制品身份仍以上述 zip SHA 为准。

GoAhead handler contract 的复核源为
[`trenta3/goahead-versions` commit `75d8163`](https://github.com/trenta3/goahead-versions/tree/75d8163e520b26cbf9fd48f4bdd62115b59d024d)
中的 2.1.8 原始源码包
`230165webs218.tar.gz`，包 SHA-256
`b3b3ed341141a8ec2a9e3002dcde098d8a676d9cb33f82046ff2b1c08ee084d9`：

- `handler.c:83..124` 定义 prefix、handler 与 flags 的 registrar contract；
- `handler.c:243..296` 按 `urlPrefix` 匹配 `wp->path`，再把 `wp->url/wp->path/wp->query`
  传给 handler；
- `LINUX/main.c:201..205` 给出 `/goform` 与 `/cgi-bin` prefix registration 的原始示例。

该源码只用于确认通用参数语义；AC9 的具体 prefix、owner、selector 与 handler 均由固件自身证明。

## 3. `/cgi-bin` registrar ownership

### 3.1 registrar callsite

`httpd@0x2e934` 的初始化函数连续调用同一个内部 registrar `0x178f0`。阳性对照与焦点项为：

| callsite | prefix literal | handler proof | flags |
|---:|---|---|---:|
| `0x2eb3c` | `/goform`，load `0x2eb20`，VA `0xdac44` / file `0xd2c44` | GOT relocation `websFormHandler` | 0 |
| `0x2eb64` | `/cgi-bin`，load `0x2eb48`，VA `0xdac4c` / file `0xd2c4c` | PIC base `0xfd3b8` + delta `0x594` -> GOT slot `0xfd94c` -> `R_ARM_GLOB_DAT webs_Tenda_CGI_BIN_Handler` | 0 |

`webs_Tenda_CGI_BIN_Handler` 是 `bin/httpd` 的 executable dynamic export，地址
`0x3a678`，symbol size `0x138`。这不是用最近符号替 stripped function 命名：handler identity
来自目标 GOT relocation 本身。

### 3.2 registrar 本体的独立语义证明

`0x178f0` 并非仅因与已知 GoAhead 函数形似而命名。其机器码直接执行：

- `0x179d4..0x179e4`：复制 r0 prefix，并存入新 entry 的 `+8`；
- `0x179f4..0x17a04`：计算 prefix 长度并存 `+12`；
- `0x17a48..0x17a50`：把 r3 handler 存入 entry `+0`；
- 随后维护 registrar collection。

所以 `/cgi-bin -> webs_Tenda_CGI_BIN_Handler` 可以按 supported namespace binding 发布，
不依赖完整 endpoint 字面量。

## 4. path segment parser 与七分支 selector dispatcher

### 4.1 outer handler 使用 `path`，而不是函数名猜测 route

ARM ABI 与 handler prologue 共同表明 `webs_Tenda_CGI_BIN_Handler@0x3a678` 在
`0x3a6bc` 取第六个参数，也就是 GoAhead contract 中的 `path`。函数随后：

1. `0x3a6c0..0x3a6cc` 把 path 复制到 254-byte 有界 buffer；
2. `0x3a6d4..0x3a6e0` 从 `buffer+1` 查找 `/`，缺失则返回 `Missing CGI name`；
3. `0x3a714` 前移到该 `/` 后，`0x3a720..0x3a744` 查找并截断下一段 `/`；
4. `0x3a788` 把得到的第二段 selector direct-call 给 `0x3a9a0`。

结合已证明的 `/cgi-bin` prefix，该解析不是把 token 与 prefix 粗略拼接，而是执行语义上的
`/cgi-bin/<selector>` 路由。因此 `/cgi-bin/UploadWebsite` 可以作为 normalized、
deterministic-derived route；报告和 UI 必须同时显示其组成证据，不能伪装成 direct literal。

### 4.2 dispatcher 实际有七个 arm

`0x3a9a0..0x3ab68` 对 selector 逐项执行带显式长度的 `strncmp`：

| selector | compare/call | handler |
|---|---:|---:|
| `upgrade` | `0x3a9d4 / 0x3a9f0` | `0x3b4a8` |
| `UploadCfg` | `0x3aa0c / 0x3aa28` | `0x3b850` |
| `DownloadCfg` | `0x3aa44 / 0x3aa60` | `0x3c0ac` |
| `DownloadLog` | `0x3aa7c / 0x3aa98` | `0x3ce4c` |
| `DownloadFlash` | `0x3aab4 / 0x3aad0` | `0x3d4c0` |
| `DownloadWebsite` | `0x3aaec / 0x3ab08` | `0x3d6c0` |
| `UploadWebsite` | `0x3ab24 / 0x3ab40` | `0x3e564` |

焦点 literal `UploadWebsite` 位于 VA `0xdc604` / file `0xd4604`；`0x3ab14` PIC-load，
`0x3ab20` 写长度 13，`0x3ab24` 调 `strncmp@PLT 0xeeec`，匹配分支 `0x3ab40` direct-BL
到 `0x3e564`。较早只覆盖前六个 anchor 的“6-entry dispatcher”结论必须修正为本函数的
七分支完整枚举。

## 5. `UploadWebsite` body consumer 与 URL daily IPC

`0x3e564..0x3ea54` 不是 loader wrapper。它首先在 `0x3e61c..0x3e630` 读取请求对象
`+0xe0` 的长度并分配 buffer，随后 `0x3e6a4 -> 0x3acd4` 进入上传内容解析路径。内部函数
`0x3acd4` 同样读取请求长度/内容，持有 `filename` 与 `webCgiGetUploadFile` literals。

业务路径最终只有日常 URL client calls：

| callsite | target |
|---:|---|
| `0x3e900` | `GetUrlValue@PLT 0xf5c4` |
| `0x3e970`, `0x3e984` | `SetUrlValue@PLT 0xf384` |
| `0x3e9d0` | `CommitUrlCfm@PLT 0xf3e4` |

相邻的 `urlgroup.class%d.listnum`、`urlgroup.class%d.list%d` callsite binding 已在 R2-27
闭合到 `cfm/url_mib/*`。本轮新增的是 HTTP namespace 与 selector transport，不应把 request
body、IPC key/value field 和 URL-store state parameter 合并为一种“参数”。

`bin/httpd` 全函数没有 selector-specific method compare。固件全局虽包含 GET/POST/HEAD parser，
`webroot_ro` 的其他升级/配置表单也明确使用 POST，但这些都不是 `UploadWebsite` 的 method
binding 证据。body consumption 只能产生 `method_binding` obligation，不能生成 `POST` claim。

## 6. loader activation 复审

### 6.1 focus path 没有 loader edge

- `bin/httpd` 不 import `load_url_mib`、`reload_url_mib` 或 `close_url_mib`；
- `0x3e564` 的 direct/import calls 只有 body parser、字符串/内存 helper、日常 URL API 与响应
  helper；
- `UploadWebsite` token 在整个 rootfs 只有 `bin/httpd` owner；bundled `webroot_ro` 没有该 token；
- rootfs 没有完整 `/cgi-bin/UploadWebsite` 或 `/goform/UploadWebsite` 字节串。这不否定已由控制流
  组合证明的 normalized route，但说明它不是 direct literal，也没有 bundled frontend anchor。

### 6.2 全制品负证据保持不变

当前 rootfs 有 287 个 ELF；既有同一 scanner 可解析 257 个，30 个为 parser boundary。结果仍为：

- `load_url_mib@0x8d0c`、`reload_url_mib@0x8e08`、`close_url_mib@0x8eec` 只由
  `lib/libCfm.so` 持有；
- `reload_url_mib` 无外部 importer/direct caller；`close_url_mib` 同样为 0；
- `reload_url_mib` 在 `0x8e2c` 与 `0x8e50` 都先写 `r0=0`，再于
  `0x8e30/0x8e54` 调 `load_url_mib@PLT`；没有 `load_url_mib(1)` direct call；
- 30 个 parser failure 中没有目标 symbol 或 `/webroot/default_url.cfg` raw-byte hit；
- `cfmd@0x9f68 -> InitCfm` 只在 `libCfm@0x5450` 调主域 `load_mib(0)`；
  `RestoreMTD@0x5978 -> InitDefaultCfm` 也只在 `0x54d0` 调主域 `load_mib(1)`。

因此 route-binding obligation 可关闭，configuration URL document activation obligation 仍必须 open。
静态负证据不能排除 `dlsym`、未恢复的函数表、外部分区/程序或重启后的运行时行为。

## 7. 证据等级与禁止推断

### Supported direct / deterministic-derived

- `/cgi-bin` namespace registrar 与 `webs_Tenda_CGI_BIN_Handler` ownership；
- path 第二段 selector parser；
- 七个 selector arm 及 `UploadWebsite -> 0x3e564` direct branch；
- normalized `/cgi-bin/UploadWebsite` route，证据等级必须标为 deterministic-derived；
- body consumer 与 `GetUrlValue/SetUrlValue/CommitUrlCfm` daily URL IPC；
- bundled frontend absence 与 loader static negative evidence。

### Unresolved

- `UploadWebsite` 的 HTTP method、content type 与认证/运行时可达状态；
- `UploadWebsite` 是否属于已删除/外部客户端或仅保留 native implementation；
- secondary URL document 的真实运行时 activation。

### 不得宣称

- `/goform/UploadWebsite`；
- 因为函数处理上传内容，所以 method 必然是 POST；
- 完整 endpoint literal 存在于固件；
- native-only 即 hidden、未认证、漏洞或可利用；
- `UploadWebsite -> load_url_mib/reload_url_mib`；
- `UploadWebsite` 的 body 字段、2016-byte CFM IPC 字段和 `urlgroup.*` 状态键是同一参数层。

## 8. mapper、Catalog、图谱与测试建议

1. 新增通用的 two-stage HTTP dispatcher producer：先发布 namespace registrar，再发布
   path-segment selector 与 branch；不要把 selector 硬塞进普通 `websFormDefine` table。
2. candidate 应保留 `namespace_prefix=/cgi-bin`、`selector=UploadWebsite`、
   `normalized_route=/cgi-bin/UploadWebsite`、`route_derivation=prefix_plus_path_segment` 与
   `method=unresolved`；normalized route 证据必须同时引用 registrar、path parser 与 compare arm。
3. dispatcher 枚举不能依赖历史 anchor 截断。以结构结束点/失败响应为边界，本样本回归必须恢复
   7 个 selector，特别是尾部 `UploadWebsite`，并拒绝“6 个即完整”的假完成状态。
4. 路由 owner 与业务 consumer 分离：`webs_Tenda_CGI_BIN_Handler@0x3a678` 是 namespace owner，
   `httpd@0x3a9a0` 是 selector dispatcher，`httpd@0x3e564` 是 operation handler。
5. 图谱建议投影：
   `HTTP route -> namespace owner -> selector dispatcher -> operation handler -> URL IPC operation -> state`；
   UI 对 deterministic-composed route 使用与 direct literal 不同的 badge/tooltip。
6. 增加负回归：不得生成 `/goform/UploadWebsite`、method `POST`、
   `UploadWebsite -> load_url_mib`，且不得把 IPC frame fields 投影成 HTTP parameters。
7. frontend absence 应发布为 client-coverage obligation，而不是降低已由 registrar/control-flow 证明的
   backend route；method 则必须等待 selector-specific static guard 或运行时请求 trace。
8. activation 下一步应采用真实设备/仿真 trace，在一次 website upload 与一次 configuration backup
   upload 中分别观测 `load_url_mib/reload_url_mib`，避免把两个“upload”语义混为一条链。

## 9. 分析时间线、反事实与论文价值

1. R2-26 证明了 secondary URL document writer/latent loader，但 upload-to-loader execution edge
   未闭合。
2. R2-27 闭合 URL daily IPC，并只把 `UploadWebsite` token 到 `0x3e564` 视为 selector edge；因为
   尚未追到 prefix registrar，HTTP route binding 义务保持 open。
3. 本轮先从 handler GOT relocation 反向定位初始化函数，再用 `/goform` 阳性对照与 registrar
   本体存储语义证明 `/cgi-bin -> webs_Tenda_CGI_BIN_Handler`。
4. 进一步恢复 handler 的 `path` 第二段提取，route obligation 因三段组合证据从 open 变为
   supported deterministic-derived；同时将 dispatcher 完整数从 6 修正为 7。
5. 深入 `0x3e564` 后仍只看到 daily URL API。loader activation 与 method obligation没有被 route
   closure 传递关闭。

反事实失败模式：

- 若按 Tenda 常见 form 命名补成 `/goform/UploadWebsite`，会选错 transport namespace；
- 若只枚举已有六个历史 anchor，会恰好漏掉尾部 `UploadWebsite`；
- 若要求完整字符串才能发布 route，会漏掉真实的 prefix + segment dispatcher；
- 若把“上传 body consumer”直接等价为 POST，会把协议习惯冒充 selector-specific 证据；
- 若因 route 已闭合而传递关闭 loader obligation，会虚构第二文档 activation。

这个案例适合论文中的“分层 route reconstruction 与 obligation non-transitivity”：更深分析可以同时
关闭一个 obligation、修正一个 completeness claim，并保持另一个语义相近但证据独立的 obligation
开放。限制是当前结论仍来自静态 rootfs；method、认证、运行时可达与 loader activation 需要动态材料。
