# Tenda AC9 `/webroot/default_url.cfg`：独立 URL 配置域与未闭合导入触发链

> 日期：2026-08-13
>
> 样本：Tenda AC9 `15.03.05.19`，固件制品 SHA-256
> `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`
>
> 范围：只使用本地解包固件、ELF 动态符号、ARM 反汇编与确定性调用扫描；不使用相邻型号或二手材料
> 结论等级：`default_url.cfg` 的 writer、latent loader、parser、独立 URL hash、IPC consumer 与
> `CFM_URL` 持久化域已闭合；上传后的实际 loader 触发链未闭合

## 1. 结论先行

`/webroot/default_url.cfg` 不是主配置 `/webroot/default.cfg` 的别名，也不能映射到
`cfm/default_mib/*`。固件直接证明它属于另一条配置通道：

```text
tpi_sys_cfg_download
  cfm show /etc/tmp.cfg
  + "##the public configure end##"
  + cfm urlshow /etc/tmp_url.cfg
  -> 合并下载文档

tpi_sys_cfg_upload
  -> /webroot/default.cfg
  -> /webroot/default_url.cfg
  -> cfm Upload

libCfm latent path
  load_url_mib("/webroot/default_url.cfg", mode)
  -> parser@0x766c
  -> strtok(newline) -> strchr('=') -> strdup
  -> URL hash helper@0x7de4 -> hash_insert
  -> cfm/url_mib/*
  <-> CFM_URL flash block
```

但是，当前制品中没有确定性静态边把 `cfm Upload`、opcode 14 或 `RestoreMTD` 接到
`load_url_mib`：

- opcode 14 的 daemon 分支仍只调用 `RestoreMTD@0x588c`；
- `RestoreMTD` 只经 `InitDefaultCfm` 调用主域 `load_mib`；
- `load_url_mib` 的两个已解析调用点都位于 `reload_url_mib` 内部；
- `reload_url_mib` 在 287 个 ELF 的全制品扫描中没有 importer 或静态调用点。

所以最严格的当前结论是：上传处理器**产生**第二文档，固件也包含能解析它的独立 loader，
但“本次上传会执行第二文档导入”仍是开放义务。不能把主 `default.cfg` 的 1013 个唯一键复制到
URL 域，也不能把 URL store 的已知 reader 倒推成当前缺失文档里的默认声明。

## 2. 来源账本

解包根：
`../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root`。

| 制品内路径 | SHA-256 | 本轮用途 |
|---|---|---|
| `lib/libtpi.so` | `afd61cc5a6e2bd79e913d773d86fbd95b58a33f04e976b3c837827e5aa80c5ac` | 下载拼接、上传拆分、第二文档 writer |
| `lib/libCfm.so` | `163f8d4a470116288385bee4d65009db1a393773567d08decd91f72b9b195d09` | latent loader、parser、URL hash、flash store 与 client IPC |
| `bin/cfmd` | `5483f90689f6f068d924d1043bc219560b31e6b4a75b634ce1d55a1b596abede` | opcode dispatcher 与 URL store 服务端 consumer |
| `bin/cfm` | `913e1a916cf2fd54772f1cd56932bdc6cbd25b0df7307c9a2cb2fe26b3b688f5` | `urlSet/urlGet/urlUnSet/urlshow` CLI consumer |
| `bin/httpd` | `2fd5c92e15f8c9c0b45047c77af080539237d7b99a9b35fe43dc2a9d5a57702b` | URL group 业务键的实际读写 consumer |

整个解包树中不存在名为 `default_url.cfg` 的静态文件；因此本轮没有该文档的内容 SHA、行号或
键声明列表。两个完整路径字面量 owner 只有 `libtpi.so` 与 `libCfm.so`。

## 3. writer 与备份格式：直接静态证据

### 3.1 下载方向定义了两个逻辑段

`lib/libtpi.so:tpi_sys_cfg_download@0x9994` 的 PIC literals 与调用点直接给出：

- `/etc/tmp.cfg`，binary file span `0x4fa30..0x4fa3c`；
- `cfm show /etc/tmp.cfg`，`0x4fa40..0x4fa55`；
- `##the public configure end##`，`0x4fb48..0x4fb64`；
- `cfm urlshow /etc/tmp_url.cfg`，`0x4fb68..0x4fb84`；
- `cat /etc/tmp_url.cfg >> /etc/tmp.cfg`，`0x4fb88..0x4fbac`。

相应 `doSystemCmd` 调用位于 `0x99d0`、`0x9b48`、`0x9b64`、`0x9b74`、`0x9b90`、
`0x9ba0` 与 `0x9bb0`。这直接证明备份文档按 delimiter 拼接普通 MIB 与 URL MIB 两段。

### 3.2 上传方向只证明“写出”，尚未证明“加载”

`lib/libtpi.so:tpi_sys_cfg_upload@0x9c5c` 同时持有：

- `/webroot/default.cfg`，file span `0x4fbc0..0x4fbd4`；
- `/webroot/default_url.cfg`，file span `0x4fbdc..0x4fbf4`；
- 同一 delimiter，file span `0x4fb48..0x4fb64`；
- `cfm Upload`，file span `0x4fbf8..0x4fc02`。

函数在 `0x9ca4/0x9cc8` 打开两个文件，在 `0x9cf8` 查找 delimiter，在
`0x9d1c/0x9d48` 分别写入两段，最后在 `0x9d68` 执行导入命令。因此可发布
`writes_primary_document` 与 `writes_secondary_document`，但这个函数本身没有调用
`load_url_mib`、`reload_url_mib` 或 URL IPC client。

## 4. 独立 loader、parser 与 store：直接静态证据

### 4.1 `load_url_mib` 明确拥有第二路径

`lib/libCfm.so:load_url_mib@0x8d0c..0x8da4` 持有
`/webroot/default_url.cfg`（file span `0xe74c..0xe764`），并在 `0x8d40` 调用内部
loader/parser `0x766c`。与主域 `load_mib@0x8c74` 调用 `0x7314` 不同，它在
`0x8d2c` 初始化另一张 hash，并在失败时调用独立清理函数 `0x7b70`。

`load_url_mib` 把自己的 `mode` 参数继续传给 `0x766c`。parser 的控制流直接表明：

- `mode == 0` 时先在 `0x7724` 调用 `nvram_cfm_url_init` 从 `CFM_URL` block 取值，失败再从
  `/webroot/default_url.cfg` 读取；
- `mode != 0` 时跳过 flash 初始化，直接从文件读取；
- `mode == 1` 且解析结束时，`0x793c` 调用 `0x8af0`，后者序列化 URL hash 并排队保存。

因此可确定的是 mode 0 的 flash-first/fallback-file 分支，以及 mode 1 的 file-first/save 分支；
本轮没有给 mode 取业务名称，也不根据函数名猜测它由哪条外部操作触发。

### 4.2 parser 是相同语法、不同 hash

`parser@0x766c..0x7950` 的关键 locator：

| locator | 事实 |
|---:|---|
| `0x774c`、`0x77a8` | internal file-to-buffer helper `0x5ed0` |
| `0x77e8`、`0x7910` | `strtok` 按换行迭代 |
| `0x783c` | 共享 entry helper `0x5d2c` |
| `0x5d98` | helper 调用 `strchr`，立即数为 `0x3d`（`=`） |
| `0x78a8`、`0x78c4` | 分别 `strdup` key 与 value |
| `0x78dc` | 调用 URL 专用 hash helper `0x7de4` |
| `0x7e6c` | URL helper 最终调用 `hash_insert` |

主 parser `0x7314` 最终调用的是另一 helper `0x7d18`；URL parser 调用 `0x7de4`。因此二者
共享 `key=value` 文法，却写入不同 hash。最合适的状态 scope 是 `cfm/url_mib/*`，不是
R2-25 主链使用的 `cfm/default_mib/*`。

### 4.3 `CFM_URL` 是独立持久化域

`libCfm.so` 只有自身持有 `CFM_URL` literal：

- `nvram_cfm_url_init@0xa648..0xa94c`：`get_cfm_url_blk_size_from_cache → flash_read → crc32 → uncompress`；
- `nvram_cfm_url_commit@0xafec..0xb2dc`：`compress → crc32 → flash_write`；
- literals `CFM_URL` 分别由这两条路径引用。

这证明 URL hash 与 URL flash block 构成独立持久化通道。它不等价于主 `default_mib`，也不证明
物理 MTD 分区号；`CFM_URL` 是代码中的 block identity。

## 5. 已闭合的 IPC consumer，而不是已闭合的上传触发

URL store 的日常读写链是完整的 2016-byte Cfm IPC：

| client (`libCfm.so`) | request/response opcode | `cfmd@0xa504` 分支 | server wrapper | store primitive |
|---|---:|---:|---|---|
| `GetUrlValue@0x4820` | `32 / 33` | `0xa874..0xa8d0` | `GetCfmUrlValue@0x56b8` | `url_mib_get_value → hash_find` |
| `SetUrlValue@0x4a80` | `30 / 31` | `0xa8d4..0xa930` | `SetCfmUrlValue@0x5718` | `url_mib_set_value` |
| `UnSetUrlValue@0x4c54` | `36 / 37` | `0xa934..0xa97c` | `UnSetCfmUrlValue@0x5748` | `url_mib_unset_value → hash_remove` |
| `CommitUrlCfm@0x3788` | `34 / 35`（成功也接受通用 `16`） | `0xa980..0xa9cc` | `SaveCfmUrl2Flash@0x5770` | `save_url_mib` |
| `ShowUrlValue@0x4de0` | `38 / 39` | `0xa9d0..0xaa18` | `ShowCfmUrlValue@0x5788` | `url_mib_list` |

`bin/cfm` 导入这些 client，并把它们暴露为 `urlSet`、`urlUnSet`、`urlGet` 与 `urlshow`。
`bin/httpd` 也导入 `GetUrlValue`、`SetUrlValue`、`UnSetUrlValue`、`CommitUrlCfm`。

`httpd` 的直接业务 consumer 至少包含：

- `0x3d6c0..0x3de34`：读取 `urlgroup.sysnum`、`urlgroup.list%d`、
  `urlgroup.class%d.listnum`、`urlgroup.class%d.sysnum`、`urlgroup.class%d.list%d`，并导出
  `/etc/website.cfg`；
- `0x3df54..0x3e0c0`：读写 `urlgroup.sysnum`、`urlgroup.listnum`、`urlgroup.list%d`；
- `0x3e0d4..0x3e538`：读写/删除 `urlgroup.flag`、`urlgroup.rule.listnum`、
  `urlgroup.rule.list%d` 与 class/list keys；
- `0x3e564..0x3ea54`：`UploadWebsite` 路径读写 `urlgroup.name` 与 class/list keys，最后在
  `0x3e9d0` 调用 `CommitUrlCfm`。

这些 key 是 URL store reader/writer 的直接证据，但当前静态 root 没有 `default_url.cfg` 内容，
所以不能宣称它们一定由默认文档声明或由一次配置上传写入。

## 6. 断链核验与负面搜索

### 6.1 全制品 literal/symbol 搜索

复核命令：

```sh
rg -a -l -F '/webroot/default_url.cfg' "$artifact_root"
rg -a -l -F 'load_url_mib' "$artifact_root"
rg -a -l -F 'reload_url_mib' "$artifact_root"
find "$artifact_root" -type f -name 'default_url.cfg' -print
```

结果：完整路径只有 `libtpi.so`、`libCfm.so`；`load_url_mib` 与 `reload_url_mib` 字符串只在
`libCfm.so` 的自身动态符号表；静态文件搜索为零。

### 6.2 287 ELF 的确定性 call/import 扫描

扫描所有 ELF magic 文件，以 `.plt` relocation + ARM direct branch 恢复 importer/callsite：

- 总计 287 ELF；257 个用户态/可支持 ELF 成功解析；
- 30 个失败项主要是 kernel module、loader 或不满足当前 dynamic-ELF parser 的制品；
- `load_url_mib` 唯一 importer 是 `libCfm.so` 自身，唯一调用点为
  `reload_url_mib@0x8e30/0x8e54`；
- `reload_url_mib` importer 0、调用点 0；
- `close_url_mib` importer 0、调用点 0；
- 原始 byte search 同样没有在那 30 个 parser 失败项中发现这些符号或路径。

相对地，URL IPC consumer 扫描能稳定恢复：

- `bin/cfm@0x9240` 与 `bin/httpd@0x3e9d0` 调用 `CommitUrlCfm`；
- `bin/httpd` 有 16 个 `GetUrlValue`、6 个 `SetUrlValue`、2 个 `UnSetUrlValue` callsite；
- `bin/cfmd@0xa8a8/0xa908/0xa954/0xa98c/0xa9f0` 调用五个 server wrapper。

这说明 scanner 能看到真实 URL 业务链；缺失的恰好是 loader trigger，而不是搜索器把所有 URL
调用都漏掉。

### 6.3 opcode 14 反事实

`cfmd@0xa800..0xa870` 对 request opcode 14 调用 `atoi@0xa83c` 与
`RestoreMTD@0xa848`，response 为 15。`RestoreMTD@0x588c..0x59a4` 的 call set 是
`SetCfmValue`、`restore_config_type`、`RestoreNvram`、`InitDefaultCfm` 与 `sleep`；
`InitDefaultCfm@0x5480` 只调用 `close_mib/load_mib`。

若把“第二文件已写出”直接等价为“第二 URL store 已导入”，会错误补出一条不存在的
`RestoreMTD → load_url_mib` 边，并把主域 1013 个键错误复制到 URL 域。这正是本轮必须保留的
反事实失败模式。

## 7. 证据等级、限制与开放义务

### 直接静态证据

- 两个 literal owner、writer、delimiter 与下载拼接格式；
- `load_url_mib → parser@0x766c → URL hash_insert`；
- `CFM_URL` flash read/commit；
- URL IPC opcodes、daemon wrappers 与 HTTP/CLI consumers；
- 当前制品中不存在静态 `default_url.cfg` 源文件。

### 确定性派生

- `cfm/url_mib/*` 是独立状态 scope；
- mapper 可发布 writer、latent loader、parser、store 与 consumer 节点；
- writer-to-loader 的 execution edge 当前必须保持 unresolved。

### 不得宣称

- `cfm Upload` 在真实运行时必然调用 `load_url_mib`；
- 当前上传能恢复 URL store；
- 已知 `urlgroup.*` reader keys 必然存在于某个上传文档；
- `CFM_URL` 对应某个未经定位的物理分区号；
- 任一 URL handler 存在或可利用历史漏洞。

### 开放义务

1. 从设备运行时或真实配置备份取得第二段内容，保存内容 hash、顺序声明与重复键；
2. 动态观测一次配置上传，确认是否有间接调用、另一个进程或后续重启路径触发
   `load_url_mib(1)`；
3. 搜索 `dlsym`、函数表或运行时脚本生成的间接入口；没有动态证据前不把静态断链改写成执行边；
4. 把 `urlgroup.*` consumer keys 与实际第二段声明做双向差分：reader-only、document-only、both；
5. 若真实设备同样不触发第二 loader，应把它升级为固件行为缺陷候选，而不是 mapper 漏报。

## 8. 对 mapper 与页面的具体影响

1. 新 flow 身份应以 `load_url_mib@0x8d0c`、`parser@0x766c` 与 `cfm/url_mib/*` 组成，不能复用
   R2-25 的 `parser@0x7314` 或 `cfm/default_mib/*`。
2. 图谱至少分成 `upload writer → secondary document`、`latent loader → URL store` 两段；中间以
   open obligation/未验证虚线表达，禁止生成确定性 `invokes`。
3. 在缺少第二文档内容时，Catalog coverage 应为 `PARTIAL`，声明键数量应为 unknown/0，而不是
   从 `webroot_ro/default.cfg` 继承。
4. consumer 可单独发布：`bin/httpd`/`bin/cfm → URL IPC → cfmd → cfm/url_mib/*`，并把
   `urlgroup.*` 标为 configuration-state key template，不标为 HTTP body/query parameter。
5. 页面应让用户一眼看到“writer 已证实、loader 存在、execution 未闭合”，并能展开本节的
   负面搜索、257/287 ELF coverage 与 30 项 parser limitation。
6. 回归门必须包含反向断言：当前 AC9 样本不得出现
   `RestoreMTD → load_url_mib` 或 `default.cfg key → cfm/url_mib/*`。
