# R2-27：AC9 URL 日常 IPC 与跨状态域消费者

> 日期：2026-08-13
> 主样本：Tenda AC9 `V15.03.05.19(6318)`，Firmware Artifact SHA-256
> `981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`
> Profile / Registry：`auto-v19` / `builtin-v19`
> SSH 部署：不适用（`firmatlas.mapping` 研究例外）

## 本轮问题与设计边界

R2-26 已证明 AC9 存在独立的 URL 配置文档 consumer，但仍不知道日常业务如何读写
`cfm/url_mib/*`，也不能把共同的 `urlgroup.` 前缀直接当成同一状态域。本轮把可复用工具能力
定义为两个稳定接口：

1. 从任意已解包 rootfs 的 ELF 集合恢复 URL-store IPC 的 client、frame、opcode、daemon
   dispatcher、server wrapper 与 store primitive；
2. 在业务二进制中按“字面量出现位置到最近 URL client callsite”绑定 key template 和
   read/write/delete，而不是用函数级或前缀级共现。

IPC frame 字段是进程间协议，不是 HTTP 参数；静态调用关系也不等于运行时激活、认证结论或
漏洞存在。日常 IPC 不会自动关闭 R2-26 的 document loader activation 义务。

## 研究证据与认识时间线

原始来源与逐地址证据保存在
[AC9 URL IPC activation primary sources](../research/2026-08-13-ac9-url-ipc-activation-primary-sources.md)。

1. 首先闭合 `/var/cfm_socket` 上 2016-byte 消息：opcode@0、key/path@4、value@516；操作为
   Get 32/33、Set 30/31、Unset 36/37、Commit 34/(35 或 16)、Show 38/39。
2. 随后证明 `libCfm` client 经 `cfmd@0xa504` 分发到五个 wrapper，再进入
   `url_mib_get/set/unset/list` 与 `save_url_mib`。
3. 初始假设按 `urlgroup.` 前缀归组。深入同一 httpd 函数后发现架构分裂：`list*`/`class*`
   跟随 URL client，`rule.*`/`flag` 却调用主 `GetValue/UnSetValue/CommitCfm`；`name` 只有 parser
   比较，尚未绑定状态域。于是实现改成逐字面量出现位置的 callsite binding。
4. 全固件复扫 287 个 ELF，257 个可解析；`reload_url_mib` 只内部调用 `load_url_mib(0)`，没有
   外部 caller/importer，也没有 `load_url_mib(1)`。因此 activation obligation 仍为 open。
5. 首轮页面验收又暴露视图合同缺陷：底层 consumer→state 边存在，但“参数与状态” preset
   漏掉 `component`，导致模板焦点只显示 1 node / 0 edge。加入回归断言后修正 preset，二次
   页面验收恢复为 4 nodes / 3 edges。该失败没有被最终成功倒写覆盖。

## 已固化的工具能力

- 新 producer `native-arm-configuration-url-ipc-flow@0.1.0`，带 source identity、字节与指令
  预算、fail-closed 校验、可重放 EvidenceAtom；
- `auto-v19/builtin-v19` 从完整 rootfs 自动分类 `libCfm/cfmd/httpd/cfm`，无需把 AC9 接口清单
  作为输入；旧 profile/registry 继续冻结重放；
- Catalog 发布 5 个 operation 与 5 个 httpd consumer，operation 同时保留 httpd 与 cfm CLI
  调用计数；不生成 HTTP parameter；
- Graph 发布 `reads_state`、`writes_state`、`deletes_state`、`persists_state`，具体模板使用
  `(key template, access mode)` 精确投影；
- Console 增加“URL IPC”“URL 状态消费者”筛选，详情展示 frame、opcode、offset、wrapper、
  primitive、调用计数、逐 callsite 提示和原始证据；参数/状态图可同时显示 consumer 与 state。

## 真实样本中间输出

机器报告：[r2-27-vendor-tenda-ac9-configuration-url-ipc.json](../samples/r2-27-vendor-tenda-ac9-configuration-url-ipc.json)，
SHA-256 `a5301e62b9576a40973a8d20387e0dd9b6eaa8bc2f6d5f9327d23550725269b2`。

- stage：`completed`，5 operations + 5 consumers；
- httpd 调用点：Get 16、Set 6、Unset 2、Commit 1；cfm CLI 五种操作各 1；
- URL 状态模板：`urlgroup.list%d/listnum/sysnum` 与
  `urlgroup.class%d.list%d/listnum/sysnum`；
- 负面对照：`urlgroup.rule.list%d/listnum`、`urlgroup.flag`、`urlgroup.name` 不进入 URL
  consumer；真实主 MIB 仍观察到 `urlgroup.rule.list1/listnum`；
- 图谱：7,111 nodes / 9,312 edges，URL scope 包含 read/write/delete/persist 四类边；
- analysis run `mapping-analysis-run:4d519344e77064113bacaae2cef4d864553f5463eafa21a10bf6235f6075282e`，
  graph `communication-graph:ab88b632cc4d34d4b3f94fdbb7794e9b00629531799c78f8a16850c06757741a`。

## 回归、服务与页面验收

- Python 全量：`521 passed in 1094.42s`；
- 冻结报告/案例冷启动矩阵：`18 passed in 582.64s`；
- Console：9 files / 24 tests；两套 TypeScript check 与 Vite production build 通过；
- `serve_vendor_tenda_ac9_mapping_round.py` 从真实 AC9 rootfs 独立分析、发布 SQLite catalog/graph；
  `GET /api/health` 返回 `status=ok`，生产前端文档可加载；
- 页面依次操作“通信测绘 → URL IPC → SetUrlValue”，可见 2016 bytes、opcode 30/31、offset
  4/516、`SetCfmUrlValue → url_mib_set_value`、httpd 6/cfm 1 调用和四条证据定位；
- 图谱搜索 `cfm/url_mib/*` 返回 7 nodes / 6 edges；搜索并聚焦
  `urlgroup.class%d.list%d` 后，“参数与状态”显示 4 nodes / 3 edges，分别为 read/write/delete；
- 聚焦 `urlgroup.rule.list1` 只显示主 `cfm/default_mib/*` 的 `imports_state`，没有 URL IPC 边；
  浏览器 warning/error 为 0。验收后停止本地服务。

## 反事实、限制与下一轮

- 若只按共同前缀或函数级操作集合投影，会把每种访问方式错误连到每个 key，并把主 MIB 的
  `rule.*` 冒充 URL MIB；本轮的重复 literal occurrence 和最近 callsite 绑定用于避免该错误。
- 当前只静态证明协议和调用图，未证明请求真实发生、服务认证边界或漏洞可利用性。
- `UploadWebsite` selector 到内部函数的直接边已观察，但外层 HTTP route/method 仍未绑定；
  `reload_url_mib` activation 仍开放。下一轮应恢复该 selector 的 transport/route ownership，
  并在安全隔离环境取得动态上传/loader 证据；在此之前不得补造 `/goform` 路径或 method。

Git revision：`a94e6ad70fe924bd346e704a470dcab806fb6739`（功能、测试、机器报告与本轮
验收记录）；随后 revision 仅追加该检查点和推送交接元数据。
