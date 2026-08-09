# R2-05：Tenda AC9 双向 ARM PIC literal pool 与 Samba binding

> 主样本：Tenda AC9 V15.03.05.19 / `BM-2024-00012`
> 目标：解释并关闭 `SetSambaCfg` 的 route→handler obligation

## 失败复现与根因

R2-04 已观察 `/goform/SetSambaCfg`、页面参数、Native route string 和动态符号
`formSetSambaConf`，但字符串共现不构成绑定。指令级复核发现同一 `bin/httpd` 存在两种合法的
ARM literal-pool 访问：早期注册块用 `LDR [PC, +offset]`，Samba 所在较后注册块则用
`LDR [PC, -offset]` 回指前方 pool。旧 `arm32-pic-r0-r1-bl/v1` 只接受 U-bit 为 1 的前向形式，
因此遗漏整个后向注册块。

## TDD 切片与证据门限

公共 seam 是 `discover_arm_pic_callsite_bindings(source, content, anchors, profile)`。

1. RED：最小 ARM32 ELF 使用负向 route/handler literal load，返回 0 binding；
2. GREEN：按 ARM U-bit 计算加减偏移，仍要求固定 r0/r1 参数流、GOT relocation、可执行 handler
   symbol、可执行 registrar branch target 和同 registrar 至少两对独立注册；
3. 真实回放：`SetSambaCfg → formSetSambaConf` 位于 callsite `0x43780`，registrar `0x17134`，
   registrar 内共有 164 对结构注册；`GetSambaCfg → formGetSambaConf` 同时恢复；
4. 版本护栏：旧行为冻结为 `ArmPicCallsiteProfile.v1()`；`auto-v1/auto-v2` 报告不漂移，默认升级
   为 `auto-v3 / builtin-v3`。

新证据仍不声称运行时可达、漏洞存在或可利用性。若缺少 relocation 或 handler 不在可执行节，
即使名称相似也不会发布 binding。

## 整根结果

| 指标 | R2-04 | R2-05 |
| --- | ---: | ---: |
| Catalog candidates | 3461 | 3489 |
| parameters | 130 | 130 |
| EvidenceAtom | 4056 | 4126 |
| verified ARM route bindings | 45 | 59 |
| open obligations | 89 | 61 |
| historical routes with verified binding | 3/13 | 5/13 |

13 条历史 expectation 仍为 8 observed / 5 version-out-of-scope；变化发生在更深的后端绑定层。
精确制品的 `SetOnlineDevName` 与 `SetSambaCfg` 现在都具有接口、参数、method 和 handler binding
证据。完整机器输出见
[R2-05 report](../samples/r2-05-vendor-tenda-ac9-bidirectional-pic.json)。

## 反事实、局限与下一轮

只看动态符号会在 R2-04 提前伪造成功；只支持前向 literal 又会错误认为 Samba 使用另一套
dispatcher。保留 obligation 后再用真实指令形状驱动 Adapter 扩展，使失败原因和修复效果都可
重放。当前仍只有前端/历史 anchor 能触发深化，registrar 中 164 对并未全部进入 Catalog；下一轮
应增加“已验证 registrar 全表枚举→潜在隐藏接口”能力，同时对 46 条未语义分析 AC9 漏洞回填
结构化 expectation。

## 验证记录

- Native callsite、AnalyzeRun、historical audit 定向回归 34 项通过；
- `make test`：391 项通过；Console Vitest：9 个文件、19 项通过；TypeScript 和 production build 通过；
- R2-02 vendor 与 R2-04 冻结报告保持逐字段相等；R2-05 报告独立重放逐字段相等；
- R2-05 SHA-256：`1d3d96d3eb5638a8de1011ecf6d1b8208b30c07eac43597fea0ae2624ecaa326`；
- Python/JSON、凭据片段扫描及 `git diff --check` 通过。

本轮属于 firmware mapping research，SSH 部署不适用。
