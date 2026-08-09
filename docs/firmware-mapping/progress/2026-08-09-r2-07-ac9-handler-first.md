# R2-07：Tenda AC9 handler-first registrar 与 DLNA 剩余义务

> 主样本：Tenda AC9 V15.03.05.19 / `BM-2024-00012`
> 输入缺口：R2-06 的 5 条 Frontend-only goform action

## 真实证据复核

逐制品精确搜索将五条分成两组：

- `GetUpnpCfg/GetSySLogCfg` 同时存在于页面与 `bin/httpd` route pool；相邻动态符号分别是
  `formGetUpnpLists/formGetSysLog`；
- `GetDlnaCfg/SetDlnaCfg/refreshDLNA` 只存在于 `webroot_ro/js/dlna.js`，整个 Native 辅助范围无
  精确 token。页面还把 refresh 点击绑定注释掉，因此不能仅凭函数定义声称运行时会发送请求。

指令复核发现前两条仍调用 registrar `0x17134`，但采用第二种合法布局：先加载 handler GOT
relocation，再以 r2 加 PIC base 得到 route、搬入 r0，handler 留在 r3 后搬入 r1。旧 v2 Profile
只支持 route-first/r3，所以 route string 虽已被 Shallow Producer 观察，binding 仍漏失。

## TDD 与版本护栏

1. RED：最小 ARM ELF 使用 handler-first/r2-route，两条验证注册均未枚举；
2. GREEN：v3 Profile 支持第二模板，但继续要求 literal、PIC base、GOT relocation、可执行符号、
   BL registrar 与至少两对共享注册；
3. `auto-v5/builtin-v5` 启用 v3；R2-06 固定 `auto-v4 + ArmPic v2`，旧报告不漂移；
4. Set Difference 将 287 个 Native 制品作为 Frontend-only 辅助证据。初次同时扫描 Native-only
   时，高频 token 超过 hit budget，coverage 降为 partial，潜在隐藏接口索引按 gate 发布 0 条；
5. 新策略只用辅助制品解释 Frontend-only，Native-only 仍由验证 registrar 与完整前端差集决定，
   coverage 恢复 completed。

## 状态迁移

| 指标 | R2-06 | R2-07 |
| --- | ---: | ---: |
| registrar inventory | 185 | 187 |
| anchor binding | 59 | 61 |
| Catalog EvidenceAtom | 4821 | 4831 |
| open obligations | 61 | 57 |
| Frontend-only | 5 | 3 |
| potential hidden interface | 110 | 110 |

新增证明：

- `GetUpnpCfg → formGetUpnpLists @ 0x00087b38`，registration callsite `0x42830`；
- `GetSySLogCfg → formGetSysLog @ 0x00079e88`，registration callsite `0x42cac`。

剩余 DLNA 三条不能称为 mapper miss，也不能称为固件已删除功能；当前可证状态是“前端声明存在、
当前完整 Native 辅助范围没有精确 token”。下一步需检查版本配套错误、条件组件、脚本/IPC 后端或
死前端资源。

完整证据 ID 与中间结果见
[R2-07 handler-first report](../samples/r2-07-vendor-tenda-ac9-handler-first.json)。

## 下一轮

- 从 DLNA 页面参数 `dlnaEn/deviceName/scanList/folderGrade/filePath` 追踪脚本、IPC 与配置状态；
- 对 110 条潜在隐藏候选建立认证与服务装配优先级，先处理 `telnet/MfgTest/ate` 等高价值义务；
- 用 187 条 registrar 目录辅助 AC9 漏洞语义回填，并验证历史接口参数别名。

## 验证记录

- Native callsite、Set Difference、AnalyzeRun、Hidden Index 定向回归 38 项通过；
- `make test`：396 项通过；Console Vitest：9 个文件、19 项通过；TypeScript 与 production build 通过；
- R2-06 冻结报告逐字段不变，R2-07 独立重放逐字段相等；
- R2-07 SHA-256：`cdd8c558a67e1dab084222e459296aa4e20adf1ca4ec84cee4aeab18ecb50e47`；
- Python/JSON、凭据片段扫描及 `git diff --check` 通过。

本轮属于 firmware mapping research，SSH 部署不适用。
