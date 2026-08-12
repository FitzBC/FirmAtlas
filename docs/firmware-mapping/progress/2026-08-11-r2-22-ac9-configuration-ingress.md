# R2-22：AC9 配置上传入口与独立 CGI 分发器

## 本轮目标

以 Tenda AC9 为首要样本，继续处理 R2-21 的两个 priority-95 configuration-key sink。
本轮不预设配置键是 HTTP 参数，而是从用户可见上传入口反向恢复：

```text
frontend request → multipart field → dispatcher family → native handler
                 → configuration persistence (若证据足够则继续，否则拆分义务)
```

固件身份保持为
`981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296`；
不执行固件、不发送请求、不使用历史漏洞文本替代制品证据。

## 阶段时间线与反思

### 1. 前端入口先行

`webroot_ro/system_backup.html` 直接声明：

- `POST /cgi-bin/UploadCfg`；
- `multipart/form-data`；
- file field `filename`。

对应 EvidenceAtom locator 为：

- request：`text_utf8:bytes=541-559;lines=15:54-15:72`；
- parameter：`text_utf8:bytes=1322-1330;lines=28:92-28:100`。

这足以证明请求形状，但还不足以证明执行 owner。

### 2. 第一个候选被否定：不是普通 websForm registrar

此前 AC9 的 `/goform/*` 主要通过 `websFormDefine` 注册。完整 registrar 枚举只观察到
`SysToolRestoreSet → fromSysToolRestoreSet` 等普通 route，未找到 `UploadCfg` 或
`DownloadCfg`。`etc_ro/init.d/rcS` 虽启动 `tendaupload`，但进程名和上传语义都不能证明
该进程拥有 HTTP route。

若停在这里，可能产生两个反事实错误：

1. 因 registrar 中无 token 而把真实入口归为 frontend-only；
2. 因 `tendaupload` 名称相似而错误转移 owner。

### 3. 第二套 dispatcher family

`bin/httpd` 在 `0x3a9a0` 使用独立字符串 switch。新 Producer 只在以下条件全部成立时绑定：

1. frontend path 的 `/cgi-bin/` 后第一段与二进制 token 逐字节相同；
2. ARM PIC base 可由函数内指令恢复；
3. token 长度立即数与 UTF-8 长度相同；
4. 至少两个条目共享同一 dispatcher 和 compare target；
5. compare 结果显式与零比较，非匹配分支跳过 handler arm；
6. 匹配 arm 直接 `BL` 到可执行 handler。

AC9 实样本恢复六项 dispatcher family，其中本轮焦点为：

```text
POST /cgi-bin/UploadCfg
  └─ form field: filename
      └─ CGI dispatcher: bin/httpd@0x0003a9a0 (6 entries)
          └─ UploadCfg → bin/httpd@0x0003b850
```

自动证据为 token `binary:bytes=869824-869833`、PIC base
`binary:bytes=207276-207284`、comparison block `binary:bytes=207352-207388` 和
handler call `binary:bytes=207400-207404`。同一 Adapter 也验证
`DownloadCfg → bin/httpd@0x0003c0ac`；`/cgi-bin/DownloadCfg/RouterCfm.cfg`
正确取第一段 `DownloadCfg`，不会错误取末段文件名。

### 4. 误报约束

合成 fixture 的三类回归分别证明：

- 单一相似 entry 不足以建立 dispatcher family；
- 第二 entry 使用不同 compare target 时不能凑成 family；
- token 长度与 literal 不一致时不能绑定。

因此本轮不是“在二进制中找到 UploadCfg 字符串”，而是恢复了带控制流判据的接口所有权。

### 5. 跨二进制延续与自动化边界

人工指令级审计继续观察到：

```text
httpd UploadCfg handler@0x3b850
  → tpi_upfile_handle(mode=1)
  → libtpi:tpi_sys_cfg_upload
  → split at "##the public configure end##"
  → /webroot/default.cfg + /webroot/default_url.cfg
  → doSystemCmd("cfm Upload")
  → bin/cfm Upload command handler
  → libCfm:UploadValue → Cfm IPC blocks
```

机器报告保存了四个制品 SHA、六个调用点的 virtual/file offset 和 instruction bytes，以及
四个精确 literal。它们是可重放的研究证据，但尚未进入通用 AnalyzeRun Producer。因此：

- `obligation:configuration-ingress` 已由自动 request→dispatch→handler 链关闭；
- 新建 `obligation:configuration-persistence-link`，要求下一轮自动化跨 ELF PLT/call chain；
- `security.ddos.map` 与 `sys.schedulereboot.*` 继续是 configuration key；
- 当前不声称上传文件在运行时被接受、任意 key 均有效或漏洞存在。

## 工程实现

- 新增 `native-arm-cgi-string-dispatch@0.1.0` 深模块；
- 新增 `DiscoveryProducerKind/DiscoveryCandidateKind.NATIVE_CGI_DISPATCH`；
- Catalog 同时发布 dispatch candidate 与精确 handler candidate；
- 通信图投影 `request --dispatched_by→ dispatch --binds_handler→ handler`；
- 默认 profile/registry 升级为冻结的 `auto-v14/builtin-v14`，`auto-v13` 保持旧行为；
- 统一 AnalyzeRun 从 frontend CGI request 自动生成 anchor，只扫描实际包含 anchor token 的
  ARM32 ELF，并发布独立 stage；
- 新增 AC9 报告生成器和机器报告，研究案例时间线从“未知 ingress”迁移为“owner 已知、
  persistence 自动化开放”。

## 中间输出

- [R2-22 机器报告](../samples/r2-22-vendor-tenda-ac9-configuration-ingress.json)
- `analysis_run_id`：
  `mapping-analysis-run:ee24bf5afe771663436e686188742503ecc95c7d7883d7ddc45dd913a948a530`
- `native_cgi_dispatch` stage：1 个包含 `/cgi-bin/` namespace 的 ARM 输入、4 个 frontend-ref-specific binding、
  coverage `completed`；
- 焦点链：6 个自动 EvidenceAtom、2 条图边；
- 跨二进制 continuation：10 条可寻址审计记录。

4 个 binding 不是 4 个不同 native route：同一个 Upload/Download token 可由不同前端制品
候选引用，Catalog 保留 frontend reference 身份；图查询可按 canonical interface 聚合。

## 验证

已完成的目标验证：

```text
tests.test_mapping_native_cgi_dispatch                 6 passed
tests.test_mapping_configuration_ingress_report        1 passed
discovery_catalog + communication_graph + analysis_run 50 passed
```

发布验证已完成：

```text
Python unittest                 497 passed（142.225s）
Console Vitest                  22 passed（9 files）
Console typecheck + Vite build  passed（1801 modules）
机器报告双进程逐字节重放        byte-identical
checked-in 报告比对             byte-identical
```

最终报告 SHA-256 为
`3c117982bbdfd3166fdc25f5a634237af3002dbebf9b5126d85e2d5a40393135`。
提交前仍执行 `git diff --check` 和敏感信息扫描，随后通过 GitHub SSH 推送。
通信测绘研究按仓库例外和用户要求不做 SSH 远程部署。

## 下一轮明确工作

R2-23 继续以 AC9 为主样本，实现通用 ARM ELF PLT/call-chain producer：

1. 从已绑定 handler 验证到 `tpi_upfile_handle` 的 PLT call；
2. 解析 `tpi_sys_cfg_upload` 的双输出路径、split marker 与 `cfm Upload`；
3. 恢复 `bin/cfm` 的 `gCtlCmdArr` command→handler 表；
4. 绑定 `libCfm:UploadValue` 的 IPC 消息链；
5. 把上传配置建模为 wildcard configuration-state write surface，再与历史 configuration-key
   sink 相连；若缺少 key 级 parser 证据，只发布 may-affect/wildcard，不发布精确参数流。
