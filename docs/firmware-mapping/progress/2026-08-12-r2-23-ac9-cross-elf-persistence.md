# R2-23：AC9 跨 ELF 配置持久化链

> 日期：2026-08-12
> 主样本：Tenda AC9 `15.03.05.19`
> 范围：symbol-sized command table、ARM PLT/import/export call chain、图谱与产品交互
> 部署：不适用；通信测绘研究按用户要求不做 SSH 远程部署

## 问题与设计

R2-22 自动证明了 `POST /cgi-bin/UploadCfg → bin/httpd@0x3b850`，但后续
`libtpi → cfm → libCfm` 仍是人工记录。本轮固定两个深模块 seam：

```text
discover_native_pointer_command_table_bindings(source, bytes)
discover_arm_cross_elf_calls(artifacts, handler anchors, bounded policy)
```

第一模块从动态符号尺寸和 entry layout 恢复命令→handler；第二模块验证 ARM `BL`、PLT
relocation、import symbol 与同固件 export。export owner 只能来自当前制品，或由
`DT_NEEDED` 唯一限定；即使全 rootfs 只有一个同名 export，只要 loader 依赖关系没有证明，
也只发布调用与参数并让 owner 保持未决。

## 红灯—绿灯与反思

1. 红灯：缺少跨 ELF producer；AC9 实样本期望的五个 PLT hop 无法导入。实现后恢复
   `tpi_upfile_handle/tpi_sys_cfg_upload/UploadValue/SendMsg/RecvMsg`。
2. 红灯：`gCtlCmdArr` 不符合旧的 fixed-width `daemon_exe_info` profile。新增四指针表 profile，
   恢复 15 项并绑定 `Upload → bin/cfm@0x9e20`。
3. 性能反思：按 frontend-ref 展开产生 1,221 个重复 hop。改为按 source function/callsite/export
   去重并保留 origin 集合，并把 libc/pthread 等平台运行库设为“记录边界但不递归”；最终 AC9
   分析降为 381 个唯一事实，stage `completed`。
4. owner 反思：最初按路径排序把 `doSystemCmd` 错绑到 `bin/pptpctrl`。改为 dependency-aware
   resolution 后，调用点与 `cfm Upload` 参数保留，owner 正确降级为未决。
5. 图谱反思：所有 hop 直接连入口会形成星图。新增 function-identity chain edge，并以
   `cfm Upload` 尾 token 连接 `gCtlCmdArr[Upload]`，不依赖 owner 猜测。
6. 页面反思：真实页面最初在接口焦点切换“通信组件”时得到 `partial / 0 nodes`，因为 preset
   先过滤掉 interface；补入 interface→dispatch→handler 入口闭包后，又发现 `calls` 被反向遍历
   会通过共享 libc callee 合并无关 caller。最终把 `calls` 查询定义为有向 caller→callee，且只让
   origin 连接锚点函数的直接调用。AC9 子图由预算截断的 240/480 收敛为 completed 128/161。

## AC9 自动结果

```text
POST /cgi-bin/UploadCfg
  → httpd@0x3b850 --tpi_upfile_handle@0x3ba38→ libtpi@0x9e80
  → tpi_sys_cfg_upload@0x9ef4 → libtpi@0x9c5c
  → doSystemCmd("cfm Upload")@0x9d68 [owner unresolved]
  → gCtlCmdArr[Upload] → bin/cfm@0x9e20
  → UploadValue@0x9e64 → libCfm@0x429c
  → SendMsg@0x4334 / RecvMsg@0x4374
```

机器报告：
[r2-23-vendor-tenda-ac9-cross-elf-persistence.json](../samples/r2-23-vendor-tenda-ac9-cross-elf-persistence.json)

本轮关闭 `obligation:configuration-persistence-link`，新建更窄的
`obligation:configuration-key-parser`。当前不声称静态链运行过、上传 blob 的每个 key 都被解析、
历史配置键是 HTTP 参数，或存在可利用漏洞。

## 验证门禁

- 目标与全量后端：cross-ELF/graph/repository/report 目标回归通过；`make test` 为
  **503/503 passed**，包含 AC9 rootfs 独立 AnalyzeRun与 directed-call 查询回归。
- Console：使用工作区固定 Node runtime，Vitest **22/22 passed**；TypeScript 双 tsconfig 检查
  与 Vite production build 通过（1,801 modules）。第一次普通 shell 因 `node` 不在 PATH 失败，
  属于环境前置条件，未计作代码绿灯。
- 确定性：两个独立进程生成报告逐字节一致，SHA-256 均为
  `0215beefc4b27f6808d327b86be97065ac3680e2f4753aac21e327b37fca53cc`。
- 最终服务：`PYTHONPATH=src python scripts/serve_vendor_tenda_ac9_mapping_round.py`；
  `/api/health=ok`；graph `46aa9a6b…` 为 completed、6,078 nodes / 8,261 edges；
  `/cgi-bin/UploadCfg + communication_components + 8 hops` 为 completed、128 nodes / 161 edges，
  无 diagnostics，包含 Upload/Restore、UploadValue、SendMsg/RecvMsg。
- 最终页面：实际进入“通信测绘 → 架构图谱”，搜索并聚焦 `/cgi-bin/UploadCfg`，切换“通信组件”，
  页面保持 completed；可见 `tpi_sys_cfg_upload`、`UploadValue`、`SendMsg/RecvMsg` 与
  `bin/cfm@0x9e20`。下钻 `doSystemCmd@0x9d68` 显示 `argument_literals=["cfm Upload"]`、
  `unresolved_import_owner`、入/出 `calls` 和精确 binary EvidenceAtom；浏览器 warning/error 为 0。
- 页面证据截图：
  [r2-23-ac9-uploadcfg-communication-components.png](./r2-23-ac9-uploadcfg-communication-components.png)。
- 发布前最后执行 `git diff --check`、凭证扫描、提交和 GitHub SSH 推送；SSH 远程部署按本研究
  例外明确不适用。

## 下一轮

R2-24 继续 AC9，恢复上传 blob 的 parser 与 wildcard/key-level configuration-state write。没有
key provenance 时仅发布 wildcard may-affect，不得把 `security.ddos.map` 或
`sys.schedulereboot.*` 写成 HTTP 参数。
