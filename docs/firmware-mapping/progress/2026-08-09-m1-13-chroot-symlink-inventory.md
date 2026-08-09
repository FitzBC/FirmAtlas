# M1-13：固件 chroot symlink Inventory

> 工作项：M1-13  
> 日期：2026-08-09  
> 状态：已验证  
> 部署：不适用；通信测绘专项按用户明确范围不执行 SSH 部署

## 1. 本轮出口

本轮保持唯一公开 Module Interface：

```text
build_inventory(root, policy) -> SourceInventory
```

没有增加一个由调用者拼装路径的浅 resolver。Inventory v1alpha2 在模块内部将
绝对 symlink 解释为固件 chroot 路径，发布原始 `link_target`、最终
`resolved_path` 与有界 `expansion_status`。调用者不接触宿主机解析细节。

## 2. 安全与覆盖语义

解析器只做词法规范化和逐段 `lstat`：不经 symlink 打开、读取或计算目标内容
摘要。语义边界如下：

| 情况 | 状态 | Coverage |
| --- | --- | --- |
| 固件根内相对链 | `recorded_not_followed` | completed |
| 固件根内绝对链 | `recorded_chroot_absolute_not_followed` | completed |
| 未物化 `/dev/*` | `recorded_runtime_target_not_materialized` | completed |
| 普通目标缺失 | `missing_target` | partial |
| `..` 越过固件根 | `rejected_escape` | partial |
| 链路循环 | `rejected_cycle` | partial |
| 超过 `max_symlink_depth` | `depth_limited` | partial |
| 元数据检查失败 | `target_inspection_failed` | partial |

`/dev/*` 不是任意 dangling link 豁免：它表达由启动/挂载过程提供的设备命名空间，
不属于静态 source artifact。`/missing/tool` 等普通缺失目标仍产生可见诊断。

## 3. TDD 与真实重放

RED → GREEN 用例冻结了：

1. `/dev/null` 在固件根内存在时，绝对链接得到规范目标；
2. 相对链接可跨越固件内绝对链接继续解析；
3. 普通缺失目标、循环与深度预算保持 coverage gap；
4. 源链接和中间目录链接都不能越过固件根，`symlink/..` 必须按组件顺序解析，
   不能提前词法消除 symlink hop；
5. 未物化 `/dev/null` 被记录为运行时设备目标，而非伪造文件；
6. DAP-3520 真实 rootfs 的 118 条链接不再产生错误 escape 诊断。

机器可读结果见
[M1-13 DAP-3520 replay](../samples/m1-13-dap3520-chroot-symlink-replay.json)：

- Inventory：`c5d877e83f97f294a4c01e417d8fb0914e1ecea9f9df7538f2f727bef2dd14f7`；
- 753 observed / 753 processed，16,354,258 bytes；
- 635 files、118 symlinks；
- 103 个一般固件内链接、15 个未物化 `/dev/null` 运行时目标；
- Coverage `completed`，0 diagnostics。

该身份只描述 Producers 实际使用的选定 `squashfs-root`。M1-02B 历史记录的
Binwalk 完整派生目录是另一层 Source Inventory，二者不混用。

## 4. 对代表性 corpus 的影响

DAP-3520 Catalog 现在现场构建 rootfs Inventory，而非硬编码旧 SHA 和旧 coverage：

- Catalog：`discovery-catalog:b0537381a16b6849890027d803727fa1b4e7af24e0edf1e3d57bd54bb751da01`；
- 273 candidates、288 EvidenceAtom、0 open obligations；
- `hnap_soap` 真实固件类别从 `coverage_gap` 晋级 `verified`；
- Corpus Report：`corpus-report:384bf542890d89f47da86402ddb805551ea229c1dd6a81d22bb763a0354e055e`。

整个 M1 gate 仍为 `partial`：共享 CGI 只有 contract fixture，脚本后端缺少绑定
原始固件身份的 Catalog，Native-only 仍是 acquisition gap。

## 5. 反思与下一步

先前把固件 `/...` 当作宿主机绝对路径，安全上保守，却把正常 chroot 语义误报为
逃逸。正确做法不是放宽宿主机跟随，而是把“解析 namespace”和“执行 I/O”分离：
固件路径在虚拟根内解析，目标内容仍不经链接读取。

下一轮继续 M1-11，优先获得共享 CGI、脚本后端原始制品和 Native-only 原始样本。
若出现新的混合 dispatcher、复杂 namespace 或二进制归属链，按研究案例合同追加
到案例库；确定性 Profile 无法关闭 Native 义务时才触发 Ghidra Adapter。

## 6. 验证记录

- Inventory contract 26 项通过，含 DAP-3520 真实 rootfs 重放；
- Python 全量 267/267 通过；Console 9 个测试文件、17/17 通过；TypeScript
  检查与 Vite production build 通过，1800 modules；
- Corpus 脚本输出与记录 JSON 逐字一致；全部样例 JSON 有效；127 个本地文档
  链接、Python compileall 与 `git diff --check` 通过；
- 本地 `/api/health`、前端文档和 `/api/mappings/catalogs` 均返回 200；
- 通信测绘专项不执行 SSH 部署。
