# M1-02：安全、确定性源制品清单

> 工作项：M1-02
> 状态：进行中
> 日期：2026-08-08
> 发布范围：本地回归、样本回放、Git 提交与推送；按用户当前指示不部署 SSH

## 1. 结果

建立 `build_inventory(root, policy) -> SourceInventory` 深 Module Interface，为已解包固件目录发布 `firmatlas.mapping.inventory/v1alpha1` 合同。调用者不需知道路径遍历、ZIP 成员、inode 复用、摘要流式计算或诊断细节。

用户可运行：

```bash
make mapping-inventory ROOT=/path/to/extracted-root
```

查看清单摘要、覆盖、预算消耗、诊断代码和有限样例路径。

## 2. 范围

已完成：

- 按规范 POSIX 路径排序，清单不受 root 位置和 mtime 影响；
- 对普通文件分块计算 SHA-256；
- symlink 只记录不跟随，根外逃逸生成诊断；
- hardlink 保留所有路径，共享 inode 只读取一次；
- FIFO/device/socket 类节点只记录、不打开；
- 以内容而非扩展名识别 ZIP，不落盘解包；
- 递归 ZIP、安全规范成员路径、拒绝穿越和 collision；
- 独立限制文件数、单文件、原始读取、展开体积和归档深度；
- 损坏/不可读成员转换为诊断，不丢失其他结果；
- 版本化 JSON 合同与 CLI 摘要。

本轮不包含：

- 原始固件解密、分区和文件系统解包；
- TAR/cpio/SquashFS/UBI 容器 Adapter；
- MIME、ELF、权限、uid/gid 和组件身份；
- EvidenceSpan、接口发现或 Snapshot 持久化。

## 3. Interface 不变量

1. 根路径必须是已存在目录，预算必须有效；
2. 不执行、不跟随 symlink、不把归档成员写入文件系统；
3. canonical path 唯一且稳定，归档规范化 collision 不重复发布；
4. 任何未处理范围都使 Coverage 为 `partial` 并具有诊断；
5. `observed_count`、`processed_count`、`processed_bytes` 和 `expanded_bytes` 表达不同维度；
6. inventory digest 由规范条目、覆盖和诊断派生，不包含本地绝对根路径或 mtime。

## 4. TDD 与回归证据

本轮沿同一 Interface 执行纵向红—绿循环，已覆盖：

- 位置/mtime 独立的确定性；
- symlink 逃逸；
- ZIP 路径穿越、递归深度、collision 和 CRC 损坏；
- 文件数、文件字节和归档展开预算；
- hardlink 复用和特殊文件不打开；
- 无效根路径/预算、版本化 JSON 和 CLI 观察面。

目标测试当前 17 条；全量回归结果在本轮关闭前回填。review 期间曾捕获 Python 3.9 `SpooledTemporaryFile` 与递归 `zipfile` 的兼容失败，已改为可 seek 临时文件并回归通过。

## 5. 实际样本证据

Tenda AC9 完整说明见 [`M1-02 完整 rootfs 清单`](../samples/tenda-ac9-m1-inventory-walkthrough.md)。

| 指标 | 结果 |
| --- | ---: |
| Inventory SHA-256 | `f425a98b9b7f4143a3b6b979631abe0715e3fc03773a656e1ee4455716ca8b4d` |
| Observed / Processed | 1,038 / 1,038 |
| Processed bytes | 73,075,984 |
| Coverage | `completed` |
| Diagnostics | 0 |

AC9 三个关键制品摘要与 M1-01 人工重放一致。带 `.tar` 后缀但内容不是归档的制品没有被误展开。

## 6. 反思与未决义务

- ZIP 是证明安全归档遍历的第一个 Adapter，不应把它广告为通用固件解包器；
- 归档成员目前通过临时文件限制内存，但后续需增加临时空间预算与 worker 隔离；
- 清单 digest 是源范围身份，不是 Firmware Artifact digest，两者不得混用；
- M1-03 需要设计类型化 EvidenceSpan，并以 inventory entry digest/path 作为唯一来源定位；
- M1-04 之前需决定 file type 识别是 Inventory 字段还是独立 Evidence Producer，不在当前 Interface 中预埋模糊字段。
- 用户已确认可使用 Binwalk 解包；它将作为 M1-02A 隔离 Extraction Worker 的首个生产 Adapter，而不是 `build_inventory` 内部子进程。
- 本机当前 `binwalk` 不存在；不在进度记录中伪造版本或真实原始镜像回放。

## 7. 发布证据

| 门禁 | 结果 |
| --- | --- |
| Inventory contract tests | 17/17 通过 |
| Mapping contract tests | 15/15 通过 |
| 后端全量 | `make test`，92/92 通过 |
| 前端测试 / 生产构建 | Vitest 16/16 通过；TypeScript 检查和 Vite build 通过 |
| 本地 API / 前端烟雾 | 临时 SQLite 下 health 200、FirmAtlas HTML 200、overview 200 |
| Tenda AC9 完整 rootfs replay | 1,038/1,038，digest 与关键条目已记录 |
| Git revision / push | 待回填 |
| SSH deployment | 不适用（用户当前范围） |

## 8. 下一动作

M1-02A：建立 Binwalk Extraction Worker Interface、deterministic fake 和派生制品谱系；随后进入 M1-03 类型化 EvidenceSpan。
