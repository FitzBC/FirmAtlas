# M1-10A：Native Deep 命名路由表 Adapter

> 工作项：M1-10A
> 日期：2026-08-09
> 状态：已验证

## 1. 目标与拆分理由

M1-06C 在 Tenda AC9 上产生了 `registers_route` 与 `binds_handler` 义务，但字符串和符号共现不能关闭它们。M1-10 按真实证据形态拆成多个 Adapter：

- M1-10A：命名静态 `{route_ptr, handler_ptr}` 注册表；
- M1-10B：PIC/调用点/反编译 Worker 输出验证；
- 后续 Adapter：dispatcher、getter 与 source-to-sink。

本轮实现第一个可运行 Adapter，不宣称覆盖所有 Native Web Server。

## 2. 公开 Interface

```text
discover_native_route_bindings(source, bytes, anchors, profile, policy)
  -> NativeDeepResult

native_deep_scheduler_analyzer(result)
  -> SchedulerAnalyzer("native-deep")
```

`NativeRouteTableProfile` 将 section allowlist、entry pointer slot 数、route slot 和 handler slot 纳入版本化分析身份。默认 Profile 只读取 `.routes`、`.route_table`、`.webs_routes`，不扫描普通 `.data` 猜测结构。

## 3. 晋级规则

一条 binding 必须同时满足：

1. 源字节与 Inventory 大小、SHA-256 一致；
2. route token 位于 `SHF_ALLOC` 且非 executable 的 ELF section；
3. 受信表项的 route slot 精确指向该 token；
4. 同一表项的 handler slot 指向 `SHF_ALLOC | SHF_EXECINSTR` section；
5. 三段 EvidenceAtom 均可从原制品重放。

三段证据分别是 `mentions_endpoint` 的字符串 span、`registers_route` 的表项 span、`binds_handler` 的表项 span。Scheduler Adapter 只按 `target_ref + required_capability` 精确关闭义务，不接受 route 名或 handler 名模糊匹配。

## 4. 样本与中间输出

机器可读摘要见 [M1-10 Native Deep 样例](../samples/m1-10-native-deep-route-table-summary.json)。

### 4.1 合成 ARM ELF 正例

332-byte ELF32 fixture 包含：

- `.text @ 0x1000`：可执行 handler；
- `.rodata @ 0x2000`：`SetOnlineDevName`；
- `.routes @ 0x3000`：`[0x2000, 0x1000]`。

Adapter 发布一个 supported route binding、一个 supported handler，并把两个 Scheduler 义务全部关闭。Catalog 查询原 candidate association 时可反向得到这两个深绑定事实。

### 4.2 Tenda AC9 真实负面对照

AC9 `bin/httpd`（SHA-256 `2fd5c92e…702b`）包含 route token 与 exported handler symbols，但没有默认 Profile 允许的命名路由表 section。结果是：coverage completed、0 binding、0 deep EvidenceAtom。

这不是失败：它证明 Adapter 没有把 `.rodata` 字符串与 `.dynsym` 名称拼成虚假 binding。AC9 需要 M1-10B 的 ARM PIC call-site/decompiler Adapter。

## 5. 目录与 UI

Discovery Catalog 新增 `native_deep` Producer Batch，以及 `native_route_binding`、`native_handler` 两种 supported candidate。SQLite 查询投影通过 candidate 的 `target_ref` 建立可重建反向关系；候选详情新增 `related_candidates`，Console 提供 Native 绑定/Handler 过滤和“已验证 Native 绑定”区域。

## 6. 当前验证

| 门禁 | 结果 |
| --- | --- |
| Python 全量回归 | 205/205 通过 |
| Native Deep 合同与纵向切片 | 10/10 通过 |
| 前端组件回归 | 17/17 通过（9 个测试文件） |
| TypeScript | app/node 两套 `tsc --noEmit` 通过 |
| 前端生产构建 | Vite 通过，1800 modules transformed |
| 合成纵向目录 | 5 candidates、1 association、0 open obligations |
| 本地浏览器 | Native Binding/Handler 下钻正常，console 0 error |
| JSON / Python 编译 / diff | 通过 |
| SSH 部署 | 不适用：通信测绘功能按用户明确范围不执行 SSH 部署 |

提交前双轴审查额外补强了三项边界：route literal 使用独立 EvidenceAtom；Scheduler 接收结果前重新校验完整三段证明；64-bit handler identity 使用指针宽度格式化。实现 revision 在提交后追加，历史记录不回写成预知 revision。

## 7. 下一步

M1-10B 建立隔离 Native Deep Worker 输出合同，并实现 ARM PIC call-site Adapter。AC9 的目标不是按 `formSetDeviceName` 名称猜测，而是定位注册调用点，证明 route 参数与 handler 函数引用进入同一次注册调用；外部反编译工具输出仍须转换为本项目 EvidenceAtom 后才能关闭义务。
