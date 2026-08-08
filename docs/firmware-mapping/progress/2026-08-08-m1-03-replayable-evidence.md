# M1-03：不可变、可回放 EvidenceAtom

> 工作项：M1-03  
> 状态：已验证  
> 日期：2026-08-08  
> 发布范围：本地回归、真实样本回放、Git 提交与推送；按用户当前指示不部署 SSH

## 1. 结果

建立深 Module Interface：

```text
capture_evidence(source_entry, source_bytes, selection, claim, producer)
  -> EvidenceAtom

replay_evidence(evidence_atom, source_entry, source_bytes)
  -> verified excerpt bytes
```

调用者只声明 SourceInventory 条目、选区和最小主张；Implementation 统一处理内容身份、类型化定位、行列换算、选区摘要、版本化序列化和稳定 Evidence ID。后续前端、配置、脚本与 Native Producer 不应各自创建自由格式 locator。

## 2. 合同与不变量

- EvidenceAtom schema：`firmatlas.mapping.evidence/v1alpha1`；
- text span 使用 UTF-8、半开字节区间与 1-based 行列；binary span 不保存伪造行列；
- SourceArtifactEntry 必须是 `file`、`hardlink`、`archive` 或 `archive_member`，且大小与 SHA-256 匹配；
- 空选区、越界选区和切断 UTF-8 codepoint 的位置被拒绝；
- `direct_static` 文本 object 必须出现在精确选区中；
- Evidence ID 包含 schema、Span、claim 与 Producer，且不依赖本地 root 或 mtime；
- replay 重新验证路径、源摘要、选区、行列、locator 与 excerpt SHA-256；
- 老 Snapshot 的自由 locator 可向后读取，但不能声称通过新回放合同。

## 3. TDD 记录

沿公开 Interface 完成 8 条测试：

1. 文本选区生成完整类型化 Span、固定 Evidence ID 与 schema 往返；
2. symlink 等非内容节点不能发布证据；
3. `direct_static` 不能声明选区中不存在的值；
4. 二进制选区只记录字节定位；
5. 内容摘要必须与 Inventory 一致；
6. 文本区间不能切断 UTF-8 codepoint；
7. replay 只返回全部定位信息验证后的选区，内容变化立即失败；
8. 文档中的 Tenda AC9 EvidenceAtom 持续兼容合同。

红阶段实际发现并修复：任意 symlink 可伪造内容、直接观察可声明不存在的 object、EvidenceAtom 没有独立 schema 往返、持久化 Atom 没有统一 replay 入口。

## 4. Tenda AC9 实际样本

输入来自 M1-02 已完整清点的 `webroot_ro/js/static_route.js`：

| 属性 | 值 |
| --- | --- |
| Source size | 11,206 bytes |
| Source SHA-256 | `9bd1ff64ac59189812d29fefe565984c7f58ac68358003e15a1e3fa71a15482b` |
| Parent Inventory | `f425a98b9b7f4143a3b6b979631abe0715e3fc03773a656e1ee4455716ca8b4d` |

中间输出见 [AC9 EvidenceAtom JSON](../samples/tenda-ac9-m1-evidence-atoms.json)：

| object | 字节 | 行列 | excerpt SHA-256 | 解释 |
| --- | --- | --- | --- | --- |
| `goform/GetStaticRouteCfg` | 431–455 | 18:14–18:38 | `54a768…a741` | 前端读取配置请求构造证据 |
| `goform/SetStaticRouteCfg` | 472–496 | 19:14–19:38 | `47463e…1347` | 前端写配置请求构造证据 |

两条 Atom 已对完整源文件执行 replay，结果 `2/2`。它们可以支撑 `constructs_request`，但仍不能单独支撑后端 `binds_handler`；后者继续作为 Native/配置分析义务。

## 5. 回归与发布证据

| 门禁 | 结果 |
| --- | --- |
| Evidence capture/replay | 8/8 通过 |
| Mapping extraction/inventory/evidence/snapshot | 48/48 通过 |
| 后端全量 | `make test`，108/108 通过 |
| 前端测试 | Vitest 16/16 通过 |
| TypeScript / 生产构建 | 检查通过；Vite build 通过 |
| 本地 API / 前端烟雾 | 临时 SQLite 下 health 200、overview 200、FirmAtlas HTML 200 |
| AC9 完整源 replay | 2/2 Atom 通过 |
| 实现修订 | `9455f4f` |
| SSH deployment | 不适用（用户当前测绘范围） |

## 6. 反思与微调

- 最初只有 Snapshot 内自由字符串 locator，无法证明相同输入能重放；现已保留向后读取但禁止新 Producer 继续制造该格式；
- Capture 接收完整 bytes，适合 Inventory 预算内的 M1 Producer；Native 超大文件后续可能需要 seekable reader Adapter，但不能改变 EvidenceAtom identity；
- `direct_static` 的 object-in-span 约束避免把规则归一化误标为直接观察；归一化结果必须发布为 `deterministic_derived` 并在后续加入 derivation chain；
- M1-04 需要区分字符串提及、请求构造、方法/representation 与参数读取，不能因为 URL 字符串存在就统一发 `constructs_request`；
- 当前 Evidence ID 包含 Producer 版本，同一来源被新规则重新解释会产生新 Atom，符合不可变发布原则；
- 结构化文档 node path、符号/地址和 runtime event span 尚未实现，分别在配置、Native 与动态里程碑按真实 Adapter 需求扩展，避免现在建立假 Seam。

## 7. 下一动作

M1-04：建立 `discover_frontend_requests(source_entry, bytes, policy) -> ProducerResult`，先以 AC9 `R.pageModel` 的 `getUrl/setUrl` 和参数构造为纵向切片；随后加入共享 CGI selector 与 HNAP/SOAP 代表样本，所有输出必须通过 M1-03 capture Interface 发布。
