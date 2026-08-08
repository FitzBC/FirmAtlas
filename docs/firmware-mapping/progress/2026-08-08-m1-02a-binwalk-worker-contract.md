# M1-02A：Binwalk 隔离 worker 合同与派生制品谱系

> 工作项：M1-02A  
> 状态：已验证  
> 日期：2026-08-08  
> 发布范围：本地回归、合同样例、Git 提交与推送；按用户当前指示不部署 SSH

## 1. 结果

建立 `FirmwareExtractor.extract(request) -> ExtractionResult` 的首个实现 `BinwalkExtractor`。调用进程不直接执行 Binwalk，而是把已校验的父制品、空输出目录和预算交给 `ExtractionWorker`。worker 返回工具身份、实际命令、退出状态和已强制资源限制；编排层再对输出执行安全 Inventory，并形成：

```text
父固件 SHA-256
→ Binwalk 工具版本与命令证据
→ execution fingerprint
→ 派生文件 SourceInventory
```

版本化 JSON 合同为 `firmatlas.mapping.extraction/v1alpha1`。可复现的中间输出见 [Binwalk worker 合同样例](../samples/binwalk-worker-contract-summary.json)。

## 2. 已冻结的边界

- 输入制品必须存在，且实际 SHA-256 与请求一致；
- 输出目录必须不存在或为空，防止把旧文件误归因于本次抽取；
- worker 必须报告 Binwalk 名称和非空版本；
- worker 必须证明实际入口是 `binwalk -Me`，不接受 shell 包装命令；
- worker 必须证明 wall time、输出文件数、输出字节和禁网四项约束；
- stdout/stderr 不进入序列化结果，只保存摘要；
- 超时或非零退出时保留可安全清点的部分输出，并明确区分 `failed` 与 `partial_success`；
- worker probe/execute 崩溃转换为结构化诊断；
- 派生输出若存在符号链接逃逸或 Inventory 缺口，成功会降级为 `partial_success`。

## 3. TDD 证据

8 条 Interface 测试覆盖：

1. 成功谱系与版本化序列化；
2. 超时保留部分派生制品；
3. Binwalk 不可用的结构化失败；
4. 拒绝非规范命令证明；
5. 拒绝缺失隔离/资源限制证明；
6. containment worker 崩溃；
7. 摘要不匹配时不调用 worker、不创建输出目录；
8. 不安全派生输出把完整成功降级为部分成功。

TDD 红阶段实际捕获了两项缺口：任意 worker 命令会被接受，以及 worker `RuntimeError` 会穿透调用边界；对应实现加入后目标测试 8/8 通过。

## 4. 中间输出解释

合同样例使用内容为 `firmware-image` 的确定性父制品，以及 fake worker 生成的 `extractions/squashfs-root/www/index.js`。样例中的三个摘要分别表示：

| 摘要 | 含义 |
| --- | --- |
| `ec4d…2036` | 父固件内容身份 |
| `6ae0…751d` | 父摘要、工具、命令、退出状态、日志摘要和限制证明组成的执行身份 |
| `505f…094f` | 派生目录的规范 Inventory 身份 |

这三个身份不能互换。后续 EvidenceAtom 只能引用派生 Inventory 条目，同时通过 ExtractionResult 回溯父固件。

## 5. 回归与发布证据

| 门禁 | 结果 |
| --- | --- |
| Extraction contract tests | 8/8 通过 |
| Mapping extraction/inventory/snapshot | 40/40 通过 |
| 后端全量 | `make test`，100/100 通过 |
| 前端测试 | Vitest 16/16 通过 |
| TypeScript / 生产构建 | 检查通过；Vite build 通过 |
| 本地 API / 前端烟雾 | 临时 SQLite 下 health 200、overview 200、FirmAtlas HTML 200 |
| 本机 Binwalk probe | 不可用，`command -v binwalk` 无结果 |
| 真实原始镜像回放 | 未执行，不宣称通过 |
| 实现修订 | `df17aaf` |
| SSH deployment | 不适用（用户当前测绘范围） |

## 6. 反思与微调

- 最初把“Binwalk Adapter”和“真实镜像验证”放在同一工作项会造成假完成，因此拆成 M1-02A 合同和 M1-02B 生产 worker；
- Inventory 的预算只能在抽取后识别缺口，不能替代 worker 对抽取过程的强制限制；
- worker 的 `enforced_limits` 当前是合同证明，M1-02B 必须用容器配置与运行记录使它成为可审计事实；
- Binwalk 依赖外部 extractor，生产镜像必须固定 Binwalk、extractor 与容器镜像身份；
- 当前仅捕获 `OSError`/`RuntimeError`，编程错误仍应失败冒泡，不能被包装成普通固件失败；
- 日志目前由 worker 返回内存字符串，M1-02B 需增加日志字节上限与截断标记。

## 7. 下一动作

M1-02B：实现禁网、只读输入、受限输出的生产 Binwalk worker，固定工具链并选择合法的代表性原始固件镜像进行真实回放。若当前环境仍无法提供 Binwalk，则不阻塞 M1-03 EvidenceAtom 合同，但 M1-02B 保持“未开始/受阻”，不能静默跳过。
