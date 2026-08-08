# M1-08：无 seed 候选目录

> 工作项：M1-08  
> 状态：已验证  
> 日期：2026-08-09  
> 发布范围：本地实现、真实样本回放、GitHub；按用户当前测绘范围不部署 SSH

## 1. Interface

```text
assemble_discovery_catalog(DiscoveryCatalogInput) -> DiscoveryCatalog
```

一个 Interface 隐藏 Producer Batch 投影、证据去重、参数归属、association 引用校验、coverage 聚合、scheduler 固定点和稳定 catalog identity。目录没有 seed、PoC、CVE 文本或流量必需参数，输出固定记录 `seed_input_count=0`。

候选类型保持能力隔离：Frontend request、Web configuration、Script source/route/state、Native hint 和 Candidate Association 不按相同字符串自动合并。每个候选和参数必须引用目录中存在的 EvidenceAtom；关联和义务目标必须引用目录中存在的候选。

## 2. 样本驱动修正

AC9 `simple_upgrade.asp` 暴露了 M1-04 的一个上游缺口：HTML Form 只扫描 `.htm/.html/.xhtml`，且所有表示都写成 `form_urlencoded`。本轮先补回 Frontend Producer：支持 `.asp/.php` 模板中的 HTML Form，并保留 `enctype=multipart/form-data` 为 `multipart_form`，再进行目录组装。

这使 AC9 真实候选从原先两份 JS 的 7 个增加为 8 个：

```text
POST /cgi-bin/upgrade
Content-Type: multipart/form-data
parameter: upgradeFile
```

Native `bin/httpd` 中存在 `/cgi-bin/upgrade` endpoint literal，因此产生第 8 个 exact-endpoint association，而不是靠文件名推断。

## 3. AC9 无 seed 中间结果

机器可读摘要见 [M1-08 AC9 Catalog JSON](../samples/m1-08-ac9-discovery-catalog-summary.json)。

| 项目 | 数量 |
| --- | ---: |
| Request Interface | 8 |
| Web Configuration | 8 |
| Native Hint | 371 |
| Candidate Association | 8 |
| Parameters | 6 |
| EvidenceAtom | 398 |
| Open obligations | 16 |

恢复出的配置链仍是 `:8180 → /cgi-bin/luci/ → 127.0.0.1:8188 → /usr/bin/app_data_center`；新增上传接口关联到 `bin/httpd`。这些是并列的可解释候选和关联，不声明 nginx FastCGI 链就是 `/cgi-bin/upgrade` 的实际处理路径。

## 4. 验证与发布证据

11 条 Discovery Catalog Interface 测试覆盖 Frontend、Web Configuration、Script Backend、Native、Correlation、Scheduler、缺失 required batch、partial coverage、输入顺序、目录身份、文档摘要和 AC9 真实端到端回放。

| 门禁 | 结果 |
| --- | --- |
| Discovery Catalog contract | 11/11 通过 |
| Frontend Producer contract | 14/14 通过 |
| Mapping 组合回归 | 128/128 通过 |
| 后端全量 | `make test`，188/188 通过 |
| 前端测试与构建 | Vitest 16/16、TypeScript 与 Vite build 通过 |
| JSON / Python validation | `json.tool`、`py_compile`、`git diff --check` 通过 |
| 本地 API/UI smoke | 临时 SQLite 下 health、overview、构建首页均 HTTP 200 |
| SSH deployment | 不适用（用户当前测绘范围） |

## 5. 下一动作

进入 M1-09：为 Discovery Catalog 增加持久化 Adapter、查询 Interface 和最小 UI 纵向视图，使分析员可以按候选类型、接口、参数、coverage 和开放义务下钻。M1-09 不改变目录事实，只建立可重建查询投影。
