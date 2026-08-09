# M1-23：全固件潜在隐藏接口目录与 UI

> 日期：2026-08-09
> 范围：Hidden Interface Projection、SQLite/API、Mapping Console、Research Case
> 首个正例：TOTOLINK X5000R `V9.1.0u.6118_B20201102`

## 1. 定义与门槛

“潜在隐藏接口”不是路径风格标签，而是严格的静态证据形状：

1. 固件 Source Inventory coverage 为 completed；
2. 声明的 Frontend scope coverage 为 completed；
3. Frontend/Native set-difference coverage 为 completed；
4. operation 存在可回放的 Native registration 与 executable handler binding；
5. 在声明前端及辅助 Native 范围内没有观察到精确引用。

范围 partial、存在前端 scope gap、只命中另一 Native literal、只有 suffix 变体或缺少 handler 的记录均不进入目录。候选始终固定 `runtime_reachability_verified=false`。

## 2. 全固件投影

新增 `build_potential_hidden_interface_index(catalog)` 与 `project_potential_hidden_interface_document(document)`。任何 Discovery Catalog 发布时都会自动建立投影；数据库升级还会回填历史目录。跨固件查询默认只选择每个 Firmware Artifact 最新的目录，防止同一固件的旧 Catalog 重复计数，也防止最新覆盖退化后继续展示旧候选。

每个条目保留：

- Firmware Artifact SHA-256 与 Catalog ID；
- operation token、注册二进制、binding identity 与 handler identity；
- 完成的前端覆盖 scope；
- 原始 EvidenceAtom identity；
- 静态解释、未决原因义务与运行时否定边界。

API：`GET /api/mappings/potential-hidden-interfaces?q=...&firmware=...`，返回分页条目、固件/handler/coverage 指标及固件、处理主体分布。

## 3. X5000R 首个集合

完成范围门槛后，X5000R 精确保留 10 条：

| operation | handler |
| --- | --- |
| `UploadCustomModule` | `www/cgi-bin/cstecgi.cgi@0x0041e518` |
| `UploadFirmwareFile` | `www/cgi-bin/cstecgi.cgi@0x0042c580` |
| `delIpsecNet2NetCfg` | `www/cgi-bin/cstecgi.cgi@0x0041b67c` |
| `getCrpcConfig` | `www/cgi-bin/cstecgi.cgi@0x00411600` |
| `getIpsecHost2NetCfg` | `www/cgi-bin/cstecgi.cgi@0x00401fb0` |
| `getIpsecL2tpXauthCfg` | `www/cgi-bin/cstecgi.cgi@0x00401dac` |
| `getIpsecNet2NetCfg` | `www/cgi-bin/cstecgi.cgi@0x00403a68` |
| `setIpsecHost2NetCfg` | `www/cgi-bin/cstecgi.cgi@0x00419e8c` |
| `setIpsecL2tpXauthCfg` | `www/cgi-bin/cstecgi.cgi@0x00419bcc` |
| `setIpsecNet2NetCfg` | `www/cgi-bin/cstecgi.cgi@0x0041c3dc` |

以上地址由机器报告锁定；若后续回放发现表项变化，应更新报告，不能手工维持表格。

## 4. 系统展示

通信测绘页新增“目录浏览 / 潜在隐藏接口”切换。新视图提供：

- 潜在接口数、覆盖合格固件数、唯一 handler 数与覆盖缺口固件数；
- 跨固件信号分布与处理二进制分布；
- operation、handler、二进制联合搜索；
- 注册主体、handler、前端覆盖范围、未决原因与证据 identity 下钻；
- 固定的“不是后门结论”解释边界。

页面沿用稳定三栏调查结构，在宽屏展示分布 → 候选 → 证据，在窄屏自然纵向堆叠，不使用遮挡式抽屉。

## 5. 论文用途与限制

该集合可用于研究不同固件/版本中“Native 注册但客户端未观察”的比例、处理二进制聚类、版本消失/出现、前端覆盖消融以及后续动态验证命中率。它比单纯 strings 扫描更严格，因为每条记录同时具备注册和 handler proof，也比“未在页面搜到”更保守，因为必须先通过覆盖门槛。

仍不能据此区分隐藏客户端、直连 API、废弃代码、版本漂移或运行时注册，更不能直接声称 undocumented feature、后门、认证缺失、漏洞或可利用性。

## 6. 中间产物

- [X5000R 潜在隐藏接口报告](../samples/m1-23-x5000r-potential-hidden-interfaces.json)；
- [研究案例 Corpus](../samples/m1-12-research-case-corpus.json)。

```bash
PYTHONPATH=src python3 scripts/build_x5000r_hidden_interface_report.py
```

## 7. 验证记录

- 后端全量回归：`337` 项测试通过；
- 前端全量回归：`18` 项测试通过，生产构建成功；
- Python 编译检查与 `git diff --check` 通过；
- 真实 X5000R Catalog 发布后，API 与 UI 均显示 `10` 条、`1` 个合格固件、`10` 个唯一 handler、`0` 个覆盖缺口；
- 搜索 `Ipsec Host` 只返回 `getIpsecHost2NetCfg` 与 `setIpsecHost2NetCfg`，operation、部分关键词和 handler/制品搜索均由服务端过滤；
- 详情面板重放 `UploadFirmwareFile → www/cgi-bin/cstecgi.cgi@0x0042c580`，并显示覆盖 scope、证据 identity 和运行时原因义务；
- 浏览器控制台无错误，三列布局在真实生产构建中无重叠；
- 报告 SHA-256：`0a0cb187066c05c0c05af103b89037dfc5f825b063115979e9998c739cd130b2`；研究案例 Corpus SHA-256：`0df82fbdc26563b569778101bbe6f9160e04ff34bad62077ebaf1780c093def1`。

通信测绘研究范围按用户约定不执行 SSH 部署，记为 N/A。
