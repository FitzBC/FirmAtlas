# R2-08 — Tenda AC9 DLNA 参数线索索引

## 本轮结论

本轮没有把字符串共现包装成数据流结论，而是增加了公共接口 `trace_frontend_parameter_clues(frontend_graph, artifacts, policy)`：它对前端已经验证的请求参数建立逐参数、预算受控、证据可重放的同固件线索索引。每个参数必须明确落入 `external_clue_observed`、`no_external_clue` 或 `coverage_limited`，因此“没找到”不再被静默省略。

| 接口 | 参数 | 非 webroot 精确线索 | 当前解释 |
|---|---|---:|---|
| `goform/SetDlnaCfg` | `deviceName` | `bin/httpd` 4 处 | 弱候选线索；名称通用，不能单凭共现证明处理器或状态绑定 |
| `goform/SetDlnaCfg` | `dlnaEn` | 0 | 完整扫描下的外部线索阴性结果 |
| `goform/SetDlnaCfg` | `scanList` | 0 | 完整扫描下的外部线索阴性结果 |

扫描覆盖 451 个非 webroot 常规制品、69,144,996 字节，未触发预算限制。机器可读结果见 [r2-08-vendor-tenda-ac9-parameter-clues.json](../samples/r2-08-vendor-tenda-ac9-parameter-clues.json)。

## 阶段时间线与中间输出

1. 前端事实：`dlna.js` 已恢复 `GetDlnaCfg`、`SetDlnaCfg`、`refreshDLNA` 三个请求；`SetDlnaCfg` 的 `dlnaEn/deviceName/scanList` 已恢复。
2. 交叉制品清点：`dlnaEn` 只存在于页面、脚本与模拟响应；`scanList` 只存在于脚本与模拟响应；`folderGrade/filePath` 只存在于脚本；`minidlna` 出现在 `httpd` 与 `time_check`。
3. RED：新契约测试因公共类型/函数不存在而失败。
4. GREEN：加入精确标识符边界、逐参数阴性结果、制品/字节/参数/命中预算与原子证据。
5. AC9 重放：仅 `deviceName` 在 `bin/httpd` 有 4 个精确 token 命中；另外两个参数为显式阴性。

## 新发现的漏检与原因

- `goform/expandDlnaFile` 及 `folderGrade/filePath` 未恢复，因为调用经过项目自定义的 `$.GetSetData.setData` 包装器。
- `/goform/refreshDLNA` 请求已恢复，但 form-urlencoded 字符串中的 `action=1` 未成为参数，因为当前 `jQuery.post` 没有解析此载荷形式。

两个缺口已固化在 JSON 的 `known_parser_gaps`，不是事后从成功结果中抹去。下一轮应先扩展前端语法覆盖，再让参数线索索引自动吸收新增参数。

## 反事实失败模式与边界

- 普通子串搜索会误报 `prefixdeviceNameSuffix`；契约测试证明它被边界规则排除。
- 只返回命中列表会让 `dlnaEn/scanList` 无声消失；逐参数 assessment 保留完整分母。
- 把 `deviceName` 共现直接提升成绑定会错误暗示四个字符串位置属于 DLNA 处理路径。本轮仅标记 `external_parameter_token`，置信度 0.55。
- 静态字符串阴性不等于运行时不存在：参数可能被索引访问、压缩、加密、动态拼接或通过 IPC 转换。

## 验证与交接

```bash
PYTHONPATH=src python scripts/build_vendor_tenda_ac9_parameter_clue_report.py \
  ../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root \
  docs/firmware-mapping/samples/r2-08-vendor-tenda-ac9-parameter-clues.json
```

下一会话从两项 RED 测试开始：自定义 `GetSetData.setData` 包装器和 jQuery form-urlencoded 字符串参数；完成后再把参数线索结果投影进统一 `AnalyzeRun/Catalog`。本轮仅涉及 mapping 研究范围，SSH 部署不适用。

验证记录：新增契约测试 2/2 通过；335 项 mapping 全量回归首次运行有 1 项既有容器预算时序测试瞬时失败，单项复跑 1/1 通过；报告连续重建摘要均为 `5468b164104ebe65c244e50a5fff2d65e6fb90e4b9c584a51cb57377bf50ad4d`；`git diff --check` 通过。
