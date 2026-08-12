# R2-24：AC9 配置镜像 IPC 与整域状态写入

## 本轮问题与结论

R2-23 已把 `POST /cgi-bin/UploadCfg` 沿 `httpd → libtpi → cfm Upload` 自动连接到
`libCfm:UploadValue → SendMsg/RecvMsg`，但仍把“上传 blob parser / 状态写入”保留为义务。
本轮从真实 Tenda AC9 继续深化，结论不是逐 key parser，而是一条跨进程的配置镜像恢复链：

```text
UploadValue@libCfm:0x429c
  opcode = 14
  message size = 2016 bytes
  payload offset = 516
  payload literal = "0"
  → SendMsg / RecvMsg
  → cfmd dispatcher@0xa504
  → atoi(payload+516)
  → RestoreMTD(0)
  → response opcode = 15
  → configuration_partition[0] (whole_configuration_image)
```

这关闭 `configuration-blob-wildcard-state-write`，但不关闭逐配置键 parser。`payload+516` 是
内部 framed IPC 字段，不是 HTTP 参数；`security.ddos.map` 等历史配置键也不能反向提升为
`UploadCfg` 表单字段。

## 工具固化

- 新增深模块 `discover_arm_configuration_blob_flows(...)`，输入上传 rootfs 中受预算约束的
  ARM ELF 候选，验证 client 动态导出、PIC literal、frame、opcode、daemon PLT import 与
  writer 邻接关系；来源摘要或结构不一致时 fail closed。
- 每条结果保存 7 个可重放 EvidenceAtom：client export、request framing、partition literal、
  message size、daemon dispatch、decoder call、state writer call。
- 默认 Profile/Registry 冻结为 `auto-v16/builtin-v16`，保留 `auto-v15` 历史别名；上传任意
  rootfs 时只对含 `UploadValue` 或 `RestoreMTD` 动态符号的 ARM ELF 选择该 producer。
- Catalog 新增 `native_configuration_blob_flow`，图谱新增 `state` 节点及 `writes_state` 边；
  参数表保持不变，避免污染用户所见接口参数。
- Console 的“参数与状态” preset 纳入 `state/writes_state`，并为状态节点增加独立颜色与层级。

机器可读中间结果：
[r2-24-vendor-tenda-ac9-configuration-blob-flow.json](../samples/r2-24-vendor-tenda-ac9-configuration-blob-flow.json)。

## TDD 与回归记录

实现顺序：

1. 先写真实 AC9 公共 Interface 合同测试，初次因模块未实现产生 ImportError（红）。
2. 最小实现后首次运行暴露 `_Elf32Arm` 没有 section API；改为受信 executable PT_LOAD
   segment 遍历，3/3 合同测试转绿。
3. 接入 Catalog/Graph 后验证结果有 `writes_state`，同时断言 `catalog.parameters == ()`。
4. 接入 `auto-v16` 后，临时 rootfs 的 Profile/Registry 与阶段集合回归通过；真实 AC9
   纵向测试 144.886 秒通过，既有路由、CGI dispatch、cross-ELF chain 和新状态流同时成立。
5. Console mapping tests 23/23、TypeScript check 和生产构建通过。最初 shell 缺 Node，改用
   Codex 固定 workspace runtime 后重跑；这不是测试失败，未跳过。
6. 页面首轮验收发现稀疏语义 rank 会把 `state` 节点绘制到当前画布可视区之外；先加入红测
   （期望相邻语义列间距 200，实际 800），再把固定 rank 坐标改为只压缩当前子图已出现的
   rank。复验后 IPC 关系节点、状态节点和箭头可在同一视口同时观察。
7. 最终 Python 全量回归为 507/507；研究案例语料 `paper_ready=true`，并加入第 9 阶段，
   分别记录已关闭的整镜像写入义务和仍开放的逐 key parser 义务。

## 服务、API 与页面交互验收

- 本轮服务使用真实 AC9 rootfs 重新执行 `auto-v16/builtin-v16`，发布 4,932 个 Catalog
  候选及 6,080 节点/8,263 关系的通信图；`GET /api/health` 返回 `status=ok`。
- 状态索引搜索 `configuration_partition[0]` 精确返回 1 个 `state`；使用页面同一
  `focus_node` 查询与 `parameter_state` preset 精确返回 2 nodes / 1 edge / 7 evidence atoms，
  无不相关 association 噪声，查询状态为 `completed`。
- 通过真实 Console 依次点击“通信测绘 → 架构图谱”，输入状态范围，点击“聚焦状态”，再点击
  `UploadValue:opcode=14->configuration_partition[0]`。页面可见两端节点、`writes_state`
  箭头、`whole_configuration_image`、opcode/offset/size、`atoi`、`RestoreMTD` 与全部证据定位。
- 修正稀疏列布局后重新加载生产构建并重复上述交互；浏览器 Console 的 warning/error 数为 0。
- 本轮限定为 firmware mapping 研究与其图谱展示，按仓库 research exception 不执行 SSH
  部署；本地验收后提交并推送。

Git 检查点：`2de178c685b0b568fc32ce248a98f7e75707612e`（首次提交；随后仅补充本轮交接
元数据并 amend，最终 revision 见该轮 Git 历史）。

## 反思、反事实与边界

- 最重要的修正是模块边界：`UploadValue` 是 IPC client，不是 parser；真实 dispatcher owner
  在 `cfmd`。如果只追同一 ELF 调用图，会把进程边界和状态 writer 都遗漏。
- `atoi → RestoreMTD` 只证明常量分区选择器 `0` 和整镜像状态范围；没有 key/value 循环、
  配置语法或 setter provenance，不能声称历史键已被配置入口发现。
- producer 采用受限 profile（export `UploadValue`、`atoi`、`RestoreMTD`）来保证本轮准确性；
  后续应从新样本扩展成多个 versioned profiles，不能用单厂商模式冒充通用语义。
- 静态链不证明服务启动、请求发送、恢复成功、认证边界或漏洞存在/可利用。

## 下一轮

继续 AC9，进入 `RestoreMTD` 的唯一 export 实现及其调用的解压、持久文件/MTD writer，判断是否
存在可验证的逐 key parser。若只恢复压缩镜像复制，则继续保持整域状态；只有观察到 key parser
和 setter provenance，才创建历史配置键到状态的细粒度映射。
