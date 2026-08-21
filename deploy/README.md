# satc_cloud 部署

每项功能或修复完成后，都必须将同一 Git 修订部署到 SSH 主机
`satc_cloud` 并验证。仓库级约束见 `AGENTS.md`。

> [!NOTE]
> 范围仅限 `firmatlas.mapping`、测绘脚本/测试和 `docs/firmware-mapping` 的固件通信测绘研究轮次适用仓库中的部署例外：完成本地全量测试、生产构建、真实 API/页面验收、提交和 GitHub 推送，但不部署到 `satc_cloud`。不得把这一例外扩展到普通 FirmAtlas 产品功能或缺陷修复。每轮记录必须明确写明“不适用”及依据。

## 布局

- 应用根目录：`/home/fitz/apps/firmatlas`
- 不可变发布：`releases/<git-sha>`
- 当前发布：`current` 符号链接
- 持久数据：`shared/var/firmatlas.db`
- 服务：用户级 systemd 单元 `firmatlas.service`
- HTTP：`0.0.0.0:18080`，同一进程提供控制台和 `/api`

远端用户已启用 systemd linger，因此 SSH 会话断开后服务仍会持续运行；部署脚本会
检查这一前置条件。

`/home/fitz/iot_firmwareassociation` 是其他项目，部署流程不得修改它。

## 常规发布

从干净工作树执行：

```bash
make deploy
```

脚本会重新运行后端测试、前端测试和生产构建，再同步当前提交、原子切换
`current`、重启服务，并检查远端提交、健康接口和前端文档。远端数据库在发布间
保持不变，由应用启动时执行兼容迁移。

首次部署或明确需要用本地数据替换远端数据时：

```bash
make deploy-with-data
```

该命令通过 SQLite `.backup` 创建一致性快照。若远端已有数据库，会先保留为
`firmatlas.db.previous`，因此可以恢复。不要把它作为日常发布命令使用。

可以通过 `FIRMATLAS_DEPLOY_HOST` 和 `FIRMATLAS_REMOTE_ROOT` 覆盖默认主机与路径。

## 验证与恢复

常用只读检查：

```bash
ssh satc_cloud 'systemctl --user --no-pager status firmatlas.service'
ssh satc_cloud 'curl -fsS http://127.0.0.1:18080/api/health'
ssh satc_cloud 'readlink /home/fitz/apps/firmatlas/current'
```

发布后还应调用至少一个覆盖本次改动的 API。若需回滚代码，将 `current` 指向上一个
完整发布目录并重启服务；若需回滚数据，在服务停止后把
`firmatlas.db.previous` 恢复为 `firmatlas.db`。

## 通信测绘本地产品服务

通信测绘研究轮次需要在最终代码和生产 Console 构建上启动真实本地服务，而不能只检查测试或 SQLite。完整 Console 必须连接 `var/firmatlas.db`；禁止把 `var/mapping-work/<round>/firmatlas.db` 作为完整产品服务数据库，因为后者可以只有测绘数据而没有漏洞情报和固件资产。单轮结果应通过 `mapping publish-*` 命令追加到主库。先运行后端全量测试、Console 测试/类型检查/生产构建，再以固定摘要的 Binwalk 3.1.0 镜像启动：

```bash
PYTHONPATH=src python3 -m firmatlas intelligence serve \
  --database var/firmatlas.db \
  --host 127.0.0.1 --port 18789 \
  --static-dir apps/console/dist \
  --mapping-workspace var/mapping-jobs \
  --mapping-runtime /usr/local/bin/docker \
  --mapping-binwalk-image-ref 'sha256:<pinned-image-id>' \
  --mapping-binwalk-version 3.1.0 \
  --mapping-upload-max-bytes 67108864 \
  --mapping-analysis-max-seconds 900
```

验收至少包括：

```bash
curl -fsS http://127.0.0.1:18789/api/health
curl -fsS http://127.0.0.1:18789/api/mappings/catalogs
curl -fsS http://127.0.0.1:18789/api/mappings/graphs
curl -fsS http://127.0.0.1:18789/api/mappings/corpus-report
curl -fsS http://127.0.0.1:18789/api/mappings/jobs
curl -fsS 'http://127.0.0.1:18789/api/mappings/catalogs/<catalog-id>/interface-force-graph'
```

随后从 Console 实际完成：固件身份与切换器检查、固件 → 真实二进制 → Web 接口 → 参数逐层
展开与折叠（主体和箭头均需验证）、节点拖拽不误展开、展开后根/组件仍在首屏、无子参数接口不显示
伪展开箭头、固件默认居中、子节点围绕实际展开父节点而非全局对称、四类对象视觉区分、空白画布平移、缩放/回到中心、节点拖拽
回弹、矩形零重叠检查、悬停邻接高亮、滚轮缩放、分支搜索、自动布局重置、
参数约束/依赖/EvidenceAtom 侧栏、原始证据查询、高级图谱、
覆盖空态和上传表单。上传验收必须确认厂商、产品、设备型号、固件版本随作业持久化并出现在发布后
的 release context；默认接口力导图不得展示前端静态资源组件，也不得把 `ubus://`/IPC 当作 Web URL。服务参数、当前功能、
解释边界和截图见[固件通信测绘产品功能与验收手册](../docs/firmware-mapping/product-guide.md)。

`/api/health` 只能证明进程存活，不能证明数据集选择正确。服务恢复还必须检查：

- `/api/intelligence/overview` 的 `counts.relevant > 0`；
- `/api/firmware/overview` 的 `counts.candidate_count > 0`；
- `/api/mappings/catalogs` 和 `/api/mappings/graphs` 的 `total > 0`；
- `/api/mappings/corpus-report` 的 `gate_status == passed`。

如果任一数据域为空，先核对 `--database`，不要通过重新同步或复制临时数据库掩盖路径错误。修改主库前使用 SQLite `.backup` 创建一致性备份。
