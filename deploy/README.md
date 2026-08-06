# satc_cloud 部署

每项功能或修复完成后，都必须将同一 Git 修订部署到 SSH 主机
`satc_cloud` 并验证。仓库级约束见 `AGENTS.md`。

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
