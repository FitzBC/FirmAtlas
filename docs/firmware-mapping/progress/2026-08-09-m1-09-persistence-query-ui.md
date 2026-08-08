# M1-09：Discovery Catalog 持久化查询与最小 UI

> 工作项：M1-09
> 日期：2026-08-09
> 状态：已验证

## 1. 目标与边界

把 M1-08 的不可变 `DiscoveryCatalog` 接入 FirmAtlas 的 SQLite、HTTP 和 React Console，使分析员能查看目录版本、搜索候选并下钻证据。M1-09 只建立可重建读模型，不修改 Producer 事实，也不在浏览器端重新分类接口。

Binwalk 仍只允许出现在隔离 Extraction Worker；查询服务、API 和 Console 均不调用解包工具。

## 2. 冻结 Interface

`DiscoveryCatalogRepository` 提供四组稳定行为：

- `publish(catalog)` / `publish_dict(document)`：内容摘要校验、幂等发布、身份冲突拒绝；
- `list_catalogs()` / `get_catalog()`：目录版本和完整版本化文档；
- `query_candidates()`：按目录、候选类型、规范化 token 与分页查询；
- `get_candidate()`：聚合参数、关联、开放义务、相关 EvidenceAtom 和 Coverage Ledger。

完整 JSON 是事实源，`mapping_discovery_candidates` 是可删除重建的查询投影。查询 token 会拆分 CamelCase 与路径分隔符，但不执行语义猜测。

## 3. HTTP、CLI 与 UI

HTTP Adapter 新增：

- `GET /api/mappings/catalogs`；
- `GET /api/mappings/catalogs/{catalog_id}`；
- `GET /api/mappings/catalogs/{catalog_id}/candidates`；
- `GET /api/mappings/catalogs/{catalog_id}/candidates/{candidate_id}`。

CLI 提供 `mapping publish-catalog` 和 `mapping list-catalogs`。Console 新增“通信测绘”工作区，使用目录 → 候选 → 证据详情的同页三级布局；宽屏三列、窄屏纵向排列，不复用会交叉遮挡的 Investigation Drawer。

## 4. 样本驱动验证

浏览器临时数据库发布了由 Frontend Producer 从 jQuery `post` 构造生成的小型目录。实测：

- `online dev` 命中 `/goform/SetOnlineDevName`；
- `request_interface` 类别过滤保留该候选；
- 详情展示 `mac`、`devName` 两个 form 参数；
- EvidenceAtom 能回到 `webroot/js/device.js` 的精确 locator；
- 浏览器控制台无错误，三级区域无覆盖式抽屉。

临时数据库不进入仓库，也不替代 AC9 的 M1-08 真实回放结果。

## 5. 验证门禁

| 门禁 | 结果 |
| --- | --- |
| Python 全量回归 | 195/195 通过 |
| Mapping Repository + API 专项 | 13/13 通过 |
| React/Vitest | 17/17 通过，9 个测试文件 |
| TypeScript + Vite production build | 通过，1,800 modules transformed |
| 本地 API | `/api/health`、目录、token 查询、候选详情与前端文档均为 200 |
| 浏览器 | 导航、过滤、三级下钻、参数与 EvidenceAtom 可见；console 0 error |
| `py_compile` / `git diff --check` | 通过 |
| `satc_cloud` | 不适用；通信测绘工作按用户明确范围暂不执行 SSH 部署 |

已验证实现 revision：`af13698a5f1951744f9861139b1591446619a126`。本 closure 只回填 revision，不修改已验证代码。上述部署例外不扩大到 FirmAtlas 的其他功能。

## 6. 下一步

进入 M1-10：实现 Native route/handler 深绑定 Adapter，消费 M1-07 的 `registers_route` / `binds_handler` 开放义务，并以独立 EvidenceAtom 关闭可证明的义务。不得因名称相似直接发布 handler binding。
