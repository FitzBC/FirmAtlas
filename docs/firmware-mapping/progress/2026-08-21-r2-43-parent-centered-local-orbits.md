# R2-43：展开父节点成为子节点局部中心

## 1. 用户反馈与问题复现

用户要求“哪个节点展开的，就围绕哪个节点，别全局对称”。R2-42 虽然按类别形成环，接口目标坐标
仍统一相对固件原点计算；多个组件存在时，某组件的接口可能在视觉上更靠近另一个组件。

TDD 反例使用同一固件下的 `bin/dhttpd` 与 `bin/httpd`，将接口 owner 固定为 `bin/httpd`。旧布局中：

- 接口到 owner `httpd`：581.15；
- 接口到无关 `dhttpd`：135.70；
- 新增行为测试因此红灯失败。

## 2. 布局修正

布局目标改为逐级父节点局部坐标：

1. 固件保持逻辑原点；
2. 组件相对固件排布；
3. 每个组件分别收集自己的接口，接口环中心使用该组件坐标；
4. 每个接口分别收集自己的参数，参数环中心使用该接口坐标；
5. 局部环的起始方向沿父节点相对祖父节点的外向向量，避免所有簇共享同一全局相位；
6. 辅助环只绘制在当前已展开节点周围，并禁用 pointer events，不阻断空白画布拖动。

这只是 Catalog UI projection 的确定性布局，不创建新的 owner、通信或运行时事实。

## 3. 红绿验证

新测试通过公开渲染坐标观察用户可见行为，不调用内部布局函数。修正后接口到真正 owner 的距离
小于到其他组件的距离，且小于 380；专项测试 9/9 通过。

AC9 真实页面展开 `bin/httpd` 后：

| 指标 | 结果 |
| --- | --- |
| 可见节点 / 边 | 194 / 193 |
| 接口数 | 191 |
| 接口簇质心到 `bin/httpd` | 14.50 |
| 接口簇质心到 `bin/dhttpd` | 343.87 |
| 卡片矩形重叠 | 0 |

![AC9 httpd 局部接口簇](../screenshots/2026-08-21-r2-43-parent-centered-local-orbit.jpg)

## 4. 回归与交付

| 验证层 | 结果 |
| --- | --- |
| Console 全量 | 39/39，10 files |
| TypeScript / production build | 通过，1,802 modules transformed |
| 真实浏览器 | AC9 owner 局部质心、0 overlap、最新 JS asset 通过 |
| Python compileall | 通过 |
| Python 全量 | 564/564，458.925s |
| 本地 API | health/catalogs/graphs/corpus/jobs 均 HTTP 200；8 catalogs、3 graphs、gate passed |
| AC9 force graph | HTTP 200；276 nodes / 275 edges |

最终 Git 状态在提交前复验并回填。

本轮属于 firmware mapping 产品范围，按仓库例外不部署 `satc_cloud`，但必须完成本地验证、提交和
GitHub 推送。
