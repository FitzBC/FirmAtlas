# R2-44：接口展开关联参数与搜索自动聚焦

## 1. 用户目标与真实断点

有参数关联的接口应继续展开，参数围绕所属接口显示；点击参数后展示类型、功能、约束、依赖与证据。

接口—参数关系和展开按钮已经存在，但父节点局部布局引入了可见性问题：搜索 `UploadCfg` 时，
`/cgi-bin/UploadCfg` 已进入三节点分支投影，却位于固定 SVG 视窗外。用户看到的仍是祖先组件，无法
点击接口，主观效果等同于“不能展开”。搜索投影本身会在接口展开后保留其直接子参数，即使参数名
不匹配搜索词；真正断点是视窗没有跟随最深层搜索命中节点。

## 2. 修正

- 搜索非空时选取最深层命中节点；
- 首次命中后把画布平移到该节点，使节点进入逻辑中心；
- 同一搜索词只自动聚焦一次，之后允许用户自由平移；
- 清空搜索恢复固件中心；
- 状态栏明确提示“展开后显示其关联参数”。

该行为只改变 UI viewport，不改变 Catalog 接口—参数 owner 事实。

## 3. TDD 与页面验证

红灯用例通过公开 SVG 卡片坐标与图层 transform 证明：搜索命中接口仍距中心 529.88。修正后接口
中心加 pan 的绝对偏差小于 60，并继续验证展开后参数可见。

AC9 真实页面：

| 步骤 | 结果 |
| --- | --- |
| 搜索 `UploadCfg` | 自动聚焦 `/cgi-bin/UploadCfg`，3 nodes / 2 edges |
| 展开接口 | 4 nodes / 3 edges，出现 `filename` |
| 局部布局 | `filename` 距接口 226.84 |
| 点击参数 | 右侧显示参数详情、owner `UploadCfg`、组件 `bin/httpd`、类型依据、约束与证据 |

![接口参数展开与详情](../screenshots/2026-08-21-r2-44-interface-parameter-expansion.jpg)

## 4. 验证与交付

| 验证层 | 结果 |
| --- | --- |
| Console | 39/39，10 files |
| TypeScript / production build | 通过，1,802 modules transformed |
| 真实浏览器 | 最新 `index-CpA0so5e.js`；搜索聚焦、展开、参数详情通过 |
| Python compileall | 通过 |
| Python 全量 | 564/564，468.416s |
| 本地 API | health/catalogs/graphs/corpus/jobs 均 HTTP 200；8 catalogs、3 graphs、gate passed |
| AC9 force graph | HTTP 200；276 nodes / 275 edges |

最终 Git 状态在提交前复验并回填。

本轮属于 firmware mapping 产品范围，按仓库例外不部署 `satc_cloud`；完成本地验证后提交并推送。
