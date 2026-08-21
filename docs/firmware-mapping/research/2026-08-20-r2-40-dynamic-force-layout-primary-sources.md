# R2-40 动态力导向图技术选型：一手来源研究

> 调研日期：2026-08-20 至 2026-08-21
>
> 调研范围：FirmAtlas Console 的“固件 → 二进制 → Web 接口 → 参数”交互图
> 来源边界：只使用项目官方文档、官方源码仓库、官方示例和维护者在官方仓库中的说明。

## 结论

FirmAtlas 当前阶段应优先采用 **`react-force-graph-2d` + 显式配置的 D3 碰撞力**，替换现有组件内自行实现的静态 SVG 力计算，但保留现有的 Catalog 投影、展开状态、搜索状态和右侧证据详情面板。

推荐不是因为该库能自动理解 FirmAtlas 的层级语义，而是因为它在现有 React 架构下同时提供：

- Canvas 渲染；
- 节点拖拽时自动重新加热模拟，使邻近节点实时让位；
- 节点和连线的 hover/click，以及平移、缩放；
- 可增量更新 `graphData`，适合展开/折叠；
- 可通过 `d3Force()` 注入碰撞力、层级定位力和局部鼠标力；
- 可定制节点绘制和独立的鼠标命中区域；
- MIT 许可，以及与 React 19 无冲突的 `react: "*"` peer dependency。

需要强调：`react-force-graph-2d` 默认只有 `link`、`charge`、`center` 三种力，**默认并不包含碰撞力**。如果只是替换渲染组件而不显式加入 `forceCollide` 或矩形碰撞力，节点仍可能重叠。[官方 API](https://github.com/vasturiano/react-force-graph/blob/master/README.md#force-engine-configuration)将默认力和 `d3Force()` 扩展点列得很清楚；[官方碰撞示例](https://github.com/vasturiano/react-force-graph/blob/master/example/collision-detection/index.html)也通过 `d3Force('collide', forceCollide(...))` 主动安装碰撞力。

Cytoscape.js + fCoSE 是第二选择，适合以后需要真正的 compound graph、对齐/相对位置约束或更多图算法时重新评估。Sigma.js/Graphology 更适合数千到数万节点的大图探索，目前会为 422 节点左右、具有较大文字卡片和证据侧栏的 FirmAtlas 图引入过多模型和渲染复杂度。直接使用 d3-force 则自由度最高，但会继续让 FirmAtlas 自己维护拖拽、缩放、Canvas 命中、生命周期和可访问性等基础设施，不是本轮的首选。

## 用户反馈对应的产品边界

### 静态资源文件不作为图节点

静态资源过滤属于 **Catalog → 接口图读模型的投影规则**，不是布局引擎职责。换图库不能解决错误的节点语义。

默认接口图应只把下列对象作为“组件”节点：

1. ELF 或其他有可执行证据的服务二进制；
2. 有请求注册、请求分派或 CGI handler 证据的运行时组件；
3. 无法绑定到具体二进制、但确实拥有 Web 请求接口的逻辑 dispatcher，并明确标为“未解析组件”，而不是静态文件。

默认不创建组件节点的对象包括：

- HTML、CSS、图片、字体、source map 等静态资产；
- 浏览器端 JavaScript 模块和页面模板；
- 只作为证据定位器出现、没有服务端执行或请求处理证据的文件；
- UBUS/IPC 等内部操作，它们仍保留在高级通信图或原始证据中，不混入 Web 接口图。

浏览器端 `.js` 不应仅凭扩展名一刀切：若 Catalog 有证据表明它在服务端作为可执行 handler 运行，仍可纳入。推荐给投影增加明确的 `component_role`/`artifact_role`，按证据分类，而不是在 React 中按路径字符串临时过滤。被过滤的静态文件仍可作为接口或参数侧栏中的 `evidence_location`，只是不能占据图上的组件层级。

### “随鼠标互动”应有明确语义

推荐按从稳定到实验性的顺序实现：

1. hover：高亮当前节点、父子链和直接邻居，其余图元淡化；
2. drag：节点跟随鼠标，模拟重新加热，其余节点通过排斥和碰撞实时让位；
3. pan/zoom：空白区拖动画布、滚轮缩放，双击或按钮聚焦选择分支；
4. 可选实验：把指针屏幕坐标用 `screen2GraphCoords()` 转成图坐标，注入有最大作用半径的弱局部排斥力。

第 4 项不应默认使用持续强排斥，否则用户只是移动鼠标阅读详情时整张图也会抖动。更稳妥的默认行为是仅在节点拖拽期间让图实时避让，或把“鼠标磁场”做成可关闭的实验开关。坐标转换和自定义力都由 `react-force-graph-2d` 官方 API 提供，但局部鼠标力本身是 FirmAtlas 需要实现和验证的产品行为，不是官方内置承诺。

## 当前实现的具体问题

当前 `FirmwareInterfaceForceGraph.tsx` 在 React render 前同步执行自研布局：

- 每轮对所有节点两两计算排斥，150 轮，复杂度近似 `O(150 × n²)`；
- SVG `foreignObject` 节点只有中心点排斥，没有按卡片宽高进行真正的碰撞检测；
- 布局一次算完后冻结，鼠标不能拖动节点，也不能让周边节点实时重新分离；
- 展开 `bin/httpd` 时新增大量接口会整图重新计算，已有节点位置不能稳定继承；
- 图的尺寸随节点数扩大，主要依靠滚动容器，而不是相机缩放和平移。

D3 的 many-body force 使用 quadtree 和 Barnes–Hut 近似，官方文档给出的单次复杂度是 `O(n log n)`；还可设置有限 `distanceMax`，缩小远距离计算范围。[D3 many-body 官方文档](https://d3js.org/d3-force/many-body)

这不等于集成后必然达到某个帧率，但说明它比当前固定轮次的全节点两两排斥更适合作为数百节点动态模拟的基础。

## 方案对比

| 方案 | 动态交互 | 防重叠 | 数百节点 | 展开/折叠 | React 接入 | 维护/许可 | FirmAtlas 判断 |
|---|---|---|---|---|---|---|---|
| `react-force-graph-2d` | 内置 hover/click/drag/pan/zoom；拖拽会重新加热 | 需用 `d3Force()` 显式加入碰撞力 | Canvas；官方仓库还提供约 4k 和约 75k 元素示例，但示例不是性能保证 | `graphData` 支持增量更新；层级状态由应用持有 | 原生 React 组件，改造面最小 | MIT；当前 2D 包源码版本 1.29.1；React peer 为 `*` | **首选** |
| d3-force + 自研渲染 | 力模拟本身不提供完整 UI 交互；需组合 drag/zoom/renderer | `forceCollide` 官方支持圆形软约束 | many-body 为 Barnes–Hut `O(n log n)` | 数据更新完全可控 | 需要继续维护 React/SVG/Canvas 桥接 | ISC；D3 官方持续维护 | 作为底层力引擎合适，单独集成工作过多 |
| Cytoscape.js + fCoSE | 内置桌面/触摸拖拽、选择、事件、pan/zoom | fCoSE 提供排斥、tiling、compound placement；可包含标签尺寸 | 核心官方给出性能调优指南；复杂标签和边会增加成本 | 可增删或 `display:none`；需重跑指定子图布局 | 核心为 imperative API；React wrapper 不是核心必需层 | 核心和一方扩展 MIT；核心官方仓库 2026-05 仍有版本发布 | **备选**，适合未来 compound/约束布局 |
| Sigma.js + Graphology | Sigma v4 官方示例内置 drag，并可与 worker force layout 联动 | Graphology 有 Noverlap；ForceAtlas2 `adjustSizes` 可考虑尺寸 | Sigma 官方定位为 WebGL 渲染数千节点和边 | Graphology 增删节点可实现，但应用需同步图模型、布局 worker 和 React 状态 | 需要额外 Graphology 模型和 imperative renderer；文字卡片需定制 WebGL/Canvas label | MIT；v3 稳定，v4 在官方仓库仍标 alpha，维护者称接近 beta但仍预期组合 bug | 当前规模和卡片 UI 下成本过高 |

### 1. react-force-graph-2d

官方 README 明确说明 2D 版本使用 Canvas，底层是 D3 force engine，并支持 zoom/pan、节点拖拽以及节点/连线 hover/click。[官方仓库](https://github.com/vasturiano/react-force-graph)

与 FirmAtlas 直接相关的官方能力：

- `graphData` 可用于增量更新；
- `nodeCanvasObject` 可自定义 2D 节点绘制；
- `nodePointerAreaPaint` 可单独绘制不可见的命中区域，适合较小参数节点和长标签；
- `onNodeHover`、`onNodeClick`、`onNodeDrag`、`onNodeDragEnd` 可驱动高亮、选择和证据侧栏；
- `enableNodeDrag` 默认开启，拖拽时模拟重新加热，其他节点会响应位置变化；
- `d3Force()` 可重配默认力或加入新力，`d3ReheatSimulation()` 可在展开分支后重新启动；
- `autoPauseRedraw` 默认在模拟停止后暂停 2D Canvas 重绘，可减少空闲开销；
- `warmupTicks`、`cooldownTicks`、`cooldownTime` 可控制首次稳定和计算上限。

来源：[官方 API 文档](https://github.com/vasturiano/react-force-graph/blob/master/README.md)、[2D 包 package.json](https://github.com/vasturiano/react-force-graph/blob/master/src/packages/react-force-graph-2d/package.json)、[MIT License](https://github.com/vasturiano/react-force-graph/blob/master/LICENSE)。

接入风险：

- Canvas 节点不再是实际 DOM button；需要保留侧栏、搜索结果和键盘可操作的节点列表，不能把 Canvas 当作唯一无障碍入口；
- `nodeCanvasObject` 每帧对每个可见节点调用，必须避免 React mount、测量 DOM 或创建图片等重操作；
- 官方 `forceCollide` 把节点视为圆，不理解当前矩形卡片；
- 库会给节点对象写入 `x/y/vx/vy/fx/fy`，不能把只读 API DTO 直接当作不可变领域对象反复复用；
- 更新链接后，`source/target` 可能从 ID 变成对象引用，投影和测试需使用单独的视图模型类型；
- hover 命中会付出性能成本，官方建议追求极限性能时关闭 pointer tracking。FirmAtlas 必须保留交互，因此应通过渐进展开和减少标签绘制控制负担。

碰撞策略建议：

1. POC 先用 `forceCollide`，半径取卡片宽高的外接圆半径加安全间距：`sqrt(width² + height²) / 2 + gap`。这会留出更多空白，但能保证任意旋转方向上的矩形包围盒不会彼此穿过；
2. 节点绘制尺寸应在图坐标中稳定，不要让碰撞半径和视觉尺寸在 zoom 时采用两套含义；
3. 如果外接圆造成图过松，再实现基于 quadtree 的轴对齐矩形碰撞力，并用独立单元测试验证每对节点包围盒；
4. `charge` 负责宏观分离，`collide` 只负责近距离不相交，两者不能互相替代。

### 2. d3-force

D3 force simulation 可用于网络、层级和碰撞布局，并通过 tick 事件把坐标交给 SVG 或 Canvas 渲染器。[d3-force 官方文档](https://d3js.org/d3-force)

`forceCollide` 把节点当作给定半径的圆，并保证中心距离至少为半径之和；其约束默认是可调 strength 和 iterations 的软约束。增加 iterations 会减少残余重叠，但会提高运行成本。[D3 collide 官方文档](https://d3js.org/d3-force/collide)

优点是控制力最强，可以原样保留 SVG/DOM 节点。问题是 FirmAtlas 还要自行补齐：

- pointer 坐标转换；
- drag pinning 和 alpha 生命周期；
- pan/zoom 相机；
- Canvas/SVG 命中；
- ResizeObserver；
- 展开时坐标继承；
- 大图降级策略。

因此建议通过 `react-force-graph-2d` 使用这套力，而不是继续独立拼装。

d3-force 的源码包声明 ISC 许可。[官方 package.json](https://github.com/d3/d3-force/blob/main/package.json)

### 3. Cytoscape.js + fCoSE

Cytoscape.js 自带图模型、Canvas renderer、桌面和触摸手势、事件系统和布局扩展机制。官方手势包括背景 pan、滚轮或触摸 zoom、节点拖拽、点选和框选。[官方文档](https://js.cytoscape.org/#introduction/gestures)

官方文档列出的 fCoSE 是较快的 compound spring embedder。fCoSE 官方扩展说明其支持 compound graph、固定节点、水平/垂直对齐和相对位置约束，并提供 `nodeRepulsion`、`nodeSeparation`、tiling、标签尺寸等参数。[fCoSE 官方仓库](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose)

这是把“固件包含组件、组件包含接口”显示成真正 compound group 的有力候选。不过 FirmAtlas 当前需求是逐层揭示而非同时绘制嵌套容器，且现有状态和侧栏均为 React。直接接 Cytoscape 需要在 effect 中维护实例、事件订阅、元素差异更新和 destroy 生命周期；如果再引入社区 React wrapper，会增加一个不由 Cytoscape 核心维护的依赖层。

官方性能指南还说明：标签和边绘制成本高，复杂 style、compound nodes 和高 pixel ratio 都会增加负担；可以 batch 更新、降低 pixel ratio、交互期间隐藏边等。[Cytoscape.js 性能指南](https://js.cytoscape.org/#performance)

另一个重要语义是 `display:none` 节点不占空间、不交互，并在布局重叠规避中被视为点。展开/折叠后应对可见子图重新运行布局，而不是期待被隐藏节点继续撑开空间。[Cytoscape.js visibility 文档](https://js.cytoscape.org/#style/visibility)

Cytoscape.js 核心和其一方扩展采用 MIT 许可；官方仓库在本次调研时显示 2026-05 仍有新版本，维护信号良好。[官方仓库](https://github.com/cytoscape/cytoscape.js)

### 4. Sigma.js + Graphology

Sigma.js 是基于 WebGL、以数千节点和边为目标的 renderer，使用 Graphology 作为图模型。[Sigma 官方仓库](https://github.com/jacomyal/sigma.js)、[官方数据模型文档](https://www.sigmajs.org/docs/advanced/data/)

Graphology ForceAtlas2 提供同步和 Web Worker 版本；开启 `barnesHutOptimize` 后，排斥由 `O(n²)` 改为 `O(n log n)`，`adjustSizes` 可让布局考虑节点 size。[Graphology ForceAtlas2 官方文档](https://graphology.github.io/standard-library/layout-forceatlas2)

Graphology 另有 Noverlap anti-collision layout，支持 margin、size ratio、grid 优化和 worker，但官方明确提醒它是迭代算法，在某些情况下不容易收敛。[Graphology Noverlap 官方文档](https://graphology.github.io/standard-library/layout-noverlap)

Sigma v4 官方拖拽示例已经能让 force layout 固定正在拖拽的节点并在释放后恢复；还支持多节点拖动。[Sigma v4 官方拖拽文档](https://v4.sigmajs.org/how-to/interactivity/drag-drop/)

但本轮不推荐 Sigma：

- 它解决的是更大图的高性能点线渲染，而 FirmAtlas 现在需要可读的大文字卡片；
- 自定义复合节点形状通常进入 WebGL program 或额外 Canvas label 层，开发成本显著高于 `nodeCanvasObject`；
- 需要同时管理 React、Graphology、Sigma renderer 和 layout worker 四套生命周期；
- Sigma 主仓库在调研时仍将 v4 标为 alpha；维护者 2026-06 在官方讨论中称其已接近 beta、功能完整，但仍预期功能组合中的新 bug。[官方 v4 状态讨论](https://github.com/jacomyal/sigma.js/discussions/1539)

Sigma/Graphology 均为 MIT 系生态。若未来单张通信图稳定达到一万级以上可见元素，再以实际数据做 Sigma POC 更合适。

## 推荐接入设计

### 依赖

只引入 2D 子包，避免 umbrella package 把 3D、VR、AR 依赖带入 Console：

```text
react-force-graph-2d
d3-force-3d
```

官方 2D 包依赖 `force-graph`、`react-kapsule` 和 `prop-types`，peer dependency 为任意 React；当前 FirmAtlas 的 React 19.2 满足其声明。[2D 包 package.json](https://github.com/vasturiano/react-force-graph/blob/master/src/packages/react-force-graph-2d/package.json)

之所以使用 `d3-force-3d` 的 2D 子集，是因为 react-force-graph 官方示例和内部引擎基于同族 force 接口；实际锁定版本前应以 pnpm lockfile 和 TypeScript build 验证类型兼容。

### 组件边界

建议拆成四层：

1. `projectVisibleInterfaceGraph(graph, expanded, query)`：纯函数，只决定哪些语义节点可见；
2. `toForceGraphData(projection, previousPositions)`：复制为可变的 Canvas view model，继承已有坐标，并把新子节点放在父节点附近；
3. `DynamicInterfaceForceCanvas`：只负责 renderer、forces、drag/hover/zoom 和帧级绘制；
4. 现有 `NodeDetail`：继续负责可访问的结构化证据展示。

展开时不要重置所有坐标：

- 保留仍可见节点的 `x/y`；
- 新节点以父节点为中心做小角度扇形或确定性 jitter；
- 更新 `graphData` 后调用 `d3ReheatSimulation()`；
- 在模拟稳定后停止重绘；
- 折叠时移除后代 view nodes，但不要污染原始 API graph。

### 推荐力模型

- `link`：按边类型设置距离，例如固件→组件较长、组件→接口中等、接口→参数较短；
- `charge`：按节点种类设负强度，并设置有限 `distanceMax`；
- `collide`：以节点视觉包围范围为半径，至少 2 次 iteration；参数通过真实 POC 调整；
- `x`：可选的弱层级带状力，让 0/1/2/3 深度大体从左到右，但不能强到把图压成四条重叠竖线；
- `y`：只施加很弱的居中力；
- `pointer`：默认关闭，实验模式下只在有限半径内施加弱排斥。

参数值不能在研究文档里假装已经验证。应通过 AC9 的 30、50、100、220 和 422 可见节点场景记录重叠数、稳定时间和交互帧率后再固化。

### 节点绘制

Canvas 上不应复刻当前 200px 宽的完整 DOM 卡片。推荐分层显示：

- 正常缩放：图标/种类色 + 截断后的主要标签；
- hover/选中：显示完整标签、展开箭头和邻居高亮；
- 详细字段：始终在右侧侧栏呈现；
- 远距离缩放：隐藏大多数标签，只保留固件、组件和选中路径；
- 参数节点保持较小，通过独立 pointer paint 扩大命中区。

这样既降低碰撞半径，又减少 Canvas 每帧文本测量和绘制。

## POC 与验收门槛

在正式替换前，应建立同一份 AC9 数据的并排 POC。最低验收条件：

1. 静态资源、浏览器端模块不出现在默认组件图，仍能在证据定位中看到；
2. 默认根层、展开 `bin/httpd`、搜索 `SetSysTimeCfg`、展开三个参数均能完成；
3. 点击接口/参数仍打开同一证据侧栏，内容与 R2-39 一致；
4. 任一稳定布局完成后，可见节点包围盒重叠数为 0；
5. 拖动一个节点时，其余节点在碰撞力作用下实时让位，释放后在有界时间内稳定；
6. 展开/折叠不应让未受影响分支完全随机跳位；
7. hover 高亮父子路径和一阶邻居，鼠标离开后恢复；
8. pan、zoom、fit、重新布局可用，右侧详情面板位置不漂移；
9. 30、50、100、220、422 个可见节点分别记录布局稳定耗时、长任务和浏览器帧率；
10. 连续 20 次展开/折叠后无事件监听器、RAF、simulation 或 Canvas 泄漏；
11. reducer/projection 单测继续验证 Web-only 和静态资产过滤；
12. 浏览器 Console 无错误，生产 build 和现有前端回归测试通过。

性能门槛建议以真实设备实测再锁定，不应引用官方“大图示例”当作 FirmAtlas 性能证明。初始目标可设置为：220 可见节点拖拽期间主观连续、无超过 100ms 的常态长任务，422 节点最终可稳定且详情交互不被阻塞。

## 接入风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 圆形碰撞与矩形视觉不一致 | 卡片重叠或图过松 | 先用外接圆保证正确，再以测试驱动实现矩形碰撞 |
| Canvas 降低 DOM 可访问性 | 键盘和读屏无法直接遍历节点 | 保留搜索、侧栏和可键盘操作的结构化结果列表 |
| 展开时全图抖动 | 用户失去空间记忆 | 继承坐标，新子节点从父节点附近生成，只局部 reheat |
| hover 命中增加开销 | 大图拖拽卡顿 | 渐进展开、缩放级别标签、精简 node paint，不关闭必要交互 |
| API DTO 被力引擎原地修改 | React memo 和领域事实被污染 | 建立独立可变 view model，按 ID 回写临时坐标缓存 |
| 过强鼠标排斥造成持续抖动 | 难以点击和阅读 | 默认仅 drag reheat；cursor force 做可关闭实验 |
| 新依赖版本漂移 | 构建或行为变化 | 精确锁版本、保存许可证、加入组件交互回归测试 |
| 把路径后缀当成唯一语义 | 漏掉服务端脚本或误收前端模块 | 后端以 producer/executable/dispatcher 证据分类 |
| 大量接口一次展开 | 画面仍拥挤 | 接口分页/分组、搜索聚焦、按业务域展开，不靠力模拟解决信息过载 |

## 决策记录

- **采纳**：`react-force-graph-2d` 作为 R2-40 POC 的渲染和交互层。
- **采纳**：底层 D3 force，通过 `d3Force()` 显式安装碰撞和弱层级力。
- **采纳**：默认 drag-reheat、hover 邻居高亮、pan/zoom；鼠标局部排斥先做实验开关。
- **采纳**：静态资源在后端/读模型投影中排除，但保留为证据定位器。
- **暂缓**：矩形 quadtree collision；先用外接圆完成无重叠基线。
- **暂缓**：Cytoscape.js + fCoSE；待 compound grouping 或布局约束成为核心需求时复评。
- **不采用本轮**：Sigma v4；版本仍处于预发布阶段，且当前图规模不足以抵消集成复杂度。
- **不采用本轮**：继续扩充自研 SVG `O(n²)` 布局。

## 一手来源索引

1. [react-force-graph 官方仓库与 API](https://github.com/vasturiano/react-force-graph)
2. [react-force-graph 官方 README/API 表](https://github.com/vasturiano/react-force-graph/blob/master/README.md)
3. [react-force-graph 官方碰撞示例源码](https://github.com/vasturiano/react-force-graph/blob/master/example/collision-detection/index.html)
4. [react-force-graph-2d 官方 package.json](https://github.com/vasturiano/react-force-graph/blob/master/src/packages/react-force-graph-2d/package.json)
5. [react-force-graph MIT License](https://github.com/vasturiano/react-force-graph/blob/master/LICENSE)
6. [D3 force 官方文档](https://d3js.org/d3-force)
7. [D3 collide 官方文档](https://d3js.org/d3-force/collide)
8. [D3 many-body 官方文档](https://d3js.org/d3-force/many-body)
9. [d3-force 官方 package.json](https://github.com/d3/d3-force/blob/main/package.json)
10. [Cytoscape.js 官方文档](https://js.cytoscape.org/)
11. [Cytoscape.js 官方仓库](https://github.com/cytoscape/cytoscape.js)
12. [fCoSE 官方扩展仓库](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose)
13. [Sigma.js 官方仓库](https://github.com/jacomyal/sigma.js)
14. [Sigma v4 官方拖拽文档](https://v4.sigmajs.org/how-to/interactivity/drag-drop/)
15. [Sigma v4 官方状态讨论](https://github.com/jacomyal/sigma.js/discussions/1539)
16. [Graphology ForceAtlas2 官方文档](https://graphology.github.io/standard-library/layout-forceatlas2)
17. [Graphology Noverlap 官方文档](https://graphology.github.io/standard-library/layout-noverlap)

## 研究限制

- 本轮是技术选型研究，没有把候选库安装进 FirmAtlas，也没有对 AC9 数据执行真实帧率 benchmark；
- 官方的大图示例证明 API 能承载对应示例，不证明 FirmAtlas 的复杂标签、侧栏和设备组合必然达到同样性能；
- `forceCollide` 官方只承诺圆形碰撞，本记录提出的外接圆和鼠标局部力属于工程推断，需要 POC 验证；
- 维护状态是截至调研日期的快照，接入时仍需重新核对版本、依赖树、许可证和安全公告。
