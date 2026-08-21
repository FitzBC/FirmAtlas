# R2-41：节点点击展开与大图首屏修复

## 1. 用户症状与验收目标

用户在 Tenda AC9 接口力导图点击 `bin/httpd` 后，页面仍像没有展开。本轮不把问题收敛为单一
按钮缺陷，而是按真实页面逐层验证：

1. 点击组件节点主体必须展开接口，点击右侧箭头也必须展开；
2. 拖拽节点只移动，释放后的浏览器 `click` 不得误触展开；
3. 191 接口大图展开后，固件、组件和第一批接口必须仍在初始画布视口；
4. 只有实际拥有子参数的接口显示展开箭头；
5. 接口展开后必须能点击参数并看到约束、依赖和证据侧栏。

本轮属于 firmware mapping 产品范围，按仓库例外不执行 SSH 部署，但完成本地服务、真实页面、
全量回归、提交和 GitHub 推送。

## 2. 诊断时间线

### 阶段 A：主体点击没有改变投影

真实浏览器点击 `选择节点 bin/httpd` 后，页面仍为：

```text
可见 3 / 276 nodes · 2 edges
接口节点：0
```

DOM 事件确认节点主体只执行 `setSelectedId`，只有右侧小箭头调用 `toggle`。这和页面“点击节点逐层
展开”的用户模型不一致。同时，pointer drag 监听挂在整个 `foreignObject`，小箭头的轻微指针位移也
可能进入拖拽路径。

### 阶段 B：数据已展开，但节点整体在屏幕外

修复主体点击后，DOM 已变为 194/276 nodes、193 edges，但截图仍是空白画布。坐标取证显示：

```text
root x=630.7, component x=1298.3
```

旧布局按总节点数成比例放大 depth column，并给所有节点使用全画布高度的随机 y；大图重新初始化后，
浅层节点被推到横向或纵向首屏之外。因此“点击事件成功”仍不足以解决用户症状。

### 阶段 C：所有接口都有伪展开箭头

服务端读模型把每个 interface 的 `expandable` 初始值固定为 `true`。AC9 的 191 个 `httpd` 接口因此
全部显示箭头，但只有 28 个接口拥有参数子节点；点击其余 165 个接口不会发生任何视觉变化。

## 3. 红绿迭代

| Slice | 红灯 | 最小修复 | 绿灯 |
| --- | --- | --- | --- |
| 主体点击 | 点击 `bin/httpd` 后找不到 `/goform/SetTimeCfg` | 可展开节点主体调用统一 `activate/toggle` | 主体和箭头均展开 |
| 拖拽隔离 | 拖拽监听覆盖整个卡片 | pointer 监听只挂主体；移动后一次性抑制 click | 拖拽状态出现且接口不展开 |
| 大图首屏 | 60 接口 fixture 的固件 y=1083、x=-70 | 固定浅层 lane、最多 6 列深层网格、degree-normalized spring、节点尺寸边界 clamp | 固件/组件 x≥0、y<500 |
| 真实子节点 | native-only interface 仍 `expandable=true` | 投影完成后由 `bool(child_ids)` 计算 | 有参数 true、无参数 false |

布局不再用总宽度百分比把组件推远。浅层固定为固件 `x=130`、组件 `x=380`，接口从 `x=610`
开始按最多六列排布；节点坐标按实际卡片半宽/半高约束，避免 `foreignObject` 被画布边缘裁切。

## 4. AC9 最终页面实证

Catalog：
`discovery-catalog:29081f8e9f48b65ee10c85b81cb73fbce5dffa26023726397ae691397e5373a4`

| 动作 | 结果 |
| --- | --- |
| 初始进入接口调查 | 3 / 276 nodes，2 edges |
| 点击 `bin/httpd` 主体 | 194 / 276 nodes，193 edges；69 个 `/goform/` 节点在 DOM |
| 服务端接口折叠能力 | 28 expandable，165 leaf，合计 193 |
| 展开 `/cgi-bin/UploadCfg` | 195 / 276 nodes，194 edges；出现参数 `filename` |
| 点击 `filename` | 右侧出现“参数详情”和“取值与代码约束” |

![点击组件后接口立即出现在首屏](../screenshots/2026-08-21-r2-41-click-expand.jpg)

![继续展开到 filename 参数及详情](../screenshots/2026-08-21-r2-41-parameter-detail.jpg)

## 5. 测试与服务

| 验证层 | 结果 |
| --- | --- |
| Backend 投影专项 | 3/3 通过；有参/无参 expandable 合同锁定 |
| Console | 37/37 通过，10 files |
| TypeScript + production build | 通过，1,802 modules transformed |
| Python compileall | 通过 |
| Python 全量 | 564/564 通过（460.243s） |
| API `/api/health` | HTTP 200，`status=ok` |
| AC9 API | 276 nodes / 275 edges；28 expandable interfaces；165 leaf interfaces |
| 真实浏览器 | 主体展开、箭头展开、首屏坐标、参数下钻和侧栏通过 |

## 6. 解释边界与反事实

- 无参数接口仍是有效接口事实，点击主体可查看 handler、方法和证据；只是不显示无效箭头。
- `expandable=false` 表示当前投影没有参数子节点，不证明接口运行时不接收任何输入。
- 固定浅层首屏不改变 Catalog，也不创造新的 owner、接口或参数关系。
- 如果只修 `onClick` 而不做真实截图，194 个节点在 DOM 但画布空白的问题会被漏掉。
- 如果只在前端按 `child_ids` 隐藏箭头，API 仍会向其他消费者发布错误能力；因此修正在后端读模型。

## 7. 交付状态

- 本地服务：`http://127.0.0.1:18789/`，最终生产构建已启动；
- SSH：不适用，符合 firmware mapping research exception；
- Git：源码、测试、README、部署说明、产品手册、截图和本记录进入同一提交并推送。
