# FirmAtlas Domain

FirmAtlas 描述固件从获取、测绘到漏洞关联和持续情报更新的完整知识链。词汇强调可追溯事实，并明确区分来源记录、自动判断与人工结论。

## 固件目录

**厂商（Vendor）**：
发布设备或固件的组织。
_Avoid_: 品牌、供应商

**产品（Product）**：
由厂商命名的一组设备，不保证组内设备使用相同固件。
_Avoid_: 资产、设备

**设备型号（Device Model）**：
具有明确硬件或市场型号标识、可与一组固件版本关联的产品变体。
_Avoid_: Product、硬件实例

**固件发行版（Firmware Release）**：
厂商面向一个或多个设备型号发布并赋予版本和时间语义的固件版本。
_Avoid_: 固件文件、镜像

**固件制品（Firmware Artifact）**：
以内容摘要唯一标识的原始二进制对象；同一发行版可以有多个制品，同一制品也可能被多个发行版引用。
_Avoid_: Firmware Release、上传文件

**来源（Acquisition Source）**：
固件制品或情报条目的获取位置及其获取时间、许可和可信度信息。
_Avoid_: 下载链接

**固件来源目录（Firmware Source Catalog）**：
可持续发现固件发行版或下载线索的官方门户、公开仓库、第三方归档或漏洞研究资料集合；它描述发现渠道，不断言其中每个链接仍可下载。
_Avoid_: 固件文件、下载链接、厂商

**固件样本候选（Firmware Sample Candidate）**：
尚未摄取为固件制品，但已记录厂商、产品、版本、下载地址及来源证据的潜在固件文件；地址可失效、受限或尚未验证内容摘要。
_Avoid_: 固件制品、已下载样本、Firmware Artifact

**样本漏洞线索（Sample Vulnerability Lead）**：
固件样本候选与漏洞记录之间带来源证据和置信度的待验证关联，不等同于该固件已被证实受漏洞影响。
_Avoid_: 漏洞匹配、受影响声明、已复现漏洞

**候选版本身份（Candidate Version Identity）**：
从来源字段或固件文件名中提取并规范化的一组可能版本标识，每个标识保留提取方式与可信度；它不等同于已解包验证的内部版本。
_Avoid_: 固件版本、已验证版本、文件名

**版本关联线索（Version Association Lead）**：
固件样本候选的版本身份与漏洞受影响声明在厂商、产品及版本约束上形成的可解释关联，区分精确版本、版本范围和仅产品范围。
_Avoid_: 已确认受影响、漏洞复现、字符串命中

## 分析与证据

**分析运行（Analysis Run）**：
针对一个固件制品、使用固定分析器与规则版本执行的一次不可变分析记录。
_Avoid_: 扫描、任务

**派生制品（Derived Artifact）**：
从固件制品或另一个派生制品中解包、解码或转换得到，并保留父子关系的内容对象。
_Avoid_: 临时文件

**观察事实（Observation）**：
分析器从制品中提取的、带证据和置信度的结构化事实。
_Avoid_: Finding、漏洞

**证据（Evidence）**：
支撑观察事实或判断的可定位材料，例如内容摘要、文件路径、字节区间、符号、配置行或工具原始输出。
_Avoid_: 日志、备注

**分析快照（Analysis Snapshot）**：
某个固件发行版在指定时点被发布的一组分析运行和关联判断，用于历史回看与版本比较。
_Avoid_: 最新结果、报告文件

**集合差异归因（Set-difference Attribution）**：
对两个已声明范围的候选集合做双向差异，并用可定位辅助证据描述“范围缺口、仅声明、被其他制品消费、变体或无引用”等观察形状；它不自动证明版本原因、运行时可达、执行主体或 handler 归属。
_Avoid_: 漏检原因、后端绑定、同源证明

**嵌套操作选择器（Nested Operation Selector）**：
同一物理请求中按先后层级选择 transport mode、dispatcher 分支或业务 operation 的多个字段或 URL 片段，例如 `action=upload` 与 `setting/setUploadSetting`；各层必须保留独立身份和证据，不能因共享 URL 而压成一个操作。
_Avoid_: 单一接口名、重复参数、路径别名

**嵌套分发路径（Nested Dispatch Path）**：
从外层 transport mode、嵌套 selector 的提取与规范化，到具体 operation table 和
handler 的证据约束路径；每一跳必须保留独立指令或配置证据，不能由多个字符串在
同一二进制中共现而合成。
_Avoid_: 字符串共现、单一表项、调用链猜测、Nested Operation Selector

**请求保护范围（Request Protection Scope）**：
由可重放的路径条件、认证调用、会话验证和拒绝分支共同限定的一组受保护或被排除请求；它描述特定静态保护门的适用边界，不自动证明运行时可达、授权策略、漏洞存在或可利用性。
_Avoid_: 登录字符串命中、全局已认证、未授权漏洞、运行时访问控制

**静态服务装配（Static Service Assembly）**：
由固件初始化调用、进程启动参数、配置文件、listener、document root、namespace 和目标制品共同证明的静态服务链；它证明制品如何被设计为一起运行，但不等同于某次启动成功或运行时进程观察。
_Avoid_: 进程已运行、端口可达、动态验证、字符串共现

**潜在隐藏接口（Potential Hidden Interface）**：
在声明的前端与客户端分析范围内没有观察到引用、但具有可重放 Native 注册或 dispatcher binding 的接口操作候选。必须同时保存前端覆盖范围、Native 证据和未决原因；它可能来自隐藏客户端、动态构造、旧版本残留或死代码，不能简写为已确认隐藏接口。
_Avoid_: 隐藏接口、后门、未授权接口、Native-only 字符串

**前端静态调用可达性（Frontend Static Invocation Reachability）**：
在声明的前端源制品与语法覆盖内，将请求区分为顶层框架声明、具有可定位调用边的活动静态
调用路径、只有定义但未观察到可执行引用的函数，以及无法保守解析的状态。注释中的事件绑定
可以作为解释证据，但不能形成活动边；该状态不证明页面已加载、事件已触发、请求已发送或
运行时不可达。
_Avoid_: 运行时可达、死代码、接口不存在、事件已执行、请求已发送

## 固件测绘

**组件（Software Component）**：
固件中可被识别的软件、库、内核、软件包或第三方代码单元，允许版本未知或身份不完整。
_Avoid_: 文件、进程

**执行主体（Runtime Principal）**：
运行时可启动或承载行为的程序、脚本、内核模块或进程角色。
_Avoid_: Component、服务

**通信端点（Communication Endpoint）**：
执行主体能够监听、连接或暴露的本地或网络可达位置。
_Avoid_: URL、接口

**通信关系（Communication Relation）**：
两个执行主体或端点之间带方向、协议、传输方式和证据的交互关系。
_Avoid_: 网络连接、依赖

**暴露接口（Exposed Interface）**：
外部调用者可触达的命令、RPC、Web 路由、消息主题、设备节点或管理入口。
_Avoid_: API、端口

**接口参数（Interface Parameter）**：
暴露接口接收的具名或位置输入及其位置、类型约束、默认值和认证要求。
_Avoid_: 配置项

**接口操作（Interface Operation）**：
在一个暴露接口内由方法、选择器、消息根或请求形状区分的可调用行为；多个接口操作可以共享同一个 URL 或传输端点。
_Avoid_: 接口、功能分类、处理函数

**参数身份（Parameter Identity）**：
接口参数在指定接口操作和输入命名空间中的规范身份，允许关联前端字段名、协议字段名、后端变量和持久化键等别名。
_Avoid_: 参数名、字符串

**参数—状态映射（Parameter-to-State Mapping）**：
经 getter 调用、寄存器或变量 provenance 与状态 setter 调用逐段证明的接口参数到配置状态键关系；控制流边界之外的传播必须保持未决。
_Avoid_: 字符串共现、同一函数出现、完整漏洞数据流

**证据原子（Evidence Atom）**：
能够独立定位来源并支撑一个最小主张的证据单元；它区分直接观察、规则推导、模型建议和运行时验证。
_Avoid_: 线索、结论、日志

**线索（Clue）**：
能够触发后续检索或分析、但尚不足以单独确认结论的可追溯信息；线索必须由一个或多个证据原子支撑。
_Avoid_: Seed、关键词、证据

**线索传播（Clue Propagation）**：
以前端、后端、配置、二进制或运行时线索为起点，沿可验证关系发现新线索并保留完整来源链的跨层分析过程。
_Avoid_: 模糊搜索、自由联想、Seed 扩展

**通信架构图（Communication Architecture Graph）**：
描述执行主体、暴露接口、接口操作、解析与分发位置、状态位置及敏感行为之间可追溯关系的图。
_Avoid_: 网络拓扑、调用图、接口列表

**固件测绘快照（Firmware Mapping Snapshot）**：
针对一个固件制品、在固定分析策略和分析器版本下发布的不可变通信架构、接口、参数、证据与覆盖状态集合。
_Avoid_: Analysis Snapshot、最新扫描、报告文件

**覆盖账本（Coverage Ledger）**：
描述哪些制品范围、证据来源和分析能力已成功、失败、跳过或不适用的可审计记录。
_Avoid_: 完成度、日志、接口数量

**未决义务（Unresolved Obligation）**：
为确认、排除或细化某项测绘主张仍需补充的明确证据需求。
_Avoid_: 待复核、TODO、错误

**通信架构指纹（Communication Architecture Fingerprint）**：
由线路形态、分发机制、处理绑定、参数解析、状态工作流和代码结构等独立视图组成的可解释固件架构表征。
_Avoid_: 路径类别、单一相似度、代码哈希

**架构关联假设（Architecture Association Hypothesis）**：
两个固件或接口操作可能共享通信架构、实现谱系或漏洞机理的可推翻判断，并分别保留各指纹视图的证据和不确定性。
_Avoid_: 同源确认、漏洞匹配、相似接口

**漏洞机制路径（Vulnerability Mechanism Path）**：
从外部输入经过解析、分发、保护条件和数据变换到敏感状态或危险行为的证据约束因果路径。
_Avoid_: 调用链、CWE 标签、PoC

**通信测绘研究案例（Communication Mapping Research Case）**：
围绕一个复杂通信结构问题，按发生顺序保存证据主张、认识状态、未决义务及其关闭过程，并附反事实、论文用途和局限的内容寻址记录；它引用既有证据，不创造新的固件事实。
_Avoid_: 成功截图、最终结论摘要、产品演示、论文真值

## 漏洞与情报

**漏洞记录（Vulnerability Record）**：
对一个安全缺陷的规范化描述，可聚合 CVE、GHSA 等多个外部标识和来源修订。
_Avoid_: CVE、漏洞情报

**受影响声明（Affected Claim）**：
某来源关于产品、组件或版本范围受某漏洞影响的陈述，可能与其他来源冲突。
_Avoid_: 漏洞命中、CPE

**漏洞匹配（Vulnerability Match）**：
受影响声明与具体固件发行版、组件或观察事实之间，带匹配理由、置信度和状态的判断。
_Avoid_: 漏洞、扫描结果

**验证结论（Validation Verdict）**：
自动分析或人工复核对漏洞匹配作出的确认、排除、待定或不可验证结论。
_Avoid_: 状态、备注

**情报条目（Intelligence Item）**：
从外部来源获取的、保留原文摘要与时间信息的漏洞、利用、修复或风险变化记录。
_Avoid_: Vulnerability Record、告警

**关注规则（Watch Rule）**：
用于识别与已有厂商、产品、组件或漏洞相关的新情报并决定是否提醒的条件。
_Avoid_: 搜索、订阅

**固件相关性（Firmware Relevance）**：
情报条目与设备固件之间基于固件术语、设备类型、厂商身份和 CPE 结构证据作出的可解释判断。
_Avoid_: 关键词命中、漏洞匹配

**相关性策略（Relevance Policy）**：
定义固件术语、设备术语、关注厂商、固件专属厂商和判断阈值的一组版本化规则。
_Avoid_: 搜索条件、关注规则

**漏洞语义分析（Vulnerability Semantic Analysis）**：
从漏洞记录的标题与描述中派生暴露接口、接口参数、通信方式和攻击语义，并为每个结果保留证据、来源与置信度的二次分析运行。
_Avoid_: 固件测绘、漏洞匹配、关键词搜索

**分析指纹（Analysis Fingerprint）**：
由漏洞内容摘要与分析器、提示词、模型配置版本共同构成的幂等标识；指纹相同的成功或部分分析不得重复执行。
_Avoid_: 任务 ID、缓存键

**接口风格类别（Interface Style Category）**：
根据暴露接口的路径结构、调用形态、观察类型和组件上下文归纳出的通信入口类别，用于聚合和下钻关联漏洞、厂商与固件。
_Avoid_: 协议、端口、漏洞类型

**后端通信架构风格（Backend Communication Architecture Style）**：
在同一接口风格类别内，根据路由命名语法、命名空间层级、处理器注册方式和分发入口形态归纳出的结构相似性判断，用于识别可能共享后端控制面架构的固件族。它表达“架构形态相似”，不单凭路径断言使用了同一 Web 服务器或相同代码实现。
_Avoid_: 接口功能、漏洞类型、已确认的软件组件、业务动作

**接口结构推荐（Interface Structure Recommendation）**：
以一个已知或未知的暴露接口为查询样本，根据其接口风格类别、后端通信架构风格和路径结构证据，返回可能采用相似后端控制面结构的接口及其关联漏洞、厂商和固件型号。推荐表达结构相似性，不构成代码同源或组件身份结论。
_Avoid_: 模糊搜索、漏洞匹配、同源确认

**测绘发行上下文（Mapping Release Context）**：
附着于不可变 Discovery Catalog 的证据支持发行身份，包含厂商、产品、设备型号、固件版本、来源引用与身份依据。它用于限定版本比较的同家族边界，不从文件名或路径单独推断。
_Avoid_: 固件候选、下载 URL、Catalog ID

**测绘快照差异（Mapping Snapshot Diff）**：
在先比较 Coverage Ledger 和分析 profile 后，对两个不可变通信测绘目录中的稳定候选、参数与潜在隐藏接口身份进行的结构差异。差异必须区分 `firmware_change_supported`、`observed_scope_only` 与 `coverage_confounded`，不能把分析覆盖变化冒充固件变化。
_Avoid_: 原始 JSON diff、Git diff、漏洞修复结论

**逻辑 RPC 操作（Logical RPC Operation）**：
前端或客户端显式声明的远程过程身份，例如 LuCI `rpc.declare` 中由 `object + method` 组成的 `ubus://object/method`。它记录通信语义而不是猜测运行时解析出的固定 HTTP URL；动态 object/method 必须保留覆盖缺口。
_Avoid_: HTTP endpoint、Native handler、已验证运行时服务

**逻辑 RPC 操作模板（Logical RPC Operation Template）**：
对象或方法包含一个可界定运行时槽位的 RPC 操作族，例如 `ubus://hostapd.{dynamic}/del_client`。模板证明固定前后缀与方法，不代表某个具体运行时实例已经存在或可达。
_Avoid_: 未解析表达式、具体 ubus object、运行时枚举结果

**ubus 后端绑定（ubus Backend Binding）**：
逻辑 RPC 操作与 rpcd 执行主体之间的证据关系。可枚举 Lua exec-plugin 方法表可形成静态绑定；Native plugin 的对象/方法字符串与保守插件身份只能形成候选，必须由注册表或调用点证据晋级。
_Avoid_: 字符串共现、ACL 授权、运行时可达

**ubus 访问授权（ubus Access Grant）**：
rpcd ACL 对 object pattern 与 method 的 read/write 授权声明。它描述策略允许范围，不证明执行主体归属、认证结果、接口可达或漏洞存在。
_Avoid_: 后端绑定、认证绕过、可利用性
