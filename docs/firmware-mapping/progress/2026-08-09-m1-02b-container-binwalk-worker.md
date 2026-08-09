# M1-02B：生产容器 Binwalk Worker 与真实原始固件回放

> 工作项：M1-02B
> 日期：2026-08-09
> 状态：进行中
> 部署：不适用；通信测绘专项按用户明确范围不执行 SSH 部署

## 1. 本轮出口

M1-02A 只冻结了 `FirmwareExtractor`/`ExtractionWorker` 合同。本轮新增
`ContainerBinwalkWorker`，使下列声明变成实际容器启动参数，而不再只是
fake worker 的返回值：

- 镜像必须使用 `sha256:` 内容身份，拒绝 `latest` 等可变 tag；
- `--network none`、只读容器根和只读固件输入；
- `cap-drop=ALL`、`no-new-privileges`、PID/CPU/内存限制；
- 输出目录是唯一普通可写 bind mount，`/tmp` 是受限 tmpfs；
- wall time、输出文件数、输出字节和日志字节均有上限；
- 保留逻辑 `binwalk -Me /input/firmware.bin` 与工具/镜像身份，但序列化结果不泄露原始日志和宿主启动命令。

固定构建配方见 [`containers/binwalk/Dockerfile`](../../../containers/binwalk/Dockerfile)。
它绑定 Ubuntu 镜像摘要、Binwalk v3.1.0 源码提交、Rust 工具链、Cargo
锁文件、sasquatch 与 Python 文件系统提取器版本。

## 2. TDD 冻结的失败语义

本轮新增/扩展的合同覆盖：

1. 镜像未固定时构造即失败；
2. probe 卡死被转换为 `extraction.tool_unavailable`，不向调用方泄漏
   `TimeoutExpired`；
3. wall-time 超限终止 worker 并保留部分派生清单；
4. 快速退出也不能绕过最终文件数/字节复核；
5. 日志只保留有界摘要，并在执行证据与指纹中记录截断状态；
6. Binwalk 返回 0 但没有任何派生文件时返回
   `failed + extraction.no_output`，不再产生空成功；
7. 工具版本 probe 与正式解包共享日志预算，日志洪泛会终止整个进程组，
   快速退出后仍执行最终字节复核。

相关 Extraction/Container 合同当前为 19 项。

## 3. 工具链实证

本机 Docker Desktop 为 ARM64。基于 ReFirmLabs v3.1.0 固定提交
`4fdab3d464d97b68e0af9088df3f9e2e1545b21c` 构建了本地验证镜像：

```text
ToolIdentity(
  name="binwalk",
  version="3.1.0",
  image_digest="sha256:a22e83ed3465eea9a009a33b01a68233253dc420bcad2b791a48c80444f0880a"
)
```

该摘要只证明本机 ARM64 验证镜像。正式发布仍以仓库 Dockerfile 重新构建
并记录的新摘要为准，不能把本地临时基础层冒充发布工具链。

## 4. 两个真实原始固件结果

机器可读记录见 [M1-02B real replay summary](../samples/m1-02b-binwalk-real-replay-summary.json)。

### 4.1 D-Link DIR-882 1.10B02：负向结果

- Artifact SHA-256：`33ec7f190b590f95f922cb361098e5ce0cda4af0c093be62d58046106b6ddfac`；
- Binwalk 进程返回 0，但没有识别出可派生产物；
- 当前结果：`failed + extraction.no_output`，观察文件数为 0；
- 价值：证明“命令成功”与“固件成功解包”是两个不同状态。

### 4.2 D-Link DAP-3520 A1 1.17-rc047：正向、部分覆盖

- Artifact SHA-256：`0de4c72f3d7ba1dc6419328be355b51e39d1dae0a8ad14918f0e4eb4699499f9`；
- 恢复 LZMA 与 SquashFS 3.0，Inventory 为 757/757 条、18,911,673
  已处理字节；
- 其中 rootfs 有 636 个普通文件、374 个 PHP 文件和 118 个符号链接；
- Extraction 未超时、退出码为 0，Inventory SHA-256 为
  `e6b0cfd9e5fed74302986e179ea23de8d9817198c2b361ee946a90e501e91334`；
- coverage 为 `partial`，唯一诊断族是 `inventory.symlink_escape`：15 个
  绝对固件符号链接被记录但没有跟随到宿主路径。

## 5. 通信架构中间解释

`etc/templates/httpd/httpd.php:101` 附近给出明确服务器侧绑定：

```text
Alias /HNAP1
Location /www/HNAP1
External { /usr/sbin/hnap { hnap } }
IndexNames { index.hnap }
```

普通管理页则使用另一条链：页面 POST 的 `ACTION_POST` 进入共享
`/www/__action.php`，再通过固件 PHP/XGI 的 `query()/set()` 状态树与提交
动作读写配置。因此当前最准确的架构假设是：

`hybrid_hnap_dispatcher_plus_php_xgi_page_controllers`。

M1-11A 已将该假设结构化为 proprietary httpd/PHP-XGI Producer 结果并送入
Discovery Catalog；这仍不是从 `/HNAP1` 路径风格直接断言后端同源。Catalog
继承本轮 Inventory 的 partial coverage，因此没有把局部 Producer 成功抬高为
整机 verified。

## 6. 为什么仍是进行中

> M1-13 后续勘误：本记录中的 `inventory.symlink_escape` 是 v1alpha1 在当时
> 对固件绝对链接采取的保守解释。v1alpha2 将 `/...` 解释为选定固件根内路径，
> 并把未物化 `/dev/*` 记录为运行时设备目标。DAP-3520 选定 rootfs 的新重放为
> completed；详情见 [M1-13 记录](./2026-08-09-m1-13-chroot-symlink-inventory.md)。

- 仓库固定 Dockerfile 尚未在正确配置全局代理的 Docker daemon 上完成
  独立重建与摘要复核；当前成功的是等价源码提交的本地 ARM64 验证镜像；
- DAP-3520 的 v1alpha1 symlink 缺口已由 M1-13 关闭；HNAP/XGI 绑定现在进入
  completed Catalog，`hnap_soap` 已晋级 `verified`；

## 7. 下一步

1. 重建仓库正式镜像并记录发布摘要，然后再评估 M1-02B 是否可标记已验证。
