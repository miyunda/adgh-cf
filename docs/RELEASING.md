# 版本、发布和升级

## 版本规则

首次版本建议为 **0.1.0**：项目已有完整可用功能，但自动切换、安装和升级仍需真实环境验证。`0.0.1` 更适合非常早期的原型；`1.0.0` 则意味着明确承诺稳定接口。遵循 [Semantic Versioning](https://semver.org/)，0.x 阶段修改配置或状态格式仍需在更新说明中明确提示。

版本唯一来源为根目录 `VERSION`，Git 标签为 `v0.1.0`。更新 VERSION、CHANGELOG.md 和 `docs/releases/v<版本>.md` 后发布；标签必须与 VERSION 一致，不能移动已经发布的标签。修复使用补丁版本，新增功能使用次版本；未来 1.0 再承诺兼容边界。`adgh-cf --version` 输出版本和提交，直接 go run 显示 dev，未提交的本地 Make 构建显示 commit unknown。

## GitHub Actions

- CI 使用 GitHub 托管 `ubuntu-24.04`，执行格式、vet、race 测试、发布边界检查和静态构建。amd64 可执行文件在 runner 上执行，arm64 为交叉编译产物，暂未进行原生 arm64 运行验证。
- 推送 `v*` 标签触发 Release，重新执行全部检查；验证标签、VERSION 和版本更新说明，生成两个架构包与 SHA256 文件，用 gh 创建 **草稿 Release**。检查附件和说明后人工发布，不自动部署到家庭网络。
- 包名为 `adgh-cf-v0.1.0-linux-amd64.tar.gz` / `arm64.tar.gz`，校验文件 `adgh-cf-v0.1.0-SHA256SUMS`。打包采用新建临时目录和明确文件范围，不把整个 checkout、旧构建目录或部署状态打包。
- 官方 checkout/setup-go 固定到完整提交 SHA，Dependabot 每月提出更新；默认 token 只读，只有 tag Release job 获取 contents:write。工作流不使用 pull_request_target，不需要家庭代理、AdGuard 或 OpenBao 凭据。
- 构建 Go 固定为已验证的 1.27.1；最低源代码版本为 go.mod 中的 1.24。Go 和 Actions 的安全更新需持续检查，固定版本不代表可以永久不更新。当前不宣称 tar 包能逐字节复现；压缩包 SHA256 用于核对下载完整性，不替代可信发布来源或签名。

源码尚未推送 GitHub，因此工作流尚未在真实 Actions 中运行；本地验证不能替代第一轮 Linux runner 验收。仓库建立后启用 Secret scanning/Push protection（按仓库可用功能）、保护默认分支，要求 CI 通过；限制谁能推送发布标签。若设置分支规则要求 PR，启用前先确认单人维护时的操作路径，不加入多余审批。

建议发布顺序：

1. 对待提交 diff 做敏感信息复查，运行 make check/test；确认配置和状态不会进入 Git。
2. 将功能分支推送至已由用户确定的远程仓库，通过 PR 合并；不直接提交 main。
3. 确认默认分支 Linux CI 成功，再为对应提交创建 annotated tag 并推送该标签。
4. 检查草稿 Release、两种架构包、SHA256 与升级说明；在目标机 dry-run 后再正式发布。

工作流只创建草稿；重复同一标签的 Release job 不覆盖已存在 Release，需先检查现有草稿和失败日志。不要通过重新指向标签来“修复”已发布的二进制。

## 升级已有安装

升级保留 `/etc/adgh-cf/config.json`、`.env`、密码文件和 `/var/lib/adgh-cf` 的完整状态。不要用示例配置覆盖它们。先阅读对应版本说明，确认是否涉及 unit、配置或状态迁移；不承诺老二进制能读取所有未来新状态。

以下以 v0.1.0 amd64 为例，在存有下载包和 SHA256 文件的临时目录操作：

```sh
sha256sum --ignore-missing --check adgh-cf-v0.1.0-SHA256SUMS
mkdir -p release-v0.1.0
tar -xzf adgh-cf-v0.1.0-linux-amd64.tar.gz -C release-v0.1.0
./release-v0.1.0/adgh-cf --version

sudo systemctl stop adgh-cf.timer
systemctl is-active adgh-cf.service
```

如果 service 正在运行，等待结束再继续，不强制打断写入。升级前将现有二进制和状态备份到 root 私有目录；其中状态可能含 pending，先检查是否有未完成变更。配置/密码的备份也必须保持私有，不能放在源码仓库。备份目录与版本号应唯一，避免覆盖上一次备份。

```sh
sudo install -d -m 700 /var/backups/adgh-cf
sudo cp /opt/adgh-cf/adgh-cf /var/backups/adgh-cf/adgh-cf-before-v0.1.0
sudo cp -a /var/lib/adgh-cf /var/backups/adgh-cf/state-before-v0.1.0
sudo install -m 755 release-v0.1.0/adgh-cf /opt/adgh-cf/adgh-cf.next
sudo mv /opt/adgh-cf/adgh-cf.next /opt/adgh-cf/adgh-cf

sudo -u adgh-cf /opt/adgh-cf/adgh-cf run --dry-run --config /etc/adgh-cf/config.json --output /var/lib/adgh-cf/dry-run.json
```

仅当本次升级说明要求更新 service/timer 时重新安装 unit、校验并 daemon-reload；仅当要求更新候选快照时更新 candidates。确认 dry-run 正常、无未处理 pending 后恢复原先已启用的 timer：

```sh
sudo systemctl start adgh-cf.timer
systemctl list-timers adgh-cf.timer
```

验证失败保持 timer 停止，查看日志并决定是否恢复旧二进制。回滚二进制不等于回滚 DNS；如果程序已经变更实际规则，不能盲目恢复旧状态备份。升级备份不自动清理，不要把逐版备份变成无限累积；确认稳定后按自己的保留策略清理。

GitHub 无法从 PT 主机直连时，在其他电脑下载并传输，或使用明确提供的代理下载；不要让升级过程改变测速的直连路径。当前不提供自动自更新。
