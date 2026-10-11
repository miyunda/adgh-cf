# 版本、发布和升级

## 版本规则

首次版本为 **0.1.0**：项目已有完整可用功能，但自动切换、安装和升级仍需真实环境验证。`0.0.1` 更适合非常早期的原型；`1.0.0` 则意味着明确承诺稳定接口。遵循 [Semantic Versioning](https://semver.org/)，0.x 阶段修改配置或状态格式仍需在更新说明中明确提示。

版本唯一来源为根目录 `VERSION`，当前待发布版本为 **0.2.0**，对应 Git 标签为 `v0.2.0`。更新 VERSION、CHANGELOG.md 和 `docs/releases/v<版本>.md` 后发布；标签必须与 VERSION 一致，不能移动已经发布的标签。修复使用补丁版本，新增功能使用次版本；未来 1.0 再承诺兼容边界。`adgh-cf --version` 输出版本和提交，直接 `go run ./cmd/adgh-cf` 显示 dev，本地 Make 构建记录当前 HEAD 的提交号；该提交号不包含未提交修改，没有 Git 提交时才显示 commit unknown。

## GitHub Actions

- CI 对 `main` 的 push、所有 PR 和手动触发运行；功能分支和 Dependabot 分支通过 PR 验证，避免同一更新重复触发 push 与 PR CI。`main` 的 push 在全部检查通过后上传 Linux amd64/arm64 包和 SHA256，制品名称包含完整提交 SHA，保留 14 天；PR 和手动运行只验证构建，不上传。
- CI 使用 GitHub 托管 `ubuntu-24.04`，执行格式、vet、race 测试、发布边界检查和静态构建。amd64 可执行文件在 runner 上执行，arm64 为交叉编译产物，暂未进行原生 arm64 运行验证。
- 推送 `v*` 标签触发 Release，重新执行全部检查；验证标签、VERSION 和版本更新说明，生成两个架构包与 SHA256 文件，用 gh 创建 **草稿 Release**。检查附件和说明后人工发布，不自动部署到家庭网络。
- 包名为 `adgh-cf-v0.2.0-linux-amd64.tar.gz` / `arm64.tar.gz`，校验文件 `adgh-cf-v0.2.0-SHA256SUMS`。打包采用新建临时目录和明确文件范围，不把整个 checkout、旧构建目录或部署状态打包。
- 官方 checkout/setup-go/upload-artifact 固定到完整提交 SHA，Dependabot 每月提出更新；默认 token 只读，只有 tag Release job 获取 contents:write。工作流不使用 pull_request_target，不需要家庭代理、AdGuard 或 OpenBao 凭据。
- 构建 Go 固定为已验证的 1.27.1；最低源代码版本为 go.mod 中的 1.24。Go 和 Actions 的安全更新需持续检查，固定版本不代表可以永久不更新。当前不宣称 tar 包能逐字节复现；压缩包 SHA256 用于核对下载完整性，不替代可信发布来源或签名。

仓库默认分支为 `main`，当前分支保护要求通过 PR 合并且 `check` 成功、审查线程已解决，不要求额外审批。每次发布仍需核对本次提交的 CI 和 tag Release 工作流，不能使用早期版本的成功记录代替；Secret scanning/Push protection 按仓库可用功能配置。

建议发布顺序：

1. 对待提交 diff 做敏感信息复查，运行 make check/test；确认配置和状态不会进入 Git。
2. 将功能分支推送至已由用户确定的远程仓库，通过 PR 合并；不直接提交 main。
3. 确认默认分支 Linux CI 成功，再为对应提交创建 annotated tag 并推送该标签。
4. 检查草稿 Release、两种架构包、SHA256 与升级说明；在目标机 dry-run 后再正式发布。

工作流只创建草稿；重复同一标签的 Release job 不覆盖已存在 Release，需先检查现有草稿和失败日志。不要通过重新指向标签来“修复”已发布的二进制。

## 升级已有安装

升级保留 `/etc/adgh-cf/` 中的全部实际配置（例如 `config.json` 或 `config.groups.json`）、`.env`、密码文件，以及 `/var/lib/adgh-cf/` 的完整状态。不要用示例覆盖它们；已有 service override 也要保留。先阅读对应版本说明，确认是否涉及 unit、配置或状态迁移；不承诺老二进制能读取所有未来新状态。

以下以 v0.2.0 amd64 为例，在存有下载包和 SHA256 文件的临时目录操作：

```sh
sha256sum --ignore-missing --check adgh-cf-v0.2.0-SHA256SUMS
mkdir -p release-v0.2.0
tar -xzf adgh-cf-v0.2.0-linux-amd64.tar.gz -C release-v0.2.0
./release-v0.2.0/adgh-cf --version

# 查看基础 unit 与 override，确认当前生效的 ExecStart --config：
systemctl cat adgh-cf.service
# 以下以已启用的格式 2 配置为例；旧单域名安装改为 /etc/adgh-cf/config.json
adgh_config_path=/etc/adgh-cf/config.groups.json
sudo -u adgh-cf test -r "$adgh_config_path"
sudo systemctl stop adgh-cf.timer
systemctl is-active adgh-cf.service
```

`adgh_config_path` 必须与当前 service 最终生效的 `--config` 一致，不根据文件名猜测格式；文件存在不代表 service 正在使用它。以下命令在同一 shell 中继续执行。如果 service 正在运行，等待结束，不强制打断写入。升级前将现有二进制和状态备份到 root 私有目录；其中状态可能含 pending，先使用原配置处理未完成变更。配置/密码的备份也必须保持私有，不能放在源码仓库。备份目录与版本号应唯一，避免覆盖上一次备份。

```sh
sudo install -d -m 700 /var/backups/adgh-cf
adgh_backup_dir=$(sudo mktemp -d /var/backups/adgh-cf/before-v0.2.0.XXXXXX)
sudo cp /opt/adgh-cf/adgh-cf "$adgh_backup_dir/adgh-cf"
sudo cp -a /var/lib/adgh-cf "$adgh_backup_dir/state"
sudo cp -a /etc/adgh-cf "$adgh_backup_dir/config"
sudo install -m 755 release-v0.2.0/adgh-cf /opt/adgh-cf/adgh-cf.next
sudo mv /opt/adgh-cf/adgh-cf.next /opt/adgh-cf/adgh-cf

sudo -u adgh-cf /opt/adgh-cf/adgh-cf run --dry-run --config "$adgh_config_path" --output /var/lib/adgh-cf/dry-run.json
```

仅当本次升级说明要求更新 service/timer 时重新安装 unit、校验并 daemon-reload，保留新配置的 ExecStart override；更新后再用 `systemctl cat adgh-cf.service` 核对有效配置路径。仅当要求更新候选快照时更新 candidates。上述流程是沿用当前配置的二进制升级；另行启用格式 2 按 [多域名迁移指南](DOMAIN-GROUPS.md#从-v1-迁移和退回) 操作。确认 dry-run 正常、无未处理 pending 后恢复原先已启用的 timer：

```sh
sudo systemctl start adgh-cf.timer
systemctl list-timers adgh-cf.timer
```

验证失败保持 timer 停止，查看日志并决定是否恢复旧二进制。回滚二进制不等于回滚 DNS；如果程序已经变更实际规则，不能盲目恢复旧状态备份。升级备份不自动清理，不要把逐版备份变成无限累积；确认稳定后按自己的保留策略清理。

GitHub 无法从 PT 主机直连时，在其他电脑下载并传输，或使用明确提供的代理下载；不要让升级过程改变测速的直连路径。当前不提供自动自更新。
