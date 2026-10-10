# 仓库与运行安全

## 公开边界

只发布源码、测试、通用配置示例、公共候选快照和文档。真实域名、家庭地址、个人绝对路径、原始报告和本地部署配置不用于公开示例。已有个人记录保留在被 Git 忽略的 local-notes，不随 Release 发布。

`.gitignore` 排除 .env、实际 config*.json（保留 *.example.json）、密钥、密码文件、日志、状态、报告、构建产物及 macOS 文件。忽略规则无法保护已经跟踪或使用 git add -f 强行加入的文件。自定义凭据文件统一放在 secrets/ 或仓库外；不要相信任意文件名都会自动被忽略。

make check 中的 scripts/check-repo.sh 检查文件边界、空白 examples/.env.example 和常见密钥/token/个人路径，同时检查 Git index 中的常见敏感标记。它是启发式检查，不识别所有密码或编码形式，不能保证“扫描通过即无秘密”。首次提交、每次发布都需查看 `git diff --cached` 和完整文件清单；配置示例只能写占位内容。GitHub Secret scanning/Push protection 可作为额外保护，不能替代本地审查。

目前工作流不需要配置任何家庭凭据，也不通过 CI 连接家庭网络。即使添加 GitHub Actions Secrets，也不能把真实密码写入 YAML、日志或制品。若秘密进入 Git 或 CI 日志，先撤销/轮换凭据，再处理日志或历史；仅删除当前文件不会从历史移除秘密。

## 运行边界

使用低权限专用账户，`.env` 和密码文件权限 0600。候选下载代理独立于测速、AdGuard API 和 DNS；不禁用 TLS 验证。HTTP Basic Auth 只用于用户明确采用的家庭管理网络，有正常 HTTPS 接口时优先使用 HTTPS。

公共名单是未经信任的输入：限制大小和超时，只接受官方网段内的 IPv4，经过目标域名证书和 OpenBao 健康检查后再参与排名。名单的新旧、地区标签或公益维护者排名都不能直接触发 DNS 更新。

程序仅更新配置域名的一条已有启用 IPv4 规则；多规则、CNAME 或 disabled 状态停止。API 无原子 compare-and-swap，仍存在并发修改窗口；自动更新时避免其他程序同时维护同一域名。pending 状态需要核对实际规则后处理，不可直接删除后重跑。

软件供应链使用固定 Action SHA、最小 token 权限和 SHA256。SHA256 只能核对制品与校验文件的一致性，不能单独证明制品来源；从可信 GitHub Release 获取，并检查版本和发布说明。后续可按需求增加制品 provenance/签名，目前未实现。

## 日志与容量

依赖主机 journald/rsyslog 的现有轮转，不另建无限追加的应用日志。报告同名替换，optimizer 状态最多 48 轮摘要，下载缓存按源替换。公开仓库不包含原始主机日志。

用户目标机已报告 dry-run 正常、timer 启用；journal 约 440MB，根分区可用约 24GB，syslog 每周轮转保留四份并压缩。现阶段无需项目专属 logrotate；主机配置属于用户环境，未由程序修改。已发布的 0.1.0 仍将完整 JSON 同时输出 journal；后续日志精简改动使 `run --output` 只输出简洁摘要，完整报告保留在指定文件。`probe`、`run` 默认不逐条打印样本，`--verbose` 可临时开启样本进度；原始样本仍在报告中。未指定 `--output` 时 stdout 保持完整 JSON。
