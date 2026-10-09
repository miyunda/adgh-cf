# 更新记录

## 0.1.1 — 待发布

- `run --output` 仅输出优化摘要，完整 JSON 保留在文件，减少 systemd journal 重复日志；`probe --output` 同样不重复输出 JSON。不带 `--output` 时保留 stdout JSON。
- `probe`、`run` 默认输出测速汇总；逐样本与淘汰进度改为显式 `--verbose`，完整报告仍保留所有细节。候选源状态、DNS 对照错误与执行错误仍可查看。

## 0.1.0

- IPv4 TCP/HTTPS 优选、OpenBao 健康检查和提前淘汰。
- 公共候选源、专用下载代理、独立缓存和离线快照。
- AdGuard Home 现有 IPv4 rewrite 的 dry-run、连续确认、写后验证和条件回滚。
- 状态、运行锁、systemd 每小时调度模板。
- 版本查询、Linux amd64/arm64 包、SHA256 校验及 GitHub Actions 草稿发布。
- 通用 HTTP 健康检查（状态码与响应标记），默认保持 OpenBao/Vault 兼容。
- MIT 许可证。
- 候选缓存采用有界读取；原子写入后同步父目录，加强 DNS 变更恢复记录的断电持久性。

未承诺配置和状态格式长期稳定。真实业务切换需在目标家庭网络验收；此版本不是 1.0 稳定版。
