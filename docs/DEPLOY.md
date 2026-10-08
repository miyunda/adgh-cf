# Linux 自动更新部署

更新：2026-10-08。本版本提供 `run --dry-run`、`run` 和 systemd 每小时任务。目标主机使用 systemd 已由用户确认；本文命令在目标 Linux 执行，开发 Mac 未运行 systemd 或连接真实 AdGuard Home。

## 工作方式

`probe` 仍不访问 AdGuard Home；`run` 才读取并管理配置域名的一条现有 IPv4 rewrite。首版不自动新增、删除规则，不处理重复规则、CNAME 或 IPv6 规则，也不启用被用户禁用的规则。

每次 `run` 读取规则并确认配置的 DNS 服务正在返回该地址，将当前 IP 固定加入 HTTPS 测试。候选正常需连续两轮胜出且 TTFB 中位数改善至少 15%，切换冷却 30 分钟。相隔不足五分钟的重复运行不增加确认次数，超过三小时的间隔或发现人工改动会重置连续胜出。当前地址不合格时可跳过改善门槛和冷却，但仍要求候选连续两轮胜出；这不是五分钟故障切换。

写前即时复验候选并重读规则。变更记录先原子写入状态文件，再调用 PUT；随后回读 API、直接向配置的 AdGuard Home 查询 A 记录，并通过该解析 IP 验证 HTTPS 健康接口。写入响应超时不会直接重试 PUT。若失败且旧地址健康、规则仍等于本程序的写入，则尝试恢复旧规则并验证。遇到无法确认的结果或人工改动，保留 pending 记录并停止；下一次运行先核对这笔变更。人工冲突需要检查状态和实际规则后处理，不能直接删除日志让程序再次写入。

API 没有原子 compare-and-swap；重读可缩小、不能消除人工修改的竞争窗口。这里验证的是指定 AdGuard Home 的 A 响应和健康接口，不等于所有客户端的 DNS 缓存、HTTPS/SVCB 或认证业务已验证。

`run --dry-run` 完成 API/DNS 读取、测速和拟变更判断，不写规则、不推进历史和确认次数。它可能写下载缓存、锁文件和指定报告。`run` 无需每次改变 DNS；没有明显改善或没有合格候选时保留现有规则。

## 配置与凭据

部署包中的 `config.run.example.json` 已启用名单来源、当前试用 IP 和旧可用 IP，使用 `/opt/adgh-cf` 的静态文件及 `/var/lib/adgh-cf` 的可写状态目录。示例中的地址必须按实际环境检查：

| 字段 | 含义 |
| --- | --- |
| `adguardHomeUrl` | API origin，例如 `http://192.168.1.1:3000`，不包含 `/control`、用户密码或查询参数 |
| `adguardHomeDns` | DNS 服务 IPv4 和端口，例如 `192.168.1.1:53`；本工具使用 DNS-over-TCP 核对 A 记录 |
| `stateFile` | 单目标的状态和未完成事务；不要让其他目标共用 |
| `confirmRuns` | 连续胜出次数，默认 2，允许 2–10 |
| `minImprovement` | 正常切换最低改善比例，默认 0.15 |
| `cooldownMinutes` | 正常切换冷却时间，默认 30 |
| `maxTtfbMs` | 任一成功样本超过此完整 TTFB 则本轮淘汰；0 禁用，自动部署示例为 1000ms |

初筛 TCP 失败的普通候选不入围；DNS 对照和固定地址仍做健康测试。成功率门槛已经不可能满足时提前停止；延迟超限也停止，报告中以 `eliminatedReason` 标注，保留实际样本，不把缺测伪装成失败。淘汰仅限本轮。

与 JSON 配置同目录的 `.env` 增加：

```dotenv
ADGH_USERNAME=admin
ADGH_PASSWORD="your-password"
ADGH_PASSWORD_FILE=
```

也可以将密码放在权限 0600 的独立文件，通过 `ADGH_PASSWORD_FILE` 指定（相对路径基于 JSON 配置目录），并把 `ADGH_PASSWORD` 留空；两种来源不能同时设置。用户名和密码不会进入 JSON 报告、状态或日志。原有 `CANDIDATE_PROXY_*` 继续仅用于名单下载；AdGuard API、DNS 和测速都直连。HTTP Basic Auth 用于用户现有家庭管理网络；已有 HTTPS 时可配置正常校验的 HTTPS 地址。

## 安装到固定目录

选择与 `uname -m` 对应的新版压缩包，解压进入目录。以下以常见提供 `useradd` 的发行版为例；服务账户不需要登录 shell：

```sh
getent passwd adgh-cf >/dev/null || sudo useradd --system --home-dir /var/lib/adgh-cf --shell /usr/sbin/nologin adgh-cf
sudo install -d -m 755 /opt/adgh-cf /opt/adgh-cf/candidates
sudo install -m 755 adgh-cf /opt/adgh-cf/adgh-cf
sudo install -m 644 candidates/*.txt /opt/adgh-cf/candidates/
sudo install -d -o root -g adgh-cf -m 750 /etc/adgh-cf
sudo install -d -o adgh-cf -g adgh-cf -m 700 /var/lib/adgh-cf
sudo test -f /etc/adgh-cf/config.json || sudo install -o root -g adgh-cf -m 640 config.run.example.json /etc/adgh-cf/config.json
sudo test -f /etc/adgh-cf/.env || sudo install -o adgh-cf -g adgh-cf -m 600 .env.example /etc/adgh-cf/.env
sudoedit /etc/adgh-cf/config.json /etc/adgh-cf/.env
```

填写实际 AdGuard API/DNS 地址、凭据和候选下载代理。现有部署目录中的 `.env` 不会自动迁移，需将已使用的代理配置填入 `/etc/adgh-cf/.env`。保留现有状态文件，升级不覆盖凭据或配置；如果在旧目录曾手动运行 `run`，迁移状态前先停 timer 并检查 pending，不要开启两套不同 stateFile 的任务。

## 先验证，再启用定时运行

先以实际服务账户运行：

```sh
sudo -u adgh-cf /opt/adgh-cf/adgh-cf run --dry-run --config /etc/adgh-cf/config.json --output /var/lib/adgh-cf/dry-run.json
```

检查报告中的 `currentIp` 是否为现有手动试用地址、代理来源是否可用、DNS 查询与 API 地址是否一致，以及拟变更原因。dry-run 不累计两轮确认；正式运行的第一次通常只记录观察。

```sh
sudo install -m 644 deploy/systemd/adgh-cf.service deploy/systemd/adgh-cf.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/adgh-cf.service /etc/systemd/system/adgh-cf.timer
sudo systemctl daemon-reload
sudo systemctl start adgh-cf.service
sudo journalctl -u adgh-cf.service -n 60 --no-pager
sudo systemctl enable --now adgh-cf.timer
systemctl list-timers adgh-cf.timer
```

开启 timer 意味着授权按配置自动更新该域名的现有 rewrite。任务每小时触发并随机延迟最多两分钟，错过的定时任务在恢复时补一次；机器无需常驻应用进程。service 最长 20 分钟，使用低权限专用账户、只写状态目录；手动和定时的 `run` 使用同一 stateFile 才能共享运行锁。

`/var/lib/adgh-cf/last-run.json` 为最近一次成功产出的完整报告，`optimizer.json` 保存最近 48 轮摘要（保留次数和中位数，不重复保存原始样本）、确认进度、切换时间和 pending。错误日志以 journald 为准：一次失败不会把旧完整报告自动改成最新报告。退出码 `0` 表示正常完成（包括保留现有地址），`1` 表示配置/API/DNS/写入验证等执行故障；`probe` 的无合格候选仍为 `2`。先不要放宽成功率门槛来掩盖家庭网络故障。

暂停自动运行：

```sh
sudo systemctl disable --now adgh-cf.timer
```

若 service 正在运行，停 timer 不会中断该次运行；可用 `systemctl status adgh-cf.service` 查看。恢复之前先检查规则、状态及日志。

## 验证边界

开发机通过 Go 本地模拟服务验证认证、精确更新、超时后核对、回滚、人工冲突、状态与锁、dry-run 和连续确认；使用本地 DNS-over-TCP 测试验证解析路径。Linux amd64/arm64 已交叉编译。真实路由器写入、systemd unit 的目标机校验、权限与定时触发仍需按上面的步骤在家庭 Linux 完成。本项目没有远程连接或安装到 PT 主机。

API 结构依据 [AdGuard Home 官方 OpenAPI](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)，调度依据 [systemd timer 官方文档](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)。
