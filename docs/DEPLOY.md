# Linux 自动更新部署

更新：2026-10-11。本版本提供 `run --dry-run`、`run` 和 systemd 每小时任务。本文命令在目标 Linux 执行；开发 Mac 只运行本地模拟服务。家庭实测已取得正常切换和 FreshRSS 客户端验证记录，故障恢复真机实测延期，详见 [STATUS.md](STATUS.md)。

## 目录与模板选择

固定目录安装统一使用以下分工；配置文件名可自行选择，手动命令与 service 的 `--config` 必须指向同一份实际配置。

| 目录 | 内容 |
| --- | --- |
| `/etc/adgh-cf/` | JSON 配置、`.env`；旧配置通常为 `config.json`，多域名配置通常为 `config.groups.json` |
| `/opt/adgh-cf/` | `adgh-cf` 二进制和 `candidates/` 静态文件 |
| `/var/lib/adgh-cf/` | 状态、下载缓存、报告；旧状态为 `optimizer.json`，新格式独立使用 `optimizer-v2.json` |

| 配置模板 | 格式与用途 | 使用位置 |
| --- | --- | --- |
| `config.https.example.json` | 格式 2，普通网站最小配置，默认 `https` | 解压目录，候选路径相对配置目录 |
| `config.groups.example.json` | 格式 2，多域名只读起点 | 解压目录，候选路径相对配置目录 |
| `config.groups.run.example.json` | 格式 2，固定目录自动更新；需填写成员、管理地址和凭据 | 安装为 `/etc/adgh-cf/config.groups.json`，模板已使用绝对路径 |
| `config.run.example.json` | 格式 1，旧单域名 OpenBao 自动更新 | 安装为 `/etc/adgh-cf/config.json`，模板已使用绝对路径 |
| `config.example.json`、`config.proxy.example.json`、`config.pt.example.json`、`config.http.example.json` | 格式 1，旧单域名配置；前三项默认 OpenBao，最后一项为严格 HTTP | 解压目录，候选路径相对配置目录 |

源码仓库的模板在 `examples/`，发布包把模板放在解压目录根部。只读模板只有候选和检查配置，不能直接用于 `run`；需补充 `adguardHomeUrl`、`adguardHomeDns` 及 `.env` 凭据。

JSON 中的相对文件路径以及 `ADGH_PASSWORD_FILE` 都基于 **JSON 配置所在目录**，与二进制位置、当前工作目录和 systemd `WorkingDirectory` 无关。`.env` 固定从 JSON 同目录读取；例如使用 `/etc/adgh-cf/config.groups.json` 时读取 `/etc/adgh-cf/.env`。`--output` 是命令行路径，相对路径基于当前工作目录；固定目录部署一律使用绝对路径。

例如，将包含 `"candidateFile": "candidates/cloudflare-ipv4.txt"` 的只读模板复制进 `/etc/adgh-cf/`，程序就会查找 `/etc/adgh-cf/candidates/cloudflare-ipv4.txt`。固定目录模板的值为 `/opt/adgh-cf/candidates/cloudflare-ipv4.txt`，无需在 `/etc` 再复制候选文件。

## v2 多域名部署

多域名配置、报告和迁移见 [DOMAIN-GROUPS.md](DOMAIN-GROUPS.md)。下文单域名行为说明针对 v1；v2 保留独立组状态，所有切换（含组内对齐）均受冷却约束。不要让多个配置/状态文件同时管理相同域名。

v2 正常运行默认上限 1800 秒，恢复最多再用 120 秒。新 service 模板 `TimeoutStartSec=125min` 可覆盖 maxRunSeconds 允许的最高 7200 秒及恢复余量，`TimeoutStopSec=130s` 给取消后的恢复留出时间。已有安装需手动更新 unit 并执行 daemon-reload；也可按实际 maxRunSeconds + 至少 120 秒配置更短的启动超时。

## 旧单域名配置（格式 1）的工作方式

`probe` 仍不访问 AdGuard Home；`run` 才读取并管理配置域名的一条现有 IPv4 rewrite。首版不自动新增、删除规则，不处理重复规则、CNAME 或 IPv6 规则，也不启用被用户禁用的规则。

每次 `run` 读取规则并确认配置的 DNS 服务正在返回该地址，将当前 IP 固定加入 HTTPS 测试。候选正常需连续两轮胜出且 TTFB 中位数改善至少 15%，切换冷却 30 分钟。相隔不足五分钟的重复运行不增加确认次数，超过三小时的间隔或发现人工改动会重置连续胜出。当前地址不合格时可跳过改善门槛和冷却，但仍要求候选连续两轮胜出；这不是五分钟故障切换。

写前即时复验候选并重读规则。变更记录先原子写入状态文件，再调用 PUT；随后回读 API、直接向配置的 AdGuard Home 查询 A 记录，并通过该解析 IP 验证 HTTPS 健康接口。写入响应超时不会直接重试 PUT。若失败且旧地址健康、规则仍等于本程序的写入，则尝试恢复旧规则并验证。遇到无法确认的结果或人工改动，保留 pending 记录并停止；下一次运行先核对这笔变更。人工冲突需要检查状态和实际规则后处理，不能直接删除日志让程序再次写入。

API 没有原子 compare-and-swap；重读可缩小、不能消除人工修改的竞争窗口。这里验证的是指定 AdGuard Home 的 A 响应和健康接口，不等于所有客户端的 DNS 缓存、HTTPS/SVCB 或认证业务已验证。

`run --dry-run` 完成 API/DNS 读取、测速和拟变更判断，不写规则、不推进历史和确认次数。它可能写下载缓存、锁文件和指定报告。`run` 无需每次改变 DNS；没有明显改善或没有合格候选时保留现有规则。

## 旧配置参数与通用凭据

部署包中的旧格式 `config.run.example.json` 已启用名单来源，`pinnedIps` 为历史实测地址示例，不能当作当前最佳地址。新格式 `config.groups.run.example.json` 默认 `candidateSources: []`，不下载名单；两者均使用 `/opt/adgh-cf` 的静态文件及 `/var/lib/adgh-cf` 的可写目录。示例中的域名、IP 和管理地址必须按实际环境检查：

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

## 安装旧单域名配置到固定目录

以下命令安装格式 1 的 `config.json`。已有此安装并启用格式 2 时，按 [多域名安装步骤](DOMAIN-GROUPS.md#已安装到-opt-的运行与定时任务) 新建 `config.groups.json` 和 service override；全新安装也可先完成下面的账户、目录和 unit 安装，再按该指南切换配置，验证后启用 timer。

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

## 旧配置先验证，再启用定时运行

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

开启 timer 意味着授权按配置自动更新该域名的现有 rewrite。任务每小时触发并随机延迟最多两分钟，错过的定时任务在恢复时补一次；机器无需常驻应用进程。新 service 模板最长 125 分钟（程序 v2 默认正常阶段仍为 30 分钟），使用低权限专用账户、只写状态目录；手动和定时的 `run` 使用同一 stateFile 才能共享运行锁。

`/var/lib/adgh-cf/last-run.json` 是最近一次成功写出的报告，报告本身可能记录失败。格式 1 的部分早期错误不产出新报告，格式 2 通常会保存带 `overallStatus`、`error` 的失败报告；若配置加载、输出路径检查或报告写入本身失败，也可能保留旧文件。排障时同时核对本次命令输出、报告内容和 journal，不能仅凭文件存在认定本次运行成功。

格式 1 的 `optimizer.json` 保存最近 48 轮测量摘要、确认进度、切换时间和 pending；格式 2 的 `optimizer-v2.json` 按组保留最近 48 轮决定摘要及组事务，不保存原始样本。退出码 `0` 表示正常完成（包括等待确认或保留地址），`1` 表示执行故障；`probe` 无合格候选为 `2`，格式 2 的 `run`/dry-run 无共享候选或预算耗尽也为 `2`。先不要放宽成功率门槛来掩盖家庭网络故障。

`--output` 将完整 JSON 保存至报告。格式 1 的 `run` 摘要包含当前/建议/拟切换地址、确认次数、原因和 `action`；是否实际切换看报告 `optimizer.action`，`optimizer.nextIp` 只是拟切换地址。格式 2 的 `probe`/`run` 输出 `Groups …: status=… groups=…; report=…`，逐组的原因、确认次数和实际动作查看报告 `groups[].status`、`groups[].transaction.outcome`。等待确认时总体 `complete` 不表示已经切换，dry-run 不写 DNS。详细样本与淘汰原因查看报告：

```sh
sudo less /var/lib/adgh-cf/last-run.json
sudo journalctl -u adgh-cf.service --since "30 minutes ago" --no-pager
```

需要临时查看每个样本的进度时，在手动 `probe` 或 `run --dry-run` 命令中添加 `--verbose`。此选项不会把文件中的 JSON 重新输出到 journal。未指定 `--output` 的手动命令仍向 stdout 输出 JSON。升级不会删除旧 journal 历史，也不会改变主机全局日志轮转；已发布的 0.1.0 仍使用原来的详细日志行为。

暂停自动运行：

```sh
sudo systemctl disable --now adgh-cf.timer
```

若 service 正在运行，停 timer 不会中断该次运行；可用 `systemctl status adgh-cf.service` 查看。恢复之前先检查规则、状态及日志。

## 验证边界

开发机通过 Go 本地模拟服务验证认证、精确更新、超时后核对、回滚、人工冲突、状态与锁、dry-run 和连续确认；使用本地 DNS-over-TCP 测试验证解析路径。Linux amd64/arm64 已交叉编译，arm64 未原生运行验证。用户已在家庭 Linux 运行 service，验证真实组内对齐写入、AdGuard Web 规则和 FreshRSS 登录功能；故障恢复真机实测延期，其他成员认证业务、重启恢复等仍待验收，详见 [STATUS.md](STATUS.md)。这些实测来自用户报告，开发机未远程连接或操作 PT 主机。

API 结构依据 [AdGuard Home 官方 OpenAPI](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)，调度依据 [systemd timer 官方文档](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)。
