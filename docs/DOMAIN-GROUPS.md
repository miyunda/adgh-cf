# 多域名配置、迁移与验收

本文的 v1/v2 指配置、状态和报告的格式版本（整数 1/2），不是软件发布版本。软件版本仍使用 `v0.2.0` 这样的格式，由 `VERSION` 管理；一次软件发布可以同时支持两种配置格式。下文“迁移到 v2”表示迁移到配置格式第 2 版，不表示升级到软件 v2.0.0。

2026-10-10：v2 已在本地实现并提供模拟测试；目标家庭 Linux 的多域名 probe、dry-run、实际更新、DNS 与客户端访问仍待验收。不得把交叉编译或模拟服务结果当作公网试用记录。

## 配置与命令（部署包中的运行步骤）

以下在家庭 Linux 的 v0.2.0 部署包解压目录执行，目录内应有 `adgh-cf`、配置模板和 `candidates/`。先运行 `./adgh-cf --version` 确认显示 0.2.0。目标 Linux 无需 Go 或其他开发运行时。

### 普通网站：默认模式

```sh
test -f config.https.json || cp config.https.example.json config.https.json
```

编辑 `config.https.json`，替换 primary、domain、url。例如下面是完整最小配置；域名必须是实际由 Cloudflare CDN 服务的网站，例中的 www.example.com 只是占位符：

```json
{
  "schemaVersion": 2,
  "candidateFile": "candidates/cloudflare-ipv4.txt",
  "cloudflareRangesFile": "candidates/cloudflare-ipv4.txt",
  "stateFile": "state/optimizer-v2.json",
  "groups": [
    {
      "id": "website",
      "primary": "www.example.com",
      "members": [
        {"domain": "www.example.com", "url": "https://www.example.com/"}
      ]
    }
  ]
}
```

一个组允许只有一个成员。省略 mode 的默认值为 **https**，即普通网页检查；这就是新配置的通用默认，不自动检查 OpenBao JSON。

```sh
./adgh-cf probe --config config.https.json --output reports/website-probe.json
```

### OpenBao：显式指定模式

在上述完整配置中修改 primary 与成员域名，并将成员写成：

```json
{"domain":"bao.example.com","url":"https://bao.example.com/v1/sys/health","mode":"openbao"}
```

仅填写 `/v1/sys/health` URL 不会自动启用 OpenBao 模式。模式是用户指定的判断规则，不按路径自动识别。沿用旧配置则继续使用原命令和旧默认。

### 多域名与组筛选

```sh
test -f config.groups.json || cp config.groups.example.json config.groups.json
# 编辑 primary 和全部成员；删除不使用的占位成员，保留实际模式
./adgh-cf probe --config config.groups.json --output reports/groups-probe.json
./adgh-cf probe --config config.groups.json --group personal-sites
```

默认运行全部组；`--group` 后填写配置中的 id。共享候选 IP 的网站放同一组，需要各自独立选址的网站放不同组。

路径相对配置文件目录，`--output` 相对当前工作目录。`stateFile` 必须显式填写独立的新路径；probe 不读取该状态文件。仓库开发运行先 `make build`，用 `./build/adgh-cf`，并从 `examples/` 复制示例到源码根目录；部署包内示例已经在根目录，使用 `./adgh-cf`。

最多 4 组、总计 16 个域名、每组 8 个成员。组 ID 唯一且稳定，primary 必须属于成员；域名跨组不得重复，大小写和末尾单个点会规范化。URL 仅允许同域名 HTTPS 443，不接受用户名密码、fragment 或控制字符；查询参数不得放秘密。整份配置始终校验，`--group` 不能绕过无效的其他组。refresh/export 不接受 `--group`。

| 成员 mode | 判断与限制 |
| --- | --- |
| 省略或 `https` | 正常 TLS、最终 2xx、无 `Cf-Mitigated: challenge`；只证明基本 HTTPS 响应可用，200 登录页或未知挑战不一定可识别 |
| `http` | 显式 1–5 个预期 2xx 状态码；可选非空内容标记，仅检查响应前缀 |
| `openbao` | 完整 JSON、Content-Type、initialized/sealed/standby；响应超限失败，不验证认证业务或 standby 转发 |

HTTPS/HTTP 只读取 `maxResponseBytes` 前缀；到达边界后关闭响应，报告 `bodyTruncated`（未知长度在读满前缀时保守标记）。网络在达到边界前中断仍失败。只跟随最多 3 次同源 HTTPS 跳转，每跳使用新连接、保留 Host/SNI、固定候选 IP，并共享单次探测超时。跨域、HTTP 降级、端口变化、循环或无效 Location 失败，需配置最终 URL。OpenBao 和 v1 不跟随跳转。

## 选择与预算

候选每次执行加载一次，各组串行独立排名。只有 primary 的排名代表性能；最多检查前 3 个合格地址，每个成员在同一地址上连续两次检查都通过，才产生组建议。没有共享候选就保留整组。run 会分别读取成员原规则、核对 AdGuard DNS 和复测当前地址，主域名当前 IP 必须参加完整排名。

正常切换保留连续确认、最短 5 分钟间隔、最多 3 小时确认间隔、改善门槛和冷却。主域名当前地址已是共享候选但组员不同，会报告“group alignment”，仍需确认、冷却及写前复验，不声称性能改善。配置指纹或人工规则变化重置确认，保留已有冷却。组 ID 应保持稳定。

`maxRequestsPerGroup` 默认 160，允许 1–1000；每个跳转请求计一次。报告包含 `budget.limit/estimated/used/exhausted`。预估为实际主域名入围数 × samplesPerIp + 当前检查 + 最多 3×成员数×2 复验 + 写前检查；跳转另计。预算不足停止，不将未完成测量算作确认。

`maxRunSeconds` 默认 1800，允许 60–7200，覆盖下载和正常测量。已开始写入后的核对与恢复单独使用累计最多 120 秒；每个成员最多检查新/旧地址各一次，每次最多 4 个 HTTP 请求。`recoveryRequests` 单独计数。恢复仍无法完成就保留 pending。

报告 `primarySuggestion` 是主域名第一名，`suggestedIp` 是全组通过的建议，`nextIp` 是满足确认和冷却后的拟写入值；实际结果看 `status` 和 `transaction.outcome`。恢复报告包含各成员 old/next/actual、progress 和错误，不包含响应正文、Cookie 或完整 Location。退出码：正常完成 0（包括等待确认或无需变更），没有共享候选或预算耗尽 2，配置/IO/API/写入/恢复错误 1；错误优先于无候选。

## 自动更新与恢复

run/dry-run 需在配置顶层加入实际管理地址（以下字段片段不能单独作为完整配置）：

```json
"adguardHomeUrl": "http://192.168.1.1:3000",
"adguardHomeDns": "192.168.1.1:53"
```

配置同目录 `.env` 填写 `ADGH_USERNAME` 与 `ADGH_PASSWORD`，或 `ADGH_PASSWORD_FILE`，沿用 [DEPLOY.md](DEPLOY.md)。普通 probe 不要求这些管理字段或凭据。所有成员必须各有一条现有、启用的公网 IPv4 rewrite，且指定 AdGuard DNS 返回该地址；不会新增、删除、启用规则或处理 CNAME。所有组共用一个 AdGuard 实例。

```sh
./adgh-cf run --dry-run --config config.groups.json --output reports/groups-dry-run.json
# 核对全部域名、原 IP、预期共享 IP、模式和预算后，在目标主机手动运行：
./adgh-cf run --config config.groups.json --output reports/groups-run.json
```

多条 rewrite 不具有原子性。第一条更新前持久保存整组 pending；每条写前重读、写后回读并保存进度。响应丢失时按实际规则判断，不重复 PUT。全组完成后逐条回读、查询 AdGuard DNS，再通过解析返回的 IP 执行 HTTPS 验证，记录实际连接 IP。

任一失败停止继续更新，按逆序条件补偿：规则仍为本次 next 且旧 IP 即时健康才恢复 old，人工修改不覆盖。无法完成则 `recovery-required`，pending 保留并阻止所有组的新更新。下次即使指定其他 `--group`，也先恢复未完成事务，恢复完成后结束本次 run；下一次才重新测速。dry-run 只显示 pending，不修改 DNS/状态，不推进确认，存在 pending 时退出 1。

有 pending 时必须使用原配置恢复；不能改 URL、模式、成员或后台身份来跳过。检查 API/DNS/旧地址可达性和人工修改后处理，不要直接删除状态。不同 stateFile 的锁彼此独立，**禁止多份任务接管同一域名**。API 没有原子 compare-and-swap，逐条重读只能缩小并发人工修改的窗口。

## 已安装到 /opt 的运行与定时任务

沿用已验证的旧 OpenBao 配置，可以继续执行：

```sh
sudo -u adgh-cf /opt/adgh-cf/adgh-cf run --dry-run --config /etc/adgh-cf/config.json --output /var/lib/adgh-cf/dry-run.json
```

固定目录部署的分工是：`/etc/adgh-cf/` 放 JSON 配置与 `.env`，`/opt/adgh-cf/` 放程序和静态候选文件，`/var/lib/adgh-cf/` 放状态、缓存和报告。

**不要直接将解压目录使用的 `config.groups.example.json` 搬进 /etc 后运行。** 它的 `candidates/...` 相对路径会解析为 `/etc/adgh-cf/candidates/...`，不会因为二进制在 /opt 或 WorkingDirectory 在 /var/lib 而改变。固定目录部署使用 **`config.groups.run.example.json`**，已填写下面的绝对路径。

启用新配置时先停旧 timer、等待当前 service 完成并用旧配置处理 pending。在新版部署包解压目录中，只在新配置尚不存在时安装模板：

```sh
sudo test -f /etc/adgh-cf/config.groups.json || sudo install -o root -g adgh-cf -m 640 config.groups.run.example.json /etc/adgh-cf/config.groups.json
sudoedit /etc/adgh-cf/config.groups.json
```

已有 `config.groups.json` 则直接编辑原文件，保留实际域名和管理地址。不要覆盖旧单域名 config.json；与旧配置同目录可继续加载原 `.env`。将下列同名字段改为绝对路径（这是字段片段，不是完整配置）：

```json
"candidateFile": "/opt/adgh-cf/candidates/cloudflare-ipv4.txt",
"cloudflareRangesFile": "/opt/adgh-cf/candidates/cloudflare-ipv4.txt",
"stateFile": "/var/lib/adgh-cf/optimizer-v2.json",
"candidateCacheDir": "/var/lib/adgh-cf/candidate-sources"
```

若配置含 `candidateSnapshotFile`，也应使用绝对路径 `/opt/adgh-cf/candidates/community-ipv4.txt`。检查静态文件可读：

```sh
sudo -u adgh-cf test -r /opt/adgh-cf/candidates/cloudflare-ipv4.txt
```

各字段用途：

- `candidateFile`、`cloudflareRangesFile`：`/opt/adgh-cf/candidates/cloudflare-ipv4.txt`。
- `stateFile`：`/var/lib/adgh-cf/optimizer-v2.json`（与旧状态分开）。
- `candidateCacheDir`：`/var/lib/adgh-cf/candidate-sources`，启用名单下载时由服务账户写入。

```sh
sudo -u adgh-cf /opt/adgh-cf/adgh-cf probe --config /etc/adgh-cf/config.groups.json --output /var/lib/adgh-cf/groups-probe.json
sudo -u adgh-cf /opt/adgh-cf/adgh-cf run --dry-run --config /etc/adgh-cf/config.groups.json --output /var/lib/adgh-cf/groups-dry-run.json
sudo -u adgh-cf /opt/adgh-cf/adgh-cf run --config /etc/adgh-cf/config.groups.json --output /var/lib/adgh-cf/groups-run.json
```

新配置须让 adgh-cf 服务账户可读，权限可沿用原配置的 root:adgh-cf、0640。正式 run 受连续确认和冷却限制，首次通常只记录观察；dry-run 不推进确认。

手动验证后，以 `sudo systemctl edit adgh-cf.service` 设置以下 override，将定时任务改为新配置并给恢复留出时间：

```ini
[Service]
ExecStart=
ExecStart=/opt/adgh-cf/adgh-cf run --config /etc/adgh-cf/config.groups.json --output /var/lib/adgh-cf/last-run.json
TimeoutStartSec=125min
TimeoutStopSec=130s
```

```sh
sudo systemd-analyze verify /etc/systemd/system/adgh-cf.service
sudo systemctl daemon-reload
sudo systemctl start adgh-cf.service
sudo journalctl -u adgh-cf.service -n 60 --no-pager
# 确认 service 与报告正常后，恢复原已启用的 timer
sudo systemctl start adgh-cf.timer
systemctl list-timers adgh-cf.timer
```

同一组再次正式运行需至少相隔 5 分钟才能增加确认，默认每小时 timer 满足该间隔。不要另外启用管理相同域名的旧任务。

## 从 v1 迁移和退回

1. 停止旧 timer，等待旧 run 完成；用旧配置先处理所有 pending。保留旧配置和状态备份，不自动转换事务。
2. 新建 `schemaVersion: 2` 配置和独立 `stateFile`，把旧 domain/healthPath 合成成员 URL。不要同时保留旧顶层 domain、healthMode、healthPath 或 port。
3. 原来省略 healthMode 的服务迁移时明确写 `mode: "openbao"`。原来的 HTTP 检查保留预期状态码和标记，例如：

```json
{"domain":"service.example.com","url":"https://service.example.com/ready","mode":"http","expectedStatusCodes":[200],"expectedBodyContains":"service-ready"}
```

v1 HTTP 仍强制标记且响应超限失败；v2 HTTP 标记可省略且仅检查有限前缀。不要借迁移去掉已有标记、改变模式或降低健康保证。v2 新默认仅对新配置生效。

4. 先 probe，再 dry-run，确认后才替换 service 的配置路径。旧状态不能给 v2 使用。
5. 退回前先用 v2 配置恢复 pending、停止 v2 任务。使用旧配置重新读取实际规则；旧快照不是当前值。不要并行运行旧、新定时任务。

## 目标 Linux 验收记录（部分已取得）

2026-10-11 用户决定将故障恢复真机实测延期，待有合适条件时再进行；本地故障模拟测试已通过，正常使用验证继续有效。

2026-10-11 已取得连续两轮 service 报告、三个成员的全组复验、FreshRSS 真实组内对齐和程序写后核对结果，用户也在 AdGuard Web 界面确认规则已更新；详见 [STATUS.md](STATUS.md)。FreshRSS 的 Chrome 页面、登录和功能已验证正常，体感响应改善没有量化数据；其他成员业务验证与故障恢复仍待完成，以下是完整验收要求。

在实际家庭出口至少使用两个域名，保留每轮独立报告。记录二进制版本/构建提交、日期、组配置摘要（无秘密）、probe、dry-run、两轮相隔至少 5 分钟的 run、写前后每个域名的 API/DNS 值，以及客户端实际访问。确认无关 rewrite 不变，观察 timer、运行锁及重启恢复。真实切换和回滚未取得记录前，专项方案 E 和整个第 1 项保持待验收，后续候选分发及 hosts 输出不启动。
