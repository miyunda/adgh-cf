# adgh-cf

[![CI](https://github.com/miyunda/adgh-cf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/miyunda/adgh-cf/actions/workflows/ci.yml?query=branch%3Amain)
[![Go](https://img.shields.io/badge/Go-%3E%3D1.24-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

English readers, you don’t need this.

在家庭网络测量 Cloudflare CDN IPv4 对目标 HTTPS 服务的访问表现。支持 OpenBao/Vault 健康判断或显式配置的通用 HTTP 检查、公共候选源、只读测速，以及通过 `run` 更新指定域名的一条现有 AdGuard Home IPv4 rewrite。`probe`、`refresh`、`export` 不改 DNS。测速只使用 IPv4；名单下载直连或连接 IPv4 代理，代理的远端连接由 OpenClash 决定。

当前进度、家庭实测和人工试用记录见 [STATUS.md](docs/STATUS.md)；后续设计与验收见 [PLAN.md](docs/PLAN.md)。用户手动将 DNS rewrite 改为 `104.17.128.164` 试用。2026-10-08 已实现自动更新和 systemd 每小时调度模板，部署与首次 dry-run 见 [DEPLOY.md](docs/DEPLOY.md)；真实家庭写入与定时触发待验证。

首次版本拟为 **0.1.0**。用户已验证家庭 dry-run 正常、service 实际运行和 timer 启用；自动切换结果仍待确认。示例域名和管理地址为通用占位值，复制示例后必须填写自己的环境。版本发布与升级见 [RELEASING.md](docs/RELEASING.md)，凭据与公开仓库边界见 [SECURITY.md](docs/SECURITY.md)。

## Linux 部署

运行只需要对应架构的二进制、JSON 配置、候选列表，以及系统 CA 根证书。目标机器无需 Go、Node.js、Python 或 OpenSSL。编译与打包在开发电脑完成。

先在 PT 主机运行 `uname -m`：`x86_64` 对应 amd64，`aarch64` 对应 arm64。将对应的发布包和 SHA256 文件传到 PT 主机。以 v0.1.0 amd64 为例，在普通用户可写目录执行：

```sh
mkdir -p adgh-cf
sha256sum --ignore-missing --check adgh-cf-v0.1.0-SHA256SUMS
tar -xzf adgh-cf-v0.1.0-linux-amd64.tar.gz -C adgh-cf
cd adgh-cf
./adgh-cf --version
test -f config.json || cp config.pt.example.json config.json
./adgh-cf probe --config config.json --output reports/home.json
```

先检查 `config.json` 中的域名、端口和健康检查规则。示例域名是占位值，不是代码默认值。只读 probe 不需要 OpenBao token 或 AdGuard Home 密码。

### 通过 OpenClash 下载名单（推荐用于 PT 主机）

另存代理下载配置，保留原配置；`.env` 必须与使用的 JSON 配置在同一目录：

```sh
cp config.proxy.example.json config.proxy.json
test -f .env || cp .env.example .env
chmod 600 .env
```

编辑 `.env`：

```dotenv
CANDIDATE_PROXY_ADDR=192.168.1.1:7893
CANDIDATE_PROXY_USERNAME=your-user
CANDIDATE_PROXY_PASSWORD="your-password"
```

地址格式为 `IPv4:端口`，使用 mixed 端口的 HTTP CONNECT 功能；无认证时用户名和密码都留空。有认证时两者都要填写。程序不会执行 `.env`，不会展开 `$变量` 或反斜杠转义；引号内的 `#`、`$`、`=` 等保持原样。注释须独占一行。进程中同名环境变量优先于文件，包括空值；三个字段全部为空则直连下载。普通 `HTTP_PROXY` / `HTTPS_PROXY` 不生效。

```sh
./adgh-cf refresh --config config.proxy.json --output reports/source-refresh.json
./adgh-cf probe --config config.proxy.json --output reports/home.json
```

只有候选名单下载走此代理，TCP/TLS/健康检查和 DNS 对照仍直连。代理必须允许 PT 主机访问，且 OpenClash 规则将名单域名送到可用代理出口。下载 TLS 校验保持开启，代理认证信息不会写入报告。代理失败使用旧缓存；无缓存时测速仍使用随包快照。配置错误会明确报错。

刷新间隔默认 24 小时，在下次执行 `probe` 或 `run` 时检查；systemd 调度见 DEPLOY.md。

### 从旧版本升级（离线方式仍可使用）

已有 `config.json` 不会被程序修改。PT 主机无法访问 GitHub 时，使用随包提供的快照和 `config.pt.example.json`；来源数组为空，不会尝试下载 GitHub 列表。另存配置避免覆盖已有文件：

```sh
cp config.pt.example.json config.pt.json
./adgh-cf probe --config config.pt.json --output reports/home-public.json
```

PT 配置从 `candidateSnapshotFile` 读取公共候选，仍按官方 IPv4 网段校验。在线配置 `config.example.json` 保留远程下载能力，同时也可用快照兜底。

### 在联网电脑更新快照

在能访问 GitHub 的电脑上运行本机版本二进制（开发 Mac 可用 `make build` 生成），使用在线配置：

```sh
test -f config.export.json || cp examples/config.example.json config.export.json
./build/adgh-cf export --config config.export.json --output candidates/community-ipv4.next.txt
```

`export` 强制刷新来源，导出去重的纯 IPv4 候选以及生成时间、来源和抓取时间；不测速，不改 DNS。下载失败但有已验证缓存时可以导出旧缓存，文件头会标注 `stale-cache`。没有有效地址则失败，不覆盖现有文件。

将生成文件同步到 PT 主机的 `candidates/community-ipv4.txt`，建议先传为独立 `.next.txt` 文件，确认传输成功后在同一目录重命名替换。无需改变 PT 主机的网络路由。传输方式由现有 SSH/SFTP 等工具决定，程序不包含远程部署凭据。

离线配置不会每天自行更新文件；每天自动更新需要联网电脑定时生成并同步，或配置经过 PT 主机验证可达的 HTTPS 来源。当前随包快照来自 2026-10-07 已下载并验证的候选缓存。

**必须在家中 Linux、与客户端使用相同出口的环境运行，成绩才能用于家庭选址。** 透明代理和策略路由仍可能改变实际出口；程序直接连接候选 IP，但不能绕过路由器的转发策略。

此项目的部署机器是长期在线、不经过 OpenClash 的 PT 主机。默认使用系统 DNS，因此可继续共用 AdGuard Home。候选测速固定 IP，不受现有 rewrite 的解析结果影响；只有 DNS 对照可能已被 rewrite 覆盖。

测到的是家庭直连路径。需要确认其他客户端访问该目标域名时也走家庭直连；如果域名仍走 OpenClash 代理，直连测速成绩不能代表代理链路的表现。

PT 下载尤其是上传占满出口时，会增加排队延迟和超时。先在 PT 低负载时建立基线，再在实际负载下重复采样；不要因为一次高负载下的失败就放宽成功率门槛。工具没有大文件测速，默认只有少量 TCP/HTTPS 请求。后续定时调度与切换策略需要同时考虑负载和多时段成绩。

## 测试与报告

1. 从公共来源读取有效缓存或下载新列表，合并本地采样和固定保留地址，再取得配置域名的 IPv4 解析地址作为对照。
2. 有限并发 TCP 初筛，保留最快的少量地址；DNS 对照和固定保留地址始终进入 HTTPS 测试。
3. 交错请求健康接口，使用 HTTP/1.1，每次建立新的 TCP/TLS 连接，保留目标域名 Host/SNI 并校验证书。
4. 输出每个样本的 TCP 耗时、TLS 阶段耗时、从请求开始到响应首字节的等待时间、总耗时、HTTP 状态及健康分类。
5. 按成功率门槛筛选，以延迟生成本轮建议地址。退出码：`0` 有合格地址；`2` 没有合格地址；`1` 配置、文件或执行错误。

报告的 `suggestedIp` 只是本轮受测地址中表现最好的候选，不会触发任何写入。TCP 最快不保证 HTTPS 最好；本版本只验证有限入围样本，不声称找到了全网最优地址。

默认每个 IP 最多五次样本，只展示中位数；至少二十个成功样本才报告本轮 P95。成功率已不可能达标时提前淘汰；可用 `maxTtfbMs` 设置延迟淘汰门槛，0 表示禁用。报告 `eliminatedReason` 和实际样本数，被淘汰地址不参与排名。`run` 已提供连续确认、冷却及条件回滚，保留最近 48 轮摘要；跨轮聚合成功率、连接复用指标尚未实现。当前健康探测不能保证认证操作可用；HTTP/2 或 HTTP/3 客户端的性能可能不同。

健康结果结合 JSON 判断：active 与 standby 可作为可达候选；sealed、未初始化、HTML 挑战页、边缘限流和网络故障分别报告。standby 的可达性不等于已经验证其转发能力。无可用地址时报告错误，不猜测 IP。

### 配置

`healthPath` 原本就可配置；`healthMode` 选择响应判断。旧配置省略时保持 `openbao`，检查健康 JSON 和 initialized/sealed/standby。其他服务使用 `http` 并显式指定路径、预期成功状态码和非敏感响应标记；不能只凭任意 200 判断服务健康。示例 `config.http.example.json` 使用：

```json
{
  "healthMode": "http",
  "healthPath": "/health",
  "expectedStatusCodes": [200],
  "expectedBodyContains": "service-ready"
}
```

这段仅展示健康字段，实际运行还需要完整配置中的域名、候选等字段。响应标记区分大小写，按字节匹配，须符合目标服务真实响应；它不是 JSON 字段解析，也不展开转义或正则。通用模式不要求 JSON Content-Type，仍限制响应大小、超时、重定向并正常校验证书。OpenBao/Vault 的特殊状态码由默认模式处理，不放宽通用模式去接受任意错误码。健康接口应无需业务凭据，标记不能包含秘密。改变健康规则或关键选择门槛会重置连续胜出。

所有相对文件路径以配置文件所在目录为基准；`--output` 相对当前工作目录。未知字段与越界参数会报错，避免拼写错误静默生效。

| 参数 | 用途 |
| --- | --- |
| `domain` / `port` / `healthPath` | 实际 HTTPS 服务，域名必填 |
| `healthMode` | openbao（默认）或 http |
| `expectedStatusCodes` / `expectedBodyContains` | http 模式必填的预期成功码和响应标记 |
| `candidateFile` | 一行一个公网 IPv4 或规范 CIDR，可用 `#` 注释 |
| `maxCandidates` / `sampleOffset` | 有限采样数量和跨轮偏移；增加偏移测试其他地址 |
| `tcpConcurrency` / `tcpTimeoutMs` | TCP 初筛并发与绝对超时 |
| `finalists` / `samplesPerIp` | 入围 IP 数量和每个 IP 的 HTTPS 样本数 |
| `httpsTimeoutMs` / `maxResponseBytes` | 每个 HTTPS 请求的绝对超时与响应字节上限 |
| `requestIntervalMs` | 顺序请求之间的暂停时间，限制探测负担 |
| `minSuccessRate` | 本轮最低可用响应比例，默认要求全部成功 |
| `maxTtfbMs` | 单次成功样本的完整 TTFB 上限；超限淘汰，默认 0 禁用 |
| `baselineDnsServers` | 可选对照 DNS 服务器 IP；空数组使用系统 DNS |
| `candidateSources` | 最多四个显式配置的公共 HTTPS 列表；旧配置省略则不下载 |
| `candidateSnapshotFile` | 可选的本地公共候选快照；PT 示例启用此文件并禁用远程来源 |
| `candidateCacheDir` / `sourceRefreshHours` | 各来源独立缓存目录、刷新间隔；默认 24 小时 |
| `cloudflareRangesFile` | 校验公共地址的官方 IPv4 CIDR 文件，与本地候选文件可分开配置 |
| `pinnedIps` | 最多四个保留复测的公网 IPv4；示例包含已验证的 `103.31.4.18` |

系统 DNS 可能已包含 AdGuard Home rewrite。如果需要独立于现有 rewrite 的对照，显式配置可达的上游解析器 IP。配置多个解析器时失败后按顺序尝试。报告记录配置的 DNS 服务器；空数组表示使用系统解析器配置，不代表没有 DNS。解析失败仍会继续候选测速并记录错误。

新示例配置最多 128 个候选、8 个 TCP 入围地址、每个 IP 五次 HTTPS 请求，另加最多四个 DNS 对照地址和一个固定保留地址。因此最多 132 次 TCP 尝试、65 次 HTTPS 请求；重叠地址会去重。HTTPS 串行且有请求间隔；没有大文件下载。

### 公共候选池与缓存

示例接入 [LancelotRar 独立扫描 Top100](https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top100.txt) 和 [joname1 聚合 IPv4 列表](https://raw.githubusercontent.com/joname1/BestCFip/main/ipv4.txt)。来源由配置指定，不在代码里硬编码。

- 接受纯 IPv4 或 `IPv4:443#标签`，丢弃 IPv6、其他端口、私网及官方 Cloudflare 网段外的反代地址；标签和来源排名不参与本地选址。
- 两份列表交错合并去重，优先纳入公共候选，同时在预算内保留最多 16 个本地探索地址。`pinnedIps` 优先保留，且始终进行 HTTPS 复验。
- 快照也按相同标准校验并合并；在线下载的地址优先于快照，重复地址只测一次。候选顺序可通过 `sampleOffset` 轮换。
- 启用来源时，本地候选和固定地址也按 `cloudflareRangesFile` 校验。该文件是随包提供的官方网段快照，独立于每日公共列表更新。
- 每个来源独立缓存，24 小时内正常 `probe` 不重复下载；到期后在下一次运行时尝试刷新。程序无需常驻，也不会在没有运行时自动醒来。
- 单个下载最多 128 KiB、15 秒，使用正常 TLS 校验；拒绝跨主机跳转或 HTTPS 降级。
- 失败或无有效地址时不覆盖旧缓存，继续使用重新通过网段校验的旧副本。没有缓存时记录来源不可用，仍可使用本地候选。报告保留失败原因；缓存写入失败也会报告。

报告 `candidateSources` 列出 `downloaded`、`cached`、`stale-cache` 或 `unavailable`、抓取时间以及接受/拒绝数量。强制 `refresh` 的退出码：`0` 至少一个来源下载有效内容，`2` 没有来源下载成功（可能仍有可用旧缓存），`1` 配置或执行错误。可从完整报告检查另一来源是否失败。

缓存与报告目录被 Git 忽略，不打包到部署包。纯 IP 快照则随部署包提供。公共列表仅提供候选；只读 `probe` 不写 AdGuard Home 规则，自动管理使用独立的 `run` 命令。

### 更新候选源

仓库中的候选网段取自 [Cloudflare 官方列表](https://www.cloudflare.com/ips-v4)，获取日期写在文件头。它们是 Anycast CDN 网段，不代表每个地址都能服务目标域名。

可先下载到独立文件再审阅替换：

```sh
curl --fail --show-error --silent --max-time 15 --max-filesize 16384 \
  https://www.cloudflare.com/ips-v4 --output /tmp/cloudflare-ipv4.txt
```

程序不会自动更新这个文件；无需每轮下载。可将配置指向审阅后的文件，或补充你已知可用的公网 IPv4。

## 开发、构建和验证

开发机器需要 Go 1.24 或更新版本；项目只使用标准库。测试通过 Go 自建本地 HTTPS 服务，不需要外部证书工具。Makefile 需要 make 和 tar，仅构建机器需要。

```sh
make build
make test
make check
make linux
```

`make build` 生成开发机可执行的 `build/adgh-cf`。`make linux` 关闭 CGO，交叉编译 amd64/arm64 静态二进制，在 `build/release/` 生成带版本号的包和 SHA256，并保留旧的本地包路径。构建注入 VERSION 和提交信息，运行 `--version` 查看。发布使用明确文件范围和新建暂存目录，不包含真实配置、缓存或报告。关闭 CGO 不会取消 TLS 校验，运行时仍使用系统 CA 根证书。

源码保持 Go 单包结构，源码与测试集中在 `cmd/adgh-cf/`，可使用 `go run ./cmd/adgh-cf --help`。目录分工如下：

| 目录 | 内容 |
| --- | --- |
| `cmd/adgh-cf/` | 命令入口、业务实现和 Go 测试 |
| `examples/` | JSON 配置模板和空值 `.env.example` |
| `candidates/` | 随包提供的候选快照和官方网段 |
| `scripts/` | 构建和公开仓库边界检查 |
| `deploy/systemd/` | service/timer 部署模板 |
| `docs/` | 设计、部署、安全和发布文档 |
| `.github/` | CI、Release 和 Dependabot 配置 |

在源码目录运行时，先把模板复制到根目录或自己的部署目录，再填写环境信息。例如：

```sh
test -f config.pt.json || cp examples/config.pt.example.json config.pt.json
test -f .env || cp examples/.env.example .env
chmod 600 .env
```

所有模板内相对路径按实际配置文件所在目录解释，不直接使用 `--config examples/config.pt.example.json`。发布包仍将配置模板放在包根目录，已有 Linux 部署命令保持有效。真实配置、报告、状态和构建产物属于本地运行文件，由 Git 忽略。

PR 执行检查、测试和构建验证；合并到 `main` 后再次验证，并将 Linux amd64/arm64 包及 SHA256 上传至对应 [CI 运行](https://github.com/miyunda/adgh-cf/actions/workflows/ci.yml) 的 Artifacts，保留 14 天。此处下载的是该提交的开发构建，正式版本通过 `v*` 标签创建草稿 Release。

`make test` 使用 race detector，开发机需要支持 CGO 的 C 编译器。只有运行测试需要；普通编译和目标 Linux 二进制不依赖 CGO。也可先使用 `go test ./...`。

测试覆盖候选输入、配置边界、健康分类、提前淘汰、TLS/Host/SNI、超时/大小限制/取消、代理认证与隔离、AdGuard API 精确更新、条件回滚、人工冲突、DNS-over-TCP、状态、运行锁和 dry-run/连续确认流程。

自动更新的配置、`.env` 凭据和 systemd 安装步骤见 [DEPLOY.md](docs/DEPLOY.md)。后续设计与验收边界见 [PLAN.md](docs/PLAN.md)。

许可证：[MIT](LICENSE)。
