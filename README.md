# CVE Guard — Ubuntu VPS 安全巡检

面向 Ubuntu 24.04、宝塔/aaPanel、PHP/Laravel、Next.js、Docker、PostgreSQL、Redis、Nginx/OpenResty 的**本地安全巡检代理**。

> 安全边界：**GitHub Actions 不能直接检查没有部署代理的 VPS**。此仓库的定时任务只测试扫描程序；真实资产扫描必须由 VPS 上的 systemd timer 本地运行。扫描不会主动攻击服务，不执行漏洞利用。

## 功能与结果

- 系统/软件盘点、监听地址与敏感端口提示、Docker 特权容器与 Docker Socket 挂载检查。
- 默认**自动扫描宝塔 / aaPanel 网站根目录 `/www/wwwroot/`**：枚举每个网站目录（包括静态网站），深入查找 Laravel、Composer、Node.js、Next.js 相关锁文件；无需一站一站添加路径。
- 调用已安装的 **Trivy** 检查网站目录、容器镜像和宿主机 rootfs（网站目录在 rootfs 扫描中跳过以减少重复）。Trivy 每次运行会按缓存策略刷新漏洞数据库。
- 对自动发现或手动配置的项目分别运行 npm audit / composer audit（有对应锁文件、工具可用时）。仅有 yarn/pnpm/bun 锁文件的项目通过 Trivy 文件扫描尝试识别依赖漏洞，不强行使用 npm audit。
- 自动生成本地 JSON 和 Markdown 报告，区分“发现风险”“扫描失败”“无法检查”，绝不将扫描失败当作零漏洞。
- systemd 每天自动扫描；可**显式选择**启用 Ubuntu unattended-upgrades 的安全更新策略。数据库、PHP 大版本、容器镜像和应用更新一律不自动变更。
- 无需 VPS 密码、SSH 私钥、Cloudflare Token 或 GitHub Token。

## 安装（在你自己的 Ubuntu VPS 上）

克隆仓库、审查脚本，再运行安装程序：

```bash
git clone https://github.com/basumobai/cve.git /opt/cve-guard
cd /opt/cve-guard
sudo bash scripts/install.sh
```

安装脚本检查 Python3，安装 systemd 单元和配置模板，**不自动下载或安装 Trivy**。建议单独执行以下可审计的可选安装脚本，从 Trivy 官方签名 APT 仓库安装漏洞扫描器：

```bash
sudo bash scripts/install-trivy.sh
```

也可参考 [Trivy 官方安装说明](https://trivy.dev/latest/getting-started/installation/) 手动安装。没有 Trivy 时报告会标记扫描未完成。

配置（本地文件不要提交到 GitHub）：

```bash
sudo cp config.example.json /etc/cve-guard/config.json
sudo nano /etc/cve-guard/config.json
sudo systemctl start cve-guard.service
sudo systemctl status cve-guard.service
sudo journalctl -u cve-guard.service --no-pager -n 100
sudo ls -l /var/lib/cve-guard/reports
```

默认自动检测 `/www/wwwroot` 下的网站目录（包括 `/www/wwwroot/example.com` 这样的域名目录），并扫描整个站点目录及最多 3 层的嵌套项目清单，常见 PHP/Laravel/Next.js/Node.js 项目无需逐个配置。`applications` 仅用于添加不在网站目录下的其他项目，比如 Learning 项目所在的独立目录。**Docker 容器内的应用不会自动被扫描成宿主项目**；Trivy 的镜像扫描负责容器镜像内依赖。
 
扫描器只读取本机内容，发现的路径与漏洞不会上传到 GitHub。默认不跟随网站目录里的符号链接（防止跑到站外的敏感目录）；被跳过的链接会报告为未覆盖。如网站是 `/www/wwwroot/site/current -> /srv/releases/...`，请单独将真实项目路径添加到 `applications`。

检查定时任务：

```bash
sudo systemctl status cve-guard.timer
sudo systemctl list-timers cve-guard.timer
```

可选择自动安装 Ubuntu 官方安全包补丁（**非默认**，需要自行审查 apt policy、备份并接受计划内重启风险）：

```bash
sudo bash scripts/enable-ubuntu-security-updates.sh
```

它使用发行版的 unattended-upgrades，修改的是 Ubuntu apt 安全更新行为，而不是直接给第三方 aaPanel/PHP/数据库软件打补丁。不会自动重启服务器（受其他系统现有配置影响，请自行复核）。

## 配置

参见 config.example.json。默认对宿主机 rootfs、网站目录、可访问 Docker 镜像进行扫描，大型服务器可能耗费较长时间与磁盘空间。可将 `scan_host_rootfs`、`scan_web_files` 或 `scan_docker_images` 改为 `false`。

网站相关的默认配置为：

```json
{
  "auto_discover_websites": true,
  "web_roots": ["/www/wwwroot"],
  "max_websites": 100,
  "web_project_depth": 3,
  "max_web_projects": 250,
  "scan_web_files": true
}
```

如果你已有旧版 `/etc/cve-guard/config.json`，**无需重置配置**：以上默认值在新扫描器中自动生效。希望扫描自定义网站目录，可修改 `web_roots`（例如另加 `/srv/www`）；可对单独部署的项目追加到 `applications`。

为了控制误扫和开销，自动搜索跳过 `node_modules`、`vendor`、`storage`、`uploads`、`logs`、`cache`、`backups`、`.git` 等目录，既不执行网站 PHP/JavaScript 代码，也不读取数据库密码进行网络连接。**这不是 WebShell/恶意文件查杀器**；无锁文件或缺少扫描工具不意味着代码没有漏洞。

## 安全注意

- **仓库是公开的**：不要 push /var/lib/cve-guard/reports、.env、密码、真实 IP、容器环境变量和数据库连接串。
- 默认扫描结果仅保存在目标 VPS，目录权限 0700，报告权限 0600。
- 无 Trivy/无网络/无权限/无锁文件时会输出“未检查”，绝不声称安全。
- 开放监听不代表真的从公网可达：还要结合云防火墙、UFW、反向代理和 Cloudflare 核对。
- Ubuntu 内核和 APT 包可能含发行版回移补丁：不要只根据上游版本号判断受影响状态。
- 自动更新可能中断业务。此项目不会自动升级 PHP 大版本、修改 Docker Compose 或在生产容器执行 npm audit fix / composer update。
- 执行 shell 脚本前先审核代码。本仓库不提供渗透或漏洞利用能力。

## GitHub CI

.github/workflows/ci.yml 会在推送、PR 和每周定时执行单元测试；Dependabot 每周提出 GitHub Actions 依赖更新 PR。**CI 的宿主机是 GitHub Runner，不是你的 VPS。**

## 手动运行

```bash
python3 src/cve_guard.py --config config.example.json --output-dir /tmp/cve-guard-reports
python3 -m unittest discover -s tests -v
```

## 手动更新本项目扫描器

在克隆目录执行 `git pull --ff-only`，然后 `sudo bash scripts/install.sh` 以更新部署的代码。新增的网站发现功能需要同时安装 `site_discovery.py`，因此只 `git pull` 而不重新运行安装脚本不会更新已经部署的服务。GitHub 不会擅自向你的 VPS 推送未知代码；每天的 Trivy CVE 数据库按工具自身更新策略自动刷新。

## 当前边界

- 尚未接入任何真实 VPS，不存在现成的生产扫描结果。
- 面板漏洞是否受影响必须由厂商构建版本/安全公告验证，不能靠推测 CVE。
- Trivy、npm audit、composer audit 的覆盖范围各不同；任何单一工具都不能证明服务器无漏洞。
