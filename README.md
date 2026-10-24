# CVE Guard

**Ubuntu VPS 安全巡检。自动发现宝塔 / aaPanel 的网站目录，检查服务器、依赖和 Docker 镜像的已知漏洞。**

- 默认扫描：Ubuntu 24.04、`/www/wwwroot/*`、PHP / Composer、Node.js / Next.js、Docker、Redis / PostgreSQL 等常见服务
- 每天自动巡检，漏洞库由 Trivy 按需更新
- **只读检查**：不会自动改动网站代码、PHP、数据库或容器；扫描结果**只保留在服务器本地**
- 适合个人 VPS 和小型自建站点；不会尝试利用漏洞或破解服务

> [!IMPORTANT]
> GitHub Actions 只能对本仓库做代码测试，**不会自动连接你的 VPS**。你必须在自己的服务器部署代理，才能看到真实漏洞报告。

## 1. 安装（首次只需一次）

Ubuntu 24.04 上通过 SSH 执行：

```bash
sudo git clone https://github.com/basumobai/cve.git /opt/cve-guard
sudo bash /opt/cve-guard/scripts/install.sh
sudo cve scan
```

安装时会自动安装缺失的 Trivy（添加 Aqua 官方签名 APT 源）、写入 systemd 服务并启动每日定时任务；**首次扫描由最后一条命令手动触发**。

如果已经安装过旧版，直接使用 `sudo cve update`；若旧版还没有 `cve` 命令，执行：

```bash
cd /opt/cve-guard && git pull --ff-only && sudo bash scripts/install.sh
```

使用非 root 账户克隆仓库的旧用户，请用原账户执行 `git pull`；`sudo cve update` 可能受到 Git 目录所有权安全检查限制。

## 2. 日常使用（只记住 4 条）

| 命令 | 做什么 |
|---|---|
| `sudo cve scan` | 立即扫描并显示漏洞数量、扫描失败数量 |
| `sudo cve status` | 查看每日巡检状态、最近一次扫描摘要 |
| `sudo cve report` | 在终端查看最新详细报告 |
| `sudo cve update` | 更新扫描器代码和服务配置，**不会升级你的站点** |

报告存放在 `/var/lib/cve-guard/reports/`（JSON + Markdown）。报告目录仅 root 可读，默认保留最近 **30 次**。若扫描退出非零，通常是有检查没有完成；可以先运行：

```bash
sudo journalctl -u cve-guard.service -n 100 --no-pager
```

定时任务可以这样查看：

```bash
sudo systemctl list-timers cve-guard.timer
```

## 3. 默认会扫描哪些内容？

| 目标 | 检查方式 | 说明 |
|---|---|---|
| Ubuntu 宿主机 | Trivy `rootfs`、APT 可更新包 | 考虑发行版安全回移补丁；仍需人工确认 |
| `/www/wwwroot` | 自动发现一级网站目录、Trivy `fs` | 包括静态网站，默认最多 100 个 |
| PHP / Laravel | 发现 Composer 清单、运行 `composer audit` | 审计依赖，不会执行 PHP 网站 |
| Next.js / Node.js | 发现 npm/pnpm/yarn/bun 锁文件 | `package-lock.json` 可使用 `npm audit`；其他锁文件主要由 Trivy 处理 |
| Docker | 扫描正在运行容器使用的镜像 | 同时检查特权模式、Docker Socket、host network/PID |
| Nginx / OpenResty / Redis / PostgreSQL | 版本盘点、敏感监听端口提示 | 不是运行时渗透测试 |
| 宝塔 / aaPanel | 检测面板安装和 /www 目录中的软件 | **不是**完整的面板插件漏洞数据库 |

项目检测深度默认为网站根目录以下 **3 层**，最多累计 250 个项目。为了控制性能和避免不必要地读取隐私文件，自动搜索跳过 `node_modules`、`vendor`、`uploads`、`storage`、`logs`、`backups`、`.git` 等；**不会沿目录符号链接扫描站外文件**。因此发现并不保证覆盖全部依赖；跳过的目录、扫描失败会在报告中标明。

## 4. 可选配置

只有网站不在 `/www/wwwroot` 下、需要额外扫描某个项目，或需要节省磁盘/扫描时间时，才需要修改：

```bash
sudo nano /etc/cve-guard/config.json
```

默认设置参考 [config.example.json](config.example.json)：

```json
{
  "applications": [],
  "scan_docker_images": true,
  "scan_host_rootfs": true,
  "timeout_seconds": 360,
  "auto_discover_websites": true,
  "web_roots": ["/www/wwwroot"],
  "max_websites": 100,
  "web_project_depth": 3,
  "max_web_projects": 250,
  "scan_web_files": true
}
```

如想额外检查独立部署的 Learning 项目：

```json
"applications": [{"name": "learning", "path": "/opt/learning"}]
```

上面只是配置片段，需放入完整 JSON 对象中；路径请换成真实宿主机目录。**不要**把带有真实服务器路径、IP、口令的本地配置或报告提交到此公开仓库。

配置变更后运行 `sudo cve scan` 即可生效；不需要重装。

## 5. 自动更新：有哪些、没有哪些？

- **每天**：systemd 自动执行本机巡检。Trivy 按缓存/网络状态更新自己的漏洞数据库。
- **每周**：GitHub CI 测试代码，Dependabot 针对仓库工作流依赖提出 PR。
- **手动**：`sudo cve update` 更新扫描器程序；不自动部署未经审核的远程代码。
- **可选**：`sudo cve enable-updates` 启用 Ubuntu 的 unattended-upgrades，安装适用的系统包安全补丁。**此命令会修改 APT 更新设置**，执行前应备份、审查升级来源和维护策略。
- **永不自动执行**：PHP 大版本升级、Composer 更新、`npm audit fix`、数据库迁移、Docker 镜像更新或容器重建。

首次 Trivy 扫描可能下载体积较大的漏洞数据库。软件源不可达、空间不足、镜像拉取失败、文件权限不足时，报告应显示扫描未完成，而不是把漏洞数量 0 当作安全结论。

## 6. 安全与局限

1. **本工具不能证明“无漏洞”**，也不是 WebShell 检测或全面源代码审计。可用于快速找出已知依赖 CVE 和一部分常见错误配置。
2. 端口监听所有地址 ≠ 已经公网可访问；还要综合云防火墙、UFW 和 Cloudflare 规则。
3. 不要因为版本号看起来旧，就断言 Ubuntu 包仍存在漏洞：发行版可能回移安全修复。
4. 扫描器以 root 运行用于读取本机包/容器信息，安装前请审查脚本。Docker Socket 访问等效于高权限访问，应保护主机。
5. 报告可能含应用路径、镜像名等内部信息，权限设为 `0700/0600`，不通过 GitHub 自动上传。
6. 如果生产网站使用指向其他目录的 `current` 符号链接，请把真实目录手动加入 `applications`；本工具不会跟随该链接。

## 开发与自检

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/cve_guard.py src/site_discovery.py
bash -n scripts/*.sh scripts/cve
```

项目仅使用 Python 标准库组织扫描，依赖 Trivy、npm、Composer 的实际安全数据库作已知漏洞判断；可用扫描器缺失时会记录未覆盖范围。

本项目用于检测和维护**你有权管理的服务器**，没有远程漏洞利用、口令破解或攻击模块。


## 扫描状态与计数说明（2026-10 更新）

- 定时巡检成功写入报告后，即使 Composer 等个别检查未完成，systemd oneshot 也正常结束；未完成项目仍列在 `sudo cve report` 的「未完成或错误」部分。严重的程序异常或写报告失败仍返回非零退出码。
- 报告分别显示「软件包漏洞匹配数」与「去重漏洞编号数」。同一漏洞可关联多个包和镜像，两者均不能直接代表可利用漏洞数量。
- Linux 旧内核及 headers 的扫描匹配不等于运行中的内核受影响；需要结合 `uname -r`、Ubuntu 安全公告以及供应商补丁回移记录核实。
- Composer 检查使用 `--no-plugins`，出现旧版 CLI 输出不合规时会标记扫描未完成，不把失败误报为零漏洞。建议安装与 PHP 版本兼容的 Composer 2。
- 每日自动扫描仅生成本地报告，不会自动升级操作系统、PHP、Docker 镜像或应用依赖。任何修复必须由管理员单独确认执行。

升级已有安装：

```bash
git pull --ff-only
sudo bash scripts/install.sh
sudo cve scan
sudo cve report
```
