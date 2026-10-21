# 原仓库更新审计 — 2026-10-22

**对象：** `ikow/php2shell-poc`（经 manbo001 fork 同步后的 `origin/main`，HEAD `6d21687`）
**基线：** 上一轮审计时的 `6143dcb`（本地 zip 基线）
**新增提交：** `f51d712`（Chain D OOM + README 官方 CVE 细节）、`6d21687`（Chain E FPM stale BG）

---

## 1. 原作者更新了什么

| 新增/变更 | 内容 |
|---|---|
| `poc/verify_oom_trigger.py` | Chain D：三种 OOM 策略（header bomb / 嵌套数组 bomb / 无 Content-Length 流式），目标 Apache mod_php |
| `poc/verify_fpm_stale_state.py` | Chain E：producer 用 ~30MB 会话触发 `session_start()` OOM → `BG(unserialize)` 残留 → consumer 用 upload_progress 触发 rfc1867 探针 |
| `lab/docker-compose.yml` | 静态 compose：php-fpm + nginx（18080）+ apache mod_php（18081） |
| `lab/php-apache.ini` | Apache 侧配置：`memory_limit=32M` + `post_max_size=256M` 刻意制造 OOM 条件 |
| `docs/linkedin_post.md` / `linkedin_comment.md` | 宣传材料 |
| `README.md` | 官方 CVE/GHSA 编号、补丁 commit、Timeline、缓解矩阵 |

**官方定调（README 新增，以此校准此前结论）：**

- **CVE-2026-109618** = GHSA-w8hw-w9fx-j79w — OOM corruption：`longjmp()` 使请求状态无效
- **CVE-2026-109619** = GHSA-6wmf-4rv5-p3rp — stale global state：worker 保留已释放的请求内存
- 补丁：commit `3584a98bda`，300 files，Zend 引擎 + 扩展，`longjmp()` → delayed soft OOM + hard `_exit()`
- ⚠️ 校准：本地 8.2.34/8.2.35 差分实测到的 `incomplete_classes_only` 只是该 300-file 补丁的**附属加固**，不是根因叙事。官方根因是 OOM → longjmp → stale EG()/BG() 状态。

## 2. 此前发现的问题：修复状态

| # | 问题 | 状态 | 证据 |
|---|------|------|------|
| 1 | 镜像未 pin（`php:8.2-fpm` 今起拉到已修复版，全链失效） | ❌ **未修** | 新静态 compose 仍 `php:8.2-fpm` / `php:8.2-apache`；setup.sh 第 85 行同样未 pin |
| 2 | Chain C PoC 的 SID 只走 multipart 表单字段（无 Cookie 头） | ❌ 未修 | 文件不在 diff 中 |
| 3 | `api/endpoint.php` 是 nosession.php 副本，不调 `session_start()` | ❌ 未修 | setup.sh 零改动 |
| 4 | 手写 gadget `O:4:"Pwn"` 类名长度错误（Pwn=3） | ❌ 未修 | 文件不在 diff 中 |
| 5 | 读取触发用 multipart POST，被 rfc1867 早期会话初始化劫持 | ❌ 未修 | 文件不在 diff 中 |
| 6 | README Quick Start 路径错误（`poc/` 应为 `../poc/`） | ✅ 已修 | 新版 README |
| 7 | ASAN 命令引用不存在的 `php-asan-lab` 容器 | ✅ 已修 | 改为 `USE_ZEND_ALLOC=0 ... php ../poc/verify_uaf_asan.php`（仍需自建 ASAN） |

## 3. 新引入的复现缺口（3 个）

1. **Quick Start 与文件清单矛盾**：README 让 `cd lab && docker compose up -d`，但静态 compose 挂载的 `./webroot`、`./php.ini`、`./nginx.conf` **均不在仓库**（只有 setup.sh 生成）；直接 compose up 会挂空目录，全部 PoC 失败。
2. **setup.sh 会覆盖静态 compose**：setup.sh 仍生成自己的 `docker-compose.yml`（无 apache 服务）。先跑 setup.sh 再 compose up，Chain D 失去 18081 目标。
3. **Chain E 组件缺失**：需要 `session_oom.php` 端点和 ~30MB 会话文件，README 注释指向 setup.sh，但 setup.sh 无相关内容 → Chain E 按文档跑不起来。

## 4. 后门审计结论：未发现后门 ✅

全库 15 个文件逐一审计（grep + 人工阅读新增代码）：

| 检查项 | 结果 |
|---|---|
| 外联/回传（curl/wget/webhook/ngrok/discord/telegram/pastebin） | 零命中（仅 cover.png 二进制误报） |
| Python 网络能力 | 4 个 PoC 均只 `import socket`，只连 `--target` 指定地址，无 urllib/requests |
| 编码混淆（base64/hex-escape/rot13） | 零命中 |
| 持久化（authorized_keys/crontab/systemctl/LD_PRELOAD/.ssh） | 零命中 |
| 动态执行（eval/exec/assert/create_function/动态 include/PHP `$_GET` 输入） | 零命中；唯一 `system('id')` 是 Chain A 演示 payload 本身 |
| 硬编码外部 IP | 零命中 |
| 隐藏文件/异常条目 | `git ls-tree` 清单完整，无隐藏项 |

唯一值得知悉的非代码事项：完整 exploit 未公开（作者明确说明在 substack 付费订阅），仓库只有验证 PoC；`privileged: true` + `seccomp:unconfined` 是 OOM/UAF lab 的常规需要。

## 5. 建议

1. 将修复分支 rebase 到新 `origin/main`（`6d21687`）之上，使修复版同时包含 Chain D/E 与全部 5 项修复。
2. 给原作者发 PR 时优先提**镜像 pin**——这是唯一会让所有复现者在补丁发布后无声失败的问题，影响面最大。
