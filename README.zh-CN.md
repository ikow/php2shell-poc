<p align="center">
  <img src="docs/cover.png" alt="php2shell" width="700">
</p>

<h1 align="center">php2shell</h1>
<p align="center">
  <strong>CVE-2026-109618 与 CVE-2026-109619 —— PHP 预认证 RCE 漏洞利用及检测工具包</strong>
</p>
<p align="center">
  <a href="https://github.com/ikow/php2shell-poc/stargazers"><img src="https://img.shields.io/github/stars/ikow/php2shell-poc?style=flat-square" alt="Stars"></a>
  <img src="https://img.shields.io/badge/CVSS-9.2%20Critical-red?style=flat-square" alt="CVSS 9.2">
  <img src="https://img.shields.io/badge/PHP-5.4%E2%80%938.5-orange?style=flat-square" alt="Affected Versions">
  <img src="https://img.shields.io/badge/Fixed-8.2.35%20%7C%208.3.36%20%7C%208.4.27%20%7C%208.5.12-green?style=flat-square" alt="Fixed Versions">
  <img src="https://img.shields.io/badge/Exploits-3%20public%20%7C%202%20paid-blue?style=flat-square" alt="Exploits">
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>简体中文</strong>
</p>

<p align="center">
  <a href="#漏洞利用">漏洞利用</a> · <a href="#检测规则">检测规则</a> · <a href="#快速开始">实验环境</a> · <a href="docs/EXPLOITATION.md">野外利用追踪</a> · <a href="https://qideng.substack.com/p/php2shell-dissecting-phps-critical">分析原文</a> · <a href="https://qideng.substack.com/p/php2shell-one-week-later-cisa-kev">一周报告</a>
</p>

---

五条独立的 RCE 利用链，利用 PHP 的 `session.upload_progress` 与 Zend 引擎的 OOM bailout 机制。**易受攻击的代码已存在 14 年** —— 从 PHP 5.4.0（2012 年）一直延续到 8.5.11。无需预认证，部分利用链甚至不要求应用程序本身存在任何漏洞。

影响**全球 78% 的网站** —— 包括 WordPress（43%）、Joomla、Drupal、Laravel、Magento，以及所有默认安装的 PHP。

**作者：** [Qi Deng](https://github.com/ikow) &nbsp;|&nbsp; **分析文章：** [Substack](https://qideng.substack.com/p/php2shell-dissecting-phps-critical) &nbsp;|&nbsp; **日期：** 2026-10-21

## CVE 详情

| CVE | GHSA | CVSS | 描述 |
|-----|------|------|-------------|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | 9.2 | OOM 触发 `longjmp()`，导致 Zend 引擎状态失效 → RCE |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | 9.2 | FPM worker 多个请求之间残留全局状态 → UAF → RCE |

**补丁：** [提交 3584a98](https://github.com/php/php-src/commit/3584a98bda) —— 横跨 Zend 引擎，共修改 300 个文件。

## 攻击链

| 利用链 | 攻击向量 | 预认证 | 触发条件 | SAPI |
|-------|--------|:--------:|------------|------|
| **A** | Session 注入 + LFI | 是 | 应用存在任意 LFI 点 | 全部 |
| **B** | var_destroy UAF → handler 覆写 | 否 | 应用调用了 `unserialize()` | 全部 |
| **C** | handler 不匹配 → `__destruct` | 是 | 存在两个使用不同 serialize_handler 的目录 | FPM |
| **D** | OOM 内存破坏 → 残留 `EG()` 状态 | 是 | **无** —— 任意端点即可 | mod_php |
| **E** | FPM 会话 OOM → 残留 `BG()` 状态 | 是 | 生产者：任意调用 `session_start()` 的端点；消费者：**任意**端点 | FPM |

利用链 D 最为致命：针对任意 Apache mod_php 安装环境的**零依赖预认证 RCE**。

利用链 E 在 FPM 上的影响面几乎同样广泛：生产者只需要一个调用 `session_start()` 的端点（这几乎随处可见 —— WordPress、Laravel、Joomla、Drupal 都会调用），而**消费者可以是任意 PHP 端点** —— `rfc1867` 上传进度处理函数在 SAPI 启动阶段、应用代码执行之前就会运行。已验证：`nosession.php`（代码中并没有 `session_start()`）在消费残留的 `BG(unserialize)` 状态时会触发 502 崩溃。

## 漏洞利用

[`exploit/`](exploit/) 目录中包含三个 RCE 利用脚本（利用链 A、B、C）：

| 文件 | 利用链 | 功能说明 |
|------|-------|-------------|
| `chain_a_session_lfi.py` | A | 通过上传文件名注入 PHP 代码 → LFI 包含 session 文件 → RCE |
| `chain_b_uaf_rce.php` | B | var_destroy UAF → 通过 EG() 定位 `zif_system` → 经 `/proc/self/mem` 覆写 `var_dump` handler → RCE |
| `chain_c_mismatch_rce.py` | C | 污染 FPM worker 的 `PS(serializer)` → 通过文件名注入序列化对象 → 解码失败时触发 `__destruct` → RCE |

利用链 D 和 E 的 EXP 仅向[付费订阅用户](https://qideng.substack.com/p/php2shell-dissecting-phps-critical)提供。

```bash
# 利用链 A：Session 注入 + LFI → RCE
python3 exploit/chain_a_session_lfi.py --host TARGET --port 80 --command 'id'

# 利用链 B：var_destroy UAF → RCE（在目标机上运行，或通过已上传的 webshell 运行）
php exploit/chain_b_uaf_rce.php

# 利用链 C：handler 不匹配 → __destruct → RCE
python3 exploit/chain_c_mismatch_rce.py --host TARGET --port 80 --command 'id'
```

## 检测规则

[`detection/`](detection/) 目录中提供开箱即用的 IDS / WAF / SIEM 规则：

| 文件 | 格式 | 签名数量 |
|------|--------|-----------|
| `php2shell.rules` | Suricata / Snort | 13 条规则 —— 覆盖请求、响应与侦察行为 |
| `php2shell.yaml` | Sigma | 5 条规则 —— 覆盖 Web 日志、进程创建、文件事件 |
| `modsecurity.conf` | ModSecurity v2/v3 | 7 条规则 —— 可直接部署到 Apache/Nginx |
| `php2shell.lua` | OpenResty Lua | 轻量级反向代理模块 |

**最快速的缓解措施：** 在 multipart POST 请求体中拦截 `PHP_SESSION_UPLOAD_PROGRESS`。该字段几乎没有合法用途，拦截后即可覆盖两个 CVE 的主要攻击向量。

## 快速开始

```bash
git clone https://github.com/ikow/php2shell-poc.git && cd php2shell-poc

# 启动实验环境（PHP-FPM + nginx + Apache mod_php）
cd lab && docker compose up -d

# 验证每条利用链
python3 ../poc/verify_session_injection.py --target http://127.0.0.1:18080
python3 ../poc/verify_handler_mismatch.py --target http://127.0.0.1:18080
python3 ../poc/verify_oom_trigger.py --host 127.0.0.1 --port 18081
python3 ../poc/verify_fpm_stale_state.py --target http://127.0.0.1:18080

# 运行 EXP
python3 ../exploit/chain_a_session_lfi.py --host 127.0.0.1 --port 18080 --command 'id'
```

## 仓库结构

```
php2shell-poc/
├── exploit/
│   ├── chain_a_session_lfi.py        # RCE：session 注入 + LFI
│   ├── chain_b_uaf_rce.php           # RCE：var_destroy UAF → handler 覆写
│   └── chain_c_mismatch_rce.py       # RCE：handler 不匹配 → __destruct
├── detection/
│   ├── php2shell.rules               # Suricata / Snort IDS 规则
│   ├── php2shell.yaml                # Sigma SIEM 检测规则
│   ├── modsecurity.conf              # ModSecurity WAF 规则
│   └── php2shell.lua                 # OpenResty / Nginx Lua WAF 模块
├── poc/
│   ├── verify_session_injection.py   # 验证利用链 A
│   ├── verify_uaf_asan.php           # 验证利用链 B（ASAN）
│   ├── verify_handler_mismatch.py    # 验证利用链 C
│   ├── verify_oom_trigger.py         # 验证利用链 D
│   └── verify_fpm_stale_state.py     # 验证利用链 E
├── lab/
│   ├── docker-compose.yml            # PHP-FPM + nginx + Apache mod_php
│   ├── setup.sh                      # 一键搭建实验环境
│   └── php.ini / php-apache.ini      # 存在漏洞的 PHP 配置
└── docs/
    ├── ANALYSIS.md                   # 完整技术分析
    ├── EXPLOITATION.md               # 野外利用追踪、IOC、下游影响
    ├── substack_article.md           # 分析文章原稿
    └── substack_exploitation_article.md  # 一周报告原稿
```

## 缓解措施

```ini
; 临时措施 —— 缩小攻击面
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

> **唯一彻底的修复方式是给 PHP 打补丁**，升级至 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 或更高版本。OOM 内存破坏（利用链 D）位于 Zend 引擎核心 —— 没有任何 INI 配置能够修复它。

对于不再受官方支持的 PHP 版本（5.4–8.1），社区维护的补丁回移（含部署自动化和验证工具）可在 [Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches) 获取。

## 野外利用情况

> **CISA KEV 已收录**（2026-10-26）&nbsp;|&nbsp; **蜜罐确认 RCE**（2026-10-24）&nbsp;|&nbsp; 24 小时内**数百万**次攻击尝试

完整分析：**[PHP2Shell 一周后](https://qideng.substack.com/p/php2shell-one-week-later-cisa-kev)**（Substack）&nbsp;|&nbsp; IOC 追踪：**[docs/EXPLOITATION.md](docs/EXPLOITATION.md)**

要点：
- **ASLR 绕过 PoC** 通过 `Set-Cookie` 泄漏地址 —— 在 x86_64 生产配置下可用，无需调试器
- **Potassium**（Mirai 变种）通过 php2shell 投递 —— ChaCha20 加密配置、20 种 DDoS 命令、反向 shell
- **下游预认证 RCE 已确认**：WordPress、Drupal、Joomla、Magento、Roundcube、phpMyAdmin、Nextcloud、Laravel、Symfony、MediaWiki、WooCommerce、Shopware、WHMCS

## 下游影响

Wiz 已在官方原版容器镜像上演示了预认证 RCE：

| 平台 | 是否受影响 | 说明 |
|----------|:----------:|-------|
| WordPress | 是 | 核心代码不使用 PHP session，但 WooCommerce 和大量插件会使用 |
| Joomla | 是 | 默认使用 PHP 原生 session |
| Drupal | 是 | 默认使用 PHP 原生 session |
| Magento | 是 | 即使处于维护模式（maintenance mode）仍可被利用 |
| Laravel | 是 | `PendingBroadcast` 是已知的 `__destruct` 利用 gadget |
| Roundcube | 是 | 邮件系统 —— 凭据泄露风险 |
| phpMyAdmin | 是 | 直接数据库访问 |
| Nextcloud | 是 | 文件存储系统 |
| Symfony | 是 | 框架级暴露 |
| MediaWiki | 是 | 维基平台 |
| WooCommerce | 是 | WordPress 插件；支付数据面临风险 |
| Shopware | 是 | 电商平台 |
| WHMCS | 是 | 主机控制面板 |

完整详情、IOC 和攻击工具追踪见 **[docs/EXPLOITATION.md](docs/EXPLOITATION.md)**。

## 参考链接

- [PHP 安全公告](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) —— CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) —— CVE-2026-109619
- [补丁提交 3584a98](https://github.com/php/php-src/commit/3584a98bda) —— 300 个文件，涉及 Zend 引擎与扩展
- [Cloudflare WAF 防护覆盖](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [Sansec 分析](https://sansec.io/research/php2shell) —— PHPSESSID 堆泄漏的发现
- [Wiz 下游影响分析](https://www.wiz.io/blog/php2shell-php-rce)
- [Corelight 检测方案](https://github.com/corelight/php2shell-detect) —— Zeek + Suricata 社区规则
- [Wiz 利用分析](https://www.wiz.io/blog/php2shell-exploitation-so-far) —— 蜜罐数据、修复进度
- [ELLIO 传感器数据](https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/) —— 首次发现时间线、payload 观察
- [VulnCheck exploit](https://www.vulncheck.com/blog/php2shell-vulnerabilities) —— 生产配置 ASLR 绕过
- [Nokia Deepfield Potassium](https://github.com/deepfield/public-research/tree/main/potassium) —— Mirai 变种 botnet 分析
- [社区 EOL 补丁回移（PHP 5.4–8.1）](https://github.com/Anton-Barinov/php2shell-patches) —— 经生产验证的补丁、部署工具和验证套件

## 免责声明

本仓库仅用于**经授权的安全测试与教学目的**。利用链 D、E（零依赖 RCE）的 EXP 仅向分析文章的[付费订阅用户](https://qideng.substack.com/p/php2shell-dissecting-phps-critical)提供。

## 许可证

MIT

---

<p align="center">
  <sub>
    <b>Keywords:</b> php2shell, CVE-2026-109618, CVE-2026-109619, PHP RCE, PHP exploit, session.upload_progress,
    pre-auth RCE, PHP vulnerability, PHP session injection, PHP deserialization, PHP OOM, PHP memory corruption,
    use-after-free, GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, WordPress RCE, Joomla RCE, Drupal RCE,
    PHP security, WAF rules, Suricata rules, ModSecurity rules, IDS signatures, PHP 8.2.35, PHP 8.4.27,
    session upload progress, PHP session fixation, rfc1867, longjmp, zend_bailout,
    Snort rules, Sigma rules, detection rules, PHP patch, PHP critical vulnerability
  </sub>
</p>
