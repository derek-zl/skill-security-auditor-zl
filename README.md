# skill-security-auditor-zl
# Skill Security Auditor — 特性总结

---

## 是什么

一个专门用于审查 Claude Skill 安全性的安全审计工具。在安装任何第三方 skill 之前，它会自动扫描其中的所有代码和配置文件，找出恶意行为并给出风险报告。

---

## 核心特性

### 🔍 自动触发

无需手动调用。上传 `.skill` 文件、说"帮我看看这个 skill 安不安全"，它就自动启动审计。

### 🌐 15+ 语言全覆盖

Shell、Python、JavaScript/TypeScript、Ruby、PHP、Go、Rust、PowerShell、Java/Kotlin、Swift、Lua、R、SQL、Dockerfile、.env 配置文件、package.json、requirements.txt。

### 📊 146 条检测规则，三级风险分级

| 级别 | 数量 | 含义 |
|------|------|------|
| 🔴 HIGH | 104 条 | 立即拦截：RCE、凭证盗取、提权、持久化后门 |
| 🟡 MEDIUM | 40 条 | 需人工确认：可疑网络请求、文件越界访问 |
| 🟢 LOW | 2 条 | 最佳实践提示：弱版本锁定等 |

### 🧠 六大检测能力

- **远程代码执行**：`curl | bash`、`eval()`、`IEX DownloadString`、`pickle` 反序列化等
- **凭证盗取**：SSH 私钥、AWS/GCP/Slack token、PEM 私钥块、数据库连接串
- **持久化后门**：写入 `.bashrc`、cron 注入、systemd 服务注册、Windows 注册表
- **提权**：`sudo`、写入系统目录、Docker 特权容器、LD_PRELOAD 劫持
- **Prompt 注入**：伪造 Anthropic 权威、隐藏指令、要求 Claude 对用户保密
- **代码混淆**：Base64 深度解码（自动还原并二次扫描）、hex 编码、字符串拼接隐藏函数名

### 🚦 高危拦截门控

发现任何 HIGH 级问题时，自动暂停并展示危险代码片段 + 具体修复建议，等用户确认后才继续。

### ✅ 经过验证

对 17 个真实 Anthropic 官方 skill 零误报，对构造的多语言恶意 skill 准确检出 22 个 HIGH 问题。

---

## 适用场景

- 安装来源不明的第三方 skill 前做安全审查
- 团队内部 skill 发布前的 CI 检查
- 学习和理解 skill 文件的安全边界