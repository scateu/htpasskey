## 设计概述

这是一个独立的 Go HTTPS 服务器，实现类似 `.htpasswd` 的 WebAuthn 认证方案：

1. **`.htpasskey` 文件**：存储已授权用户的 WebAuthn 公钥凭据（类似 `.htpasswd` / `authorized_keys`）
2. **注册流程**：未注册用户被 nginx 重定向到注册页面，注册后生成凭据文本，用户复制给管理员
3. **管理员授权**：管理员通过 `pbpaste >> .htpasskey` 方式添加凭据
4. **认证流程**：nginx `auth_request` 子请求到本服务，验证 WebAuthn 断言


```
Usage of ./webauthn-gate:
  -backend string
        reverse proxy backend (e.g. http://127.0.0.1:3000)
  -htpasskey string
        credential file path (default ".htpasskey")
  -listen string
        listen address (default ":8443")
  -prefix string
        auth endpoint prefix (default "/__webauthn")
  -rp-id string
        WebAuthn RP ID (domain) (default "localhost")
  -rp-name string
        RP display name (default "WebAuthn Gate")
  -rp-origin string
        RP origin (default: https://<rp-id>:<port>)
  -session-ttl duration
        session lifetime (default 24h0m0s)
  -tls-cert string
        TLS cert file (omit = self-signed)
  -tls-key string
        TLS key file
  -webroot string
        serve static files from this dir (if no backend)
```
## 构建与运行

```bash
# 初始化
go mod tidy
go build -o webauthn-gate .

# 最简运行（自签证书，内置欢迎页）
./webauthn-gate

# 反向代理模式（保护后端服务）
./webauthn-gate -backend http://127.0.0.1:3000

# 静态文件模式（保护目录）
./webauthn-gate -webroot ./public

# 完整参数
./webauthn-gate \
  -listen :443 \
  -rp-id example.com \
  -rp-origin https://example.com \
  -tls-cert /etc/ssl/cert.pem \
  -tls-key /etc/ssl/key.pem \
  -htpasskey /etc/webauthn/.htpasskey \
  -backend /fwd?q=aHR0cDovLzEyNy4wLjAu1:8080 \
  -session-ttl 12h
```

## 使用流程

### 1. 用户注册

```
浏览器访问 https://yoursite/__webauthn/register
  → 输入用户名，触发 Touch ID / Windows Hello / 安全密钥
  → 得到一段凭据文本
  → 用户把这段文本发给管理员（Slack、邮件等）
```

### 2. 管理员授权

```bash
# macOS: 用户把凭据复制到剪贴板发过来
pbpaste >> .htpasskey

# 或直接编辑
echo '# alice | cred:AbCdEf... | 2024-01-15
alice:eyJ1Ijoi...' >> .htpasskey

# 服务自动检测文件变更并重新加载，无需重启
```

### 3. 用户登录

```
浏览器访问任意受保护页面
  → 自动 302 重定向到 /__webauthn/login
  → 点击 "Login with Passkey" 或输入用户名
  → Touch ID / 安全密钥验证
  → 跳回原始页面
```

---

## .htpasskey 文件格式

```
# .htpasskey — WebAuthn credentials
# 格式: username:base64(json)
# 服务自动监测文件修改，热加载

# alice | cred:R0x1Y2tJZEhlcm... | 2024-07-15T08:30:00Z
alice:eyJ1IjoiYWxpY2UiLCJpZCI6IlIweDFZMnRKWkdobGNnIiwicHViIjoicE...

# bob | cred:U2VjdXJpdHlLZX... | 2024-07-16T10:00:00Z
bob:eyJ1IjoiYm9iIiwiaWQiOiJVMlZqZFhKcGRIbExaWGgi...
```



