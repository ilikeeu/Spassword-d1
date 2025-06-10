以下是将您提供的说明转换为 GitHub README 文档格式的内容。这个格式包含了标题、列表、代码块以及一些 Markdown 常见的视觉增强元素，使其在 GitHub 上更易读。

-----

# 智能密码管理助手 Pro - Cloudflare Workers 部署指南

本指南将详细指导您如何在 Cloudflare Workers 和 D1 数据库上直接部署您的密码管理器后端。

## 📋 完整部署步骤

### 1️⃣ 创建 D1 数据库

1.  **登录 Cloudflare Dashboard**
      * 访问 [https://dash.cloudflare.com](https://dash.cloudflare.com)
      * 登录您的 Cloudflare 账户。
2.  **创建 D1 数据库**
      * 在左侧菜单中找到并点击 "**Workers & Pages**"。
      * 点击 "**D1 SQL Database**"。
      * 点击 "**Create database**"。
      * 在数据库名称输入框中填写：`password-manager-db`
      * 点击 "**Create**"。
3.  **记录数据库信息**
      * 数据库创建完成后，请务必记录下 **Database ID** (格式类似：`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)。

### 2️⃣ 创建 Worker

1.  **进入 Workers 页面**
      * 在 Cloudflare Dashboard 中，点击 "**Workers & Pages**"。
      * 点击 "**Create application**"。
      * 选择 "**Create Worker**"。
2.  **配置 Worker**
      * 为 Worker 输入一个名称，例如：`password-manager` (或您喜欢的其他名称)。
      * 点击 "**Deploy**"。

### 3️⃣ 上传代码

1.  **编辑 Worker 代码**
      * 在 Worker 详情页面，点击 "**Edit code**" 按钮。
      * 删除编辑器中的所有默认代码。
      * 粘贴您提供的完整 Worker 代码（即您 Worker 后端的 JavaScript 代码）。
      * 点击右上角的 "**Save and deploy**" 保存并部署代码。

### 4️⃣ 绑定 D1 数据库

1.  **进入 Worker 设置**
      * 在 Worker 详情页面，点击顶部的 "**Settings**" 标签。
2.  **添加 D1 绑定**
      * 向下滚动找到 "**Variables**" 部分。
      * 在 "**D1 database bindings**" (D1 数据库绑定) 部分，点击 "**Add binding**"。
      * **Variable name (变量名)**: 填写 `DB`
      * **D1 database (D1 数据库)**: 从下拉列表中选择您在步骤 1 中创建的 `password-manager-db`。
      * 点击 "**Save**"。

### 5️⃣ 配置环境变量

在 Worker 设置的 "**Environment variables**" (环境变量) 部分添加以下变量：

```ini
# 必需的 OAuth 配置
OAUTH_BASE_URL = https://your-oauth-server.com
OAUTH_CLIENT_ID = your_client_id  
OAUTH_CLIENT_SECRET = your_client_secret
OAUTH_REDIRECT_URI = https://your-worker-name.your-subdomain.workers.dev/api/oauth/callback

# 可选：限制访问的用户ID
OAUTH_ID = your_authorized_user_id 
```

**添加步骤：**

1.  点击 "**Add variable**"。
2.  输入变量名和对应的实际值。
3.  对于包含敏感信息（如 `OAUTH_CLIENT_SECRET`）的变量，请务必勾选旁边的 "**Encrypt**" (加密) 复选框。
4.  点击 "**Save**"。

### 6️⃣ OAuth 服务器配置示例

如果您还没有 OAuth 服务器，可以参考以下使用 GitHub OAuth 的免费服务示例：

#### 使用 GitHub OAuth

1.  **创建 GitHub OAuth App**

      * 访问 [https://github.com/settings/developers](https://github.com/settings/developers)
      * 点击 "**New OAuth App**"。
      * 填写应用信息：
          * **Application name (应用名称)**: `Password Manager` (或您喜欢的名称)
          * **Homepage URL (主页 URL)**: `https://your-worker-name.your-subdomain.workers.dev` (替换为您的 Worker URL)
          * **Authorization callback URL (授权回调 URL)**: `https://your-worker-name.your-subdomain.workers.dev/api/oauth/callback` (替换为您的 Worker URL)

2.  **获取配置信息**

      * 在应用详情页面，您可以看到 **Client ID**。
      * 点击 "**Generate a new client secret**" (生成新的客户端密钥) 以获取 **Client Secret**。

3.  **环境变量配置**
    将获取到的信息配置到 Cloudflare Worker 的环境变量中：

    ```ini
    OAUTH_BASE_URL = https://github.com
    OAUTH_CLIENT_ID = 你的GitHub_Client_ID
    OAUTH_CLIENT_SECRET = 你的GitHub_Client_Secret  
    OAUTH_REDIRECT_URI = https://your-worker-name.your-subdomain.workers.dev/api/oauth/callback
    # 可选：限制只有你的GitHub用户ID可以访问
    OAUTH_ID = 你的GitHub用户ID
    ```

#### 如何获取 GitHub 用户ID

1.  访问 [https://api.github.com/users/your-username](https://api.github.com/users/your-username) (将 `your-username` 替换为您的 GitHub 用户名)。
2.  查看返回的 JSON 数据中的 `id` 字段，该字段即为您的 GitHub 用户 ID。

### 7️⃣ 完整的环境变量配置截图指南

在 Cloudflare Worker 设置页面：

**Settings \> Variables**

**D1 database bindings:**

```
┌─────────────────────────────────────────┐
│ Variable name: DB                       │
│ D1 database: password-manager-db        │
└─────────────────────────────────────────┘
```

**Environment variables:**

```
┌─────────────────────────────────────────┐
│ OAUTH_BASE_URL                          │
│ Value: https://github.com               │
│ ☐ Encrypt                               │
├─────────────────────────────────────────┤
│ OAUTH_CLIENT_ID                         │
│ Value: ghp_xxxxxxxxxxxxxxxxxxxx         │
│ ☐ Encrypt                               │
├─────────────────────────────────────────┤
│ OAUTH_CLIENT_SECRET                     │
│ Value: ************************ │
│ ☑ Encrypt                               │
├─────────────────────────────────────────┤
│ OAUTH_REDIRECT_URI                      │
│ Value: https://password-manager.your-   │
│        subdomain.workers.dev/api/oauth/ │
│        callback                         │
│ ☐ Encrypt                               │
├─────────────────────────────────────────┤
│ OAUTH_ID (可选)                         │
│ Value: 12345678                         │
│ ☐ Encrypt                               │
└─────────────────────────────────────────┘
```

### 8️⃣ 部署和测试

1.  **保存配置**
      * 确保所有 D1 绑定和环境变量都已正确添加。
      * 点击页面右上角或底部的 "**Save and deploy**" (保存并部署) 按钮。
2.  **访问应用**
      * 访问您的 Worker URL：`https://your-worker-name.your-subdomain.workers.dev` (替换为您的实际 Worker URL)。
      * 首次访问时，Worker 会自动创建 D1 数据库所需的表结构。
      * 点击页面上的 "**开始使用 OAuth 登录**" 按钮，测试登录功能。

### 9️⃣ 故障排除

#### 常见问题和解决方案

  * **数据库连接失败**
      * **错误信息**：`Database binding 'DB' not found`
      * **解决方法**：检查 D1 数据库绑定是否正确配置，确保变量名是 `DB` 且指向正确的 D1 数据库。
  * **OAuth 登录失败**
      * **错误信息**：`OAuth configuration missing`
      * **解决方法**：检查所有 OAuth 相关的环境变量是否都已正确设置并包含正确的值。
  * **重定向 URL 不匹配**
      * **错误信息**：`redirect_uri_mismatch`
      * **解决方法**：确保您在 OAuth 服务器（如 GitHub OAuth App）中配置的 **Authorization callback URL** 与 Cloudflare Worker 环境变量 `OAUTH_REDIRECT_URI` 的值完全一致。URL 中的 `http/https`、域名、路径甚至末尾的斜杠都必须完全匹配。

### 🔧 高级配置

#### 自定义域名（可选）

1.  在 Worker 详情页面，点击 "**Settings**" (设置) 标签。
2.  点击 "**Triggers**" (触发器)。
3.  点击 "**Add Custom Domain**" (添加自定义域名)。
4.  输入您的自定义域名（请确保该域名已在 Cloudflare 上托管 DNS）。

#### 安全建议

  * **启用访问限制**：设置 `OAUTH_ID` 环境变量可以限制只有您的 GitHub 用户 ID 才能访问密码管理器，增加安全性。
  * **定期更新密钥**：定期更换您的 OAuth Client Secret，以增强安全性。
  * **监控使用情况**：在 Worker 的 "**Analytics**" (分析) 页面中查看访问日志和使用情况，以便及时发现异常。

### 📱 使用指南

部署完成后，您的密码管理器将具备以下功能：

  * ✅ **安全登录**：支持 OAuth 第三方认证，保障账户安全。
  * ✅ **密码管理**：轻松添加、编辑、删除和搜索您的所有密码。
  * ✅ **历史记录**：自动保存密码变更历史，并支持恢复到之前的版本。
  * ✅ **分类管理**：对密码进行分类和筛选，便于查找。
  * ✅ **云备份**：支持 WebDAV 云端备份和恢复，确保数据安全。
  * ✅ **数据导入导出**：支持加密的数据导入和导出功能。
  * ✅ **响应式设计**：完美适配桌面和移动设备，随时随地管理密码。

现在您就可以开始使用这个功能完整的密码管理器了！

-----
