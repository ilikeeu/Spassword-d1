// 基于HTML5的增强版密码管理器 - Cloudflare Workers + D1 + OAuth + 分页功能 + 密码历史管理
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 设置CORS头
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // 初始化数据库表（首次访问时自动创建）
      await initializeDatabase(env);

      // 路由处理
      if (path === '/' || path === '/index.html') {
        return new Response(getHTML5(), {
          headers: { 'Content-Type': 'text/html', ...corsHeaders }
        });
      }
      
      if (path === '/api/oauth/login') {
        return handleOAuthLogin(request, env, corsHeaders);
      }
      
      if (path === '/api/oauth/callback') {
        return handleOAuthCallback(request, env, corsHeaders);
      }
      
      if (path === '/api/auth/verify') {
        return handleAuthVerify(request, env, corsHeaders);
      }
      
      if (path === '/api/auth/logout') {
        return handleLogout(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/passwords')) {
        if (path.endsWith('/reveal')) {
          return getActualPassword(request, env, corsHeaders);
        }
        if (path.endsWith('/history')) {
          return handlePasswordHistory(request, env, corsHeaders);
        }
        if (path === '/api/passwords/restore') {
          return handleRestorePassword(request, env, corsHeaders);
        }
        if (path === '/api/passwords/delete-history') {
          return handleDeletePasswordHistory(request, env, corsHeaders);
        }
        return handlePasswords(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/categories')) {
        return handleCategories(request, env, corsHeaders);
      }
      
      if (path === '/api/generate-password') {
        return handleGeneratePassword(request, env, corsHeaders);
      }
      
      if (path === '/api/export-encrypted') {
        return handleEncryptedExport(request, env, corsHeaders);
      }
      
      if (path === '/api/import-encrypted') {
        return handleEncryptedImport(request, env, corsHeaders);
      }
      
      if (path.startsWith('/api/webdav')) {
        return handleWebDAV(request, env, corsHeaders);
      }
      
      // 登录检测和保存API
      if (path === '/api/detect-login') {
        return handleDetectLogin(request, env, corsHeaders);
      }
      
      // 自动填充API
      if (path === '/api/auto-fill') {
        return handleAutoFill(request, env, corsHeaders);
      }
      
      // 账户去重检查API
      if (path === '/api/check-duplicate') {
        return handleCheckDuplicate(request, env, corsHeaders);
      }
      
      // 更新现有密码API
      if (path === '/api/update-existing-password') {
        return handleUpdateExistingPassword(request, env, corsHeaders);
      }
      
      // 获取用户信息API
      if (path === '/api/user') {
        return handleGetUser(request, env, corsHeaders);
      }
      
      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (error) {
      console.error('Error:', error);
      return new Response(JSON.stringify({ 
        error: 'Internal Server Error',
        message: error.message 
      }), { 
        status: 500, 
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};

// 初始化数据库表
async function initializeDatabase(env) {
  try {
    // 检查表是否已存在
    const checkTables = await env.DB.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name IN ('users', 'passwords', 'password_history', 'categories', 'webdav_configs', 'sessions', 'oauth_states')
    `).all();

    if (checkTables.results.length === 7) {
      // 所有表都已存在
      return;
    }

    console.log('初始化数据库表...');

    // 创建用户表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        nickname TEXT,
        email TEXT,
        avatar TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    // 创建会话表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        user_data TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `).run();

    // 创建OAuth状态表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS oauth_states (
        state TEXT PRIMARY KEY,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL
      )
    `).run();

    // 创建密码表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS passwords (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        site_name TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        url TEXT,
        category TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        restored_from TEXT,
        imported_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `).run();

    // 创建密码历史记录表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS password_history (
        id TEXT PRIMARY KEY,
        password_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        old_password TEXT NOT NULL,
        changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reason TEXT DEFAULT 'password_update',
        FOREIGN KEY (password_id) REFERENCES passwords (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `).run();

    // 创建分类表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, name),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `).run();

    // 创建WebDAV配置表
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS webdav_configs (
        user_id TEXT PRIMARY KEY,
        webdav_url TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `).run();

    // 创建索引以提高查询性能
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords (user_id)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_passwords_site_name ON passwords (site_name)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_passwords_username ON passwords (username)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_password_history_password_id ON password_history (password_id)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states (expires_at)`).run();

    console.log('数据库表初始化完成');

    // 清理过期数据
    await cleanupExpiredData(env);

  } catch (error) {
    console.error('数据库初始化失败:', error);
    throw error;
  }
}

// 清理过期数据
async function cleanupExpiredData(env) {
  try {
    const now = new Date().toISOString();
    
    // 清理过期会话
    await env.DB.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(now).run();
    
    // 清理过期OAuth状态
    await env.DB.prepare(`DELETE FROM oauth_states WHERE expires_at < ?`).bind(now).run();
    
  } catch (error) {
    console.error('清理过期数据失败:', error);
  }
}

// OAuth登录处理
async function handleOAuthLogin(request, env, corsHeaders) {
  try {
    console.log('OAuth login request received');

    if (!env.OAUTH_BASE_URL || !env.OAUTH_CLIENT_ID || !env.OAUTH_REDIRECT_URI) {
      console.error('Missing OAuth configuration');
      return new Response(JSON.stringify({ 
        error: 'OAuth configuration missing',
        details: 'Please configure OAUTH_BASE_URL, OAUTH_CLIENT_ID, and OAUTH_REDIRECT_URI'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const state = generateRandomString(32);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10分钟后过期

    // 构建授权URL
    const authUrl = new URL(`${env.OAUTH_BASE_URL}/oauth2/authorize`);
    authUrl.searchParams.set('client_id', env.OAUTH_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', env.OAUTH_REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('state', state);

    // 保存state到数据库
    await env.DB.prepare(`
      INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)
    `).bind(state, expiresAt).run();

    console.log('Generated OAuth URL:', authUrl.toString());

    return new Response(JSON.stringify({ 
      success: true,
      authUrl: authUrl.toString(),
      state: state 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });

  } catch (error) {
    console.error('OAuth login error:', error);
    return new Response(JSON.stringify({
      error: 'Failed to generate OAuth URL',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// OAuth回调处理
async function handleOAuthCallback(request, env, corsHeaders) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  console.log('OAuth callback received:', { code: !!code, state, error });

  if (error) {
    return new Response(generateErrorPage('OAuth 登录失败', `错误信息: ${error}`), {
      status: 400,
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }

  if (!code || !state) {
    return new Response(generateErrorPage('OAuth 参数错误', 'OAuth 回调缺少 code 或 state 参数'), {
      status: 400,
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }

  // 验证state
  const stateResult = await env.DB.prepare(`
    SELECT state FROM oauth_states WHERE state = ? AND expires_at > ?
  `).bind(state, new Date().toISOString()).first();

  if (!stateResult) {
    return new Response(generateErrorPage('OAuth State 验证失败', '无效的 state 参数，可能是过期或被篡改'), {
      status: 400,
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }

  // 删除已使用的state
  await env.DB.prepare(`DELETE FROM oauth_states WHERE state = ?`).bind(state).run();

  try {
    console.log('Exchanging code for token...');

    // 交换授权码获取访问令牌
    const tokenResponse = await fetch(`${env.OAUTH_BASE_URL}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${btoa(`${env.OAUTH_CLIENT_ID}:${env.OAUTH_CLIENT_SECRET}`)}`
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: env.OAUTH_REDIRECT_URI
      })
    });

    console.log('Token response status:', tokenResponse.status);

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', errorText);
      throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errorText}`);
    }

    const tokenData = await tokenResponse.json();
    console.log('Token data received:', { access_token: !!tokenData.access_token });

    // 获取用户信息
    const userResponse = await fetch(`${env.OAUTH_BASE_URL}/api/user`, {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept': 'application/json'
      }
    });

    console.log('User response status:', userResponse.status);

    if (!userResponse.ok) {
      const errorText = await userResponse.text();
      console.error('Failed to get user info:', errorText);
      throw new Error(`Failed to get user info: ${userResponse.status} - ${errorText}`);
    }

    const userData = await userResponse.json();
    console.log('User data received:', { id: userData.id, username: userData.username });

    // 检查用户授权
    if (env.OAUTH_ID && userData.id.toString() !== env.OAUTH_ID) {
      return new Response(generateErrorPage(
        '访问被拒绝',
        '抱歉，您没有访问此密码管理器的权限。',
        `用户ID: ${userData.id}<br>用户名: ${userData.username}<br>授权ID: ${env.OAUTH_ID || '未设置'}`
      ), {
        status: 403,
        headers: { 'Content-Type': 'text/html', ...corsHeaders }
      });
    }

    // 保存或更新用户信息
    await env.DB.prepare(`
      INSERT OR REPLACE INTO users (id, username, nickname, email, avatar, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      userData.id.toString(),
      userData.username,
      userData.nickname || userData.username,
      userData.email || '',
      userData.avatar_template || 'https://yanxuan.nosdn.127.net/233a2a8170847d3287ec058c51cf60a9.jpg',
      new Date().toISOString()
    ).run();

    // 创建会话令牌
    const sessionToken = generateRandomString(64);
    const userSession = {
      userId: userData.id.toString(),
      username: userData.username,
      nickname: userData.nickname || userData.username,
      email: userData.email || '',
      avatar: userData.avatar_template || 'https://yanxuan.nosdn.127.net/233a2a8170847d3287ec058c51cf60a9.jpg',
      loginAt: new Date().toISOString()
    };

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7天后过期

    // 保存会话
    await env.DB.prepare(`
      INSERT INTO sessions (token, user_id, user_data, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(sessionToken, userData.id.toString(), JSON.stringify(userSession), expiresAt).run();

    console.log('Session created for user:', userData.username);

    return new Response(generateSuccessPage(userSession, sessionToken), {
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });

  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(generateErrorPage('登录失败', 'OAuth 认证过程中发生错误，请稍后重试。', `错误详情: ${error.message}`), {
      status: 500,
      headers: { 'Content-Type': 'text/html', ...corsHeaders }
    });
  }
}

// 验证登录状态
async function handleAuthVerify(request, env, corsHeaders) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return new Response(JSON.stringify({ authenticated: false }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const session = await env.DB.prepare(`
    SELECT user_data FROM sessions WHERE token = ? AND expires_at > ?
  `).bind(token, new Date().toISOString()).first();

  if (session) {
    const userData = JSON.parse(session.user_data);

    // 检查用户授权
    if (env.OAUTH_ID && userData.userId !== env.OAUTH_ID) {
      return new Response(JSON.stringify({ 
        authenticated: false,
        error: 'Unauthorized user'
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    return new Response(JSON.stringify({ 
      authenticated: true, 
      user: userData 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  return new Response(JSON.stringify({ authenticated: false }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 获取用户信息API
async function handleGetUser(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  return new Response(JSON.stringify({
    id: session.userId,
    username: session.username,
    nickname: session.nickname,
    email: session.email,
    avatar: session.avatar
  }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 登出处理
async function handleLogout(request, env, corsHeaders) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');

  if (token) {
    await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
  }

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 密码历史记录功能
async function savePasswordHistory(existingPassword, userId, env) {
  const historyEntry = {
    id: generateId(),
    passwordId: existingPassword.id,
    oldPassword: existingPassword.password, // 已加密
    changedAt: new Date().toISOString(),
    reason: 'password_update'
  };

  // 保存到历史记录
  await env.DB.prepare(`
    INSERT INTO password_history (id, password_id, user_id, old_password, changed_at, reason)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    historyEntry.id,
    historyEntry.passwordId,
    userId,
    historyEntry.oldPassword,
    historyEntry.changedAt,
    historyEntry.reason
  ).run();

  // 只保留最近5次历史记录
  const oldHistories = await env.DB.prepare(`
    SELECT id FROM password_history 
    WHERE password_id = ? AND user_id = ? 
    ORDER BY changed_at DESC 
    LIMIT -1 OFFSET 5
  `).bind(historyEntry.passwordId, userId).all();

  if (oldHistories.results.length > 0) {
    const idsToDelete = oldHistories.results.map(h => h.id);
    const placeholders = idsToDelete.map(() => '?').join(',');
    await env.DB.prepare(`
      DELETE FROM password_history WHERE id IN (${placeholders})
    `).bind(...idsToDelete).run();
  }
}

// 获取密码历史记录API
async function handlePasswordHistory(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const url = new URL(request.url);
  const pathParts = url.pathname.split('/');
  const passwordId = pathParts[pathParts.length - 2];
  const userId = session.userId;

  try {
    const historyResults = await env.DB.prepare(`
      SELECT * FROM password_history 
      WHERE password_id = ? AND user_id = ? 
      ORDER BY changed_at DESC
    `).bind(passwordId, userId).all();

    // 解密历史密码
    const decryptedHistory = await Promise.all(
      historyResults.results.map(async (entry) => ({
        id: entry.id,
        passwordId: entry.password_id,
        oldPassword: await decryptPassword(entry.old_password, userId),
        changedAt: entry.changed_at,
        reason: entry.reason
      }))
    );

    return new Response(JSON.stringify({ history: decryptedHistory }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('获取历史记录失败:', error);
    return new Response(JSON.stringify({ 
      error: '获取历史记录失败',
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 恢复历史密码API
async function handleRestorePassword(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { passwordId, historyId } = await request.json();
  const userId = session.userId;

  try {
    // 获取当前密码
    const currentPassword = await env.DB.prepare(`
      SELECT * FROM passwords WHERE id = ? AND user_id = ?
    `).bind(passwordId, userId).first();

    if (!currentPassword) {
      return new Response(JSON.stringify({ error: '密码不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // 获取历史记录
    const historyEntry = await env.DB.prepare(`
      SELECT * FROM password_history WHERE id = ? AND password_id = ? AND user_id = ?
    `).bind(historyId, passwordId, userId).first();

    if (!historyEntry) {
      return new Response(JSON.stringify({ error: '历史记录不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // 保存当前密码到历史记录
    await savePasswordHistory(currentPassword, userId, env);

    // 恢复历史密码
    await env.DB.prepare(`
      UPDATE passwords 
      SET password = ?, updated_at = ?, restored_from = ?
      WHERE id = ? AND user_id = ?
    `).bind(
      historyEntry.old_password,
      new Date().toISOString(),
      historyEntry.id,
      passwordId,
      userId
    ).run();

    return new Response(JSON.stringify({ 
      success: true, 
      message: '密码已恢复到历史版本' 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('恢复密码失败:', error);
    return new Response(JSON.stringify({ 
      error: '恢复密码失败',
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 删除历史密码记录API
async function handleDeletePasswordHistory(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { passwordId, historyId } = await request.json();
  const userId = session.userId;

  try {
    if (historyId === 'all') {
      // 删除所有历史记录
      const result = await env.DB.prepare(`
        DELETE FROM password_history WHERE password_id = ? AND user_id = ?
      `).bind(passwordId, userId).run();

      return new Response(JSON.stringify({ 
        success: true, 
        message: `已删除所有 ${result.changes} 条历史记录`,
        deletedCount: result.changes
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      // 删除指定的历史记录
      const result = await env.DB.prepare(`
        DELETE FROM password_history WHERE id = ? AND password_id = ? AND user_id = ?
      `).bind(historyId, passwordId, userId).run();

      if (result.changes === 0) {
        return new Response(JSON.stringify({ error: '要删除的历史记录不存在' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const remainingCount = await env.DB.prepare(`
        SELECT COUNT(*) as count FROM password_history WHERE password_id = ? AND user_id = ?
      `).bind(passwordId, userId).first();

      return new Response(JSON.stringify({ 
        success: true, 
        message: '历史记录已删除',
        deletedCount: 1,
        remainingCount: remainingCount.count
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  } catch (error) {
    console.error('删除历史记录失败:', error);
    return new Response(JSON.stringify({ 
      error: '删除历史记录失败',
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 密码条目处理
async function handlePasswords(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const url = new URL(request.url);
  const id = url.pathname.split('/').pop();
  const userId = session.userId;

  // 获取分页参数
  const page = parseInt(url.searchParams.get('page')) || 1;
  const limit = parseInt(url.searchParams.get('limit')) || 50;
  const search = url.searchParams.get('search') || '';
  const category = url.searchParams.get('category') || '';

  switch (request.method) {
    case 'GET':
      if (id && id !== 'passwords') {
        try {
          const password = await env.DB.prepare(`
            SELECT * FROM passwords WHERE id = ? AND user_id = ?
          `).bind(id, userId).first();

          if (password) {
            return new Response(JSON.stringify({
              id: password.id,
              siteName: password.site_name,
              username: password.username,
              password: '••••••••',
              url: password.url,
              category: password.category,
              notes: password.notes,
              createdAt: password.created_at,
              updatedAt: password.updated_at
            }), {
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
          return new Response(JSON.stringify({ error: '未找到' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (error) {
          console.error('获取密码失败:', error);
          return new Response(JSON.stringify({ 
            error: '获取密码失败',
            message: error.message 
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      } else {
        try {
          // 构建查询条件
          let whereClause = 'WHERE user_id = ?';
          let params = [userId];

          if (search) {
            whereClause += ' AND (site_name LIKE ? OR username LIKE ? OR notes LIKE ? OR url LIKE ?)';
            const searchPattern = `%${search}%`;
            params.push(searchPattern, searchPattern, searchPattern, searchPattern);
          }

          if (category) {
            whereClause += ' AND category = ?';
            params.push(category);
          }

          // 获取总数
          const countResult = await env.DB.prepare(`
            SELECT COUNT(*) as total FROM passwords ${whereClause}
          `).bind(...params).first();

          const total = countResult.total;
          const totalPages = Math.ceil(total / limit);
          const offset = (page - 1) * limit;

          // 获取分页数据
          const passwords = await env.DB.prepare(`
            SELECT * FROM passwords ${whereClause}
            ORDER BY category, site_name
            LIMIT ? OFFSET ?
          `).bind(...params, limit, offset).all();

          const formattedPasswords = passwords.results.map(p => ({
            id: p.id,
            siteName: p.site_name,
            username: p.username,
            password: '••••••••',
            url: p.url,
            category: p.category,
            notes: p.notes,
            createdAt: p.created_at,
            updatedAt: p.updated_at
          }));

          return new Response(JSON.stringify({
            passwords: formattedPasswords,
            pagination: {
              page,
              limit,
              total,
              totalPages,
              hasNext: page < totalPages,
              hasPrev: page > 1
            }
          }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        } catch (error) {
          console.error('获取密码列表失败:', error);
          return new Response(JSON.stringify({ 
            error: '获取密码列表失败',
            message: error.message,
            passwords: [],
            pagination: {
              page: 1,
              limit: 50,
              total: 0,
              totalPages: 0,
              hasNext: false,
              hasPrev: false
            }
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }
      
    case 'POST':
      try {
        const newPassword = await request.json();
        
        // 检查重复
        const duplicateCheck = await checkForDuplicates(newPassword, userId, env, true);
        if (duplicateCheck.isDuplicate) {
          if (duplicateCheck.isIdentical) {
            return new Response(JSON.stringify({
              error: '检测到完全相同的账户',
              duplicate: true,
              identical: true,
              existing: duplicateCheck.existing,
              message: '该账户已存在且密码相同：' + duplicateCheck.existing.siteName + ' - ' + duplicateCheck.existing.username
            }), {
              status: 409,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          } else if (duplicateCheck.passwordChanged) {
            return new Response(JSON.stringify({
              error: '检测到相同账号的密码变更',
              duplicate: true,
              passwordChanged: true,
              existing: duplicateCheck.existing,
              newPassword: newPassword.password,
              message: '检测到相同账号的密码变更，是否更新现有账户的密码？',
              updateAction: 'update_password',
              shouldUpdate: true
            }), {
              status: 409,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
        }
        
        const passwordId = generateId();
        const now = new Date().toISOString();
        
        // 自动提取域名作为网站名称
        if (newPassword.url && !newPassword.siteName) {
          try {
            const urlObj = new URL(newPassword.url);
            newPassword.siteName = urlObj.hostname.replace('www.', '');
          } catch (e) {
            // 忽略URL解析错误
          }
        }
        
        const encryptedPassword = await encryptPassword(newPassword.password, userId);
        
        await env.DB.prepare(`
          INSERT INTO passwords (id, user_id, site_name, username, password, url, category, notes, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          passwordId,
          userId,
          newPassword.siteName,
          newPassword.username,
          encryptedPassword,
          newPassword.url || null,
          newPassword.category || null,
          newPassword.notes || null,
          now,
          now
        ).run();
        
        // 添加分类（如果不存在）
        if (newPassword.category) {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)
          `).bind(userId, newPassword.category).run();
        }
        
        const responseData = {
          id: passwordId,
          siteName: newPassword.siteName,
          username: newPassword.username,
          password: '••••••••',
          url: newPassword.url,
          category: newPassword.category,
          notes: newPassword.notes,
          createdAt: now,
          updatedAt: now
        };
        
        return new Response(JSON.stringify(responseData), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      } catch (error) {
        console.error('创建密码失败:', error);
        return new Response(JSON.stringify({ 
          error: '创建密码失败',
          message: error.message 
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
    case 'PUT':
      if (!id || id === 'passwords') {
        return new Response(JSON.stringify({ error: '缺少ID' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      try {
        const existingPassword = await env.DB.prepare(`
          SELECT * FROM passwords WHERE id = ? AND user_id = ?
        `).bind(id, userId).first();

        if (!existingPassword) {
          return new Response(JSON.stringify({ error: '未找到' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        
        const updateData = await request.json();
        const now = new Date().toISOString();
        
        // 如果密码发生变更，保存历史记录
        if (updateData.password) {
          const newEncryptedPassword = await encryptPassword(updateData.password, userId);
          const oldDecryptedPassword = await decryptPassword(existingPassword.password, userId);
          
          if (oldDecryptedPassword !== updateData.password) {
            // 保存历史记录
            await savePasswordHistory(existingPassword, userId, env);
          }
          
          updateData.password = newEncryptedPassword;
        }
        
        // 更新密码
        await env.DB.prepare(`
          UPDATE passwords 
          SET site_name = COALESCE(?, site_name),
              username = COALESCE(?, username),
              password = COALESCE(?, password),
              url = ?,
              category = ?,
              notes = ?,
              updated_at = ?
          WHERE id = ? AND user_id = ?
        `).bind(
          updateData.siteName || null,
          updateData.username || null,
          updateData.password || null,
          updateData.url || null,
          updateData.category || null,
          updateData.notes || null,
          now,
          id,
          userId
        ).run();

        // 添加分类（如果不存在）
        if (updateData.category) {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)
          `).bind(userId, updateData.category).run();
        }
        
        const updatedPassword = await env.DB.prepare(`
          SELECT * FROM passwords WHERE id = ? AND user_id = ?
        `).bind(id, userId).first();
        
        const responseData = {
          id: updatedPassword.id,
          siteName: updatedPassword.site_name,
          username: updatedPassword.username,
          password: '••••••••',
          url: updatedPassword.url,
          category: updatedPassword.category,
          notes: updatedPassword.notes,
          createdAt: updatedPassword.created_at,
          updatedAt: updatedPassword.updated_at
        };
        
        return new Response(JSON.stringify(responseData), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      } catch (error) {
        console.error('更新密码失败:', error);
        return new Response(JSON.stringify({ 
          error: '更新密码失败',
          message: error.message 
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
    case 'DELETE':
      if (!id || id === 'passwords') {
        return new Response(JSON.stringify({ error: '缺少ID' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      try {
        // 删除密码和相关历史记录
        await env.DB.prepare(`DELETE FROM passwords WHERE id = ? AND user_id = ?`).bind(id, userId).run();
        await env.DB.prepare(`DELETE FROM password_history WHERE password_id = ? AND user_id = ?`).bind(id, userId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      } catch (error) {
        console.error('删除密码失败:', error);
        return new Response(JSON.stringify({ 
          error: '删除密码失败',
          message: error.message 
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
    default:
      return new Response('Method not allowed', { 
        status: 405, 
        headers: corsHeaders 
      });
  }
}

// 检查重复账户
async function checkForDuplicates(newPassword, userId, env, checkPassword = false) {
  if (!newPassword.url || !newPassword.username) {
    return { isDuplicate: false };
  }

  try {
    const newUrl = new URL(newPassword.url);
    const newDomain = newUrl.hostname.replace('www.', '').toLowerCase();
    const newUsername = newPassword.username.toLowerCase().trim();

    const existingPasswords = await env.DB.prepare(`
      SELECT * FROM passwords WHERE user_id = ?
    `).bind(userId).all();

    for (const existing of existingPasswords.results) {
      // 跳过正在编辑的同一条记录
      if (newPassword.id && existing.id === newPassword.id) {
        continue;
      }
      
      if (existing.url && existing.username) {
        try {
          const existingUrl = new URL(existing.url);
          const existingDomain = existingUrl.hostname.replace('www.', '').toLowerCase();
          const existingUsername = existing.username.toLowerCase().trim();
          
          // 检查域名和用户名是否完全匹配
          if (existingDomain === newDomain && existingUsername === newUsername) {
            // 如果需要检查密码，则解密比较
            if (checkPassword && newPassword.password) {
              const existingDecryptedPassword = await decryptPassword(existing.password, userId);
              if (existingDecryptedPassword === newPassword.password) {
                // 完全相同的账户
                return {
                  isDuplicate: true,
                  isIdentical: true,
                  existing: {
                    id: existing.id,
                    siteName: existing.site_name,
                    username: existing.username,
                    password: existingDecryptedPassword,
                    url: existing.url,
                    category: existing.category,
                    notes: existing.notes
                  }
                };
              } else {
                // 相同网站和用户名，但密码不同
                return {
                  isDuplicate: true,
                  isIdentical: false,
                  passwordChanged: true,
                  existing: {
                    id: existing.id,
                    siteName: existing.site_name,
                    username: existing.username,
                    password: existingDecryptedPassword,
                    url: existing.url,
                    category: existing.category,
                    notes: existing.notes
                  }
                };
              }
            } else {
              // 不检查密码时，只要URL和用户名匹配就算重复
              return {
                isDuplicate: true,
                existing: {
                  id: existing.id,
                  siteName: existing.site_name,
                  username: existing.username,
                  password: '••••••••',
                  url: existing.url,
                  category: existing.category,
                  notes: existing.notes
                }
              };
            }
          }
        } catch (e) {
          // URL解析失败，跳过此条记录
          continue;
        }
      }
    }

    return { isDuplicate: false };
  } catch (error) {
    console.error('检查重复时出错:', error);
    return { isDuplicate: false };
  }
}

// 账户去重检查API
async function handleCheckDuplicate(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const data = await request.json();
  const userId = session.userId;

  const duplicateCheck = await checkForDuplicates(data, userId, env, true);

  return new Response(JSON.stringify(duplicateCheck), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 更新现有密码API
async function handleUpdateExistingPassword(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { passwordId, newPassword } = await request.json();
  const userId = session.userId;

  try {
    // 获取现有密码
    const existingPassword = await env.DB.prepare(`
      SELECT * FROM passwords WHERE id = ? AND user_id = ?
    `).bind(passwordId, userId).first();

    if (!existingPassword) {
      return new Response(JSON.stringify({ error: '密码不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // 保存历史记录
    await savePasswordHistory(existingPassword, userId, env);

    // 更新密码
    const encryptedPassword = await encryptPassword(newPassword, userId);
    await env.DB.prepare(`
      UPDATE passwords 
      SET password = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `).bind(encryptedPassword, new Date().toISOString(), passwordId, userId).run();

    return new Response(JSON.stringify({ 
      success: true, 
      message: '密码已更新，旧密码已保存到历史记录' 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('更新密码失败:', error);
    return new Response(JSON.stringify({ 
      error: '更新密码失败',
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 获取实际密码
async function getActualPassword(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const url = new URL(request.url);
  const pathParts = url.pathname.split('/');
  const id = pathParts[pathParts.length - 2];
  const userId = session.userId;

  try {
    const password = await env.DB.prepare(`
      SELECT password FROM passwords WHERE id = ? AND user_id = ?
    `).bind(id, userId).first();

    if (!password) {
      return new Response(JSON.stringify({ error: '未找到' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const decryptedPassword = await decryptPassword(password.password, userId);

    return new Response(JSON.stringify({ password: decryptedPassword }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('获取密码失败:', error);
    return new Response(JSON.stringify({ 
      error: '获取密码失败',
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 分类管理
async function handleCategories(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const userId = session.userId;

  if (request.method === 'GET') {
    const categories = await env.DB.prepare(`
      SELECT name FROM categories WHERE user_id = ? ORDER BY name
    `).bind(userId).all();

    return new Response(JSON.stringify(categories.results.map(c => c.name)), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  if (request.method === 'POST') {
    const { action, category } = await request.json();

    if (action === 'add' && category) {
      await env.DB.prepare(`
        INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)
      `).bind(userId, category).run();
    } else if (action === 'remove' && category) {
      await env.DB.prepare(`
        DELETE FROM categories WHERE user_id = ? AND name = ?
      `).bind(userId, category).run();
    }

    const categories = await env.DB.prepare(`
      SELECT name FROM categories WHERE user_id = ? ORDER BY name
    `).bind(userId).all();

    return new Response(JSON.stringify({ 
      success: true, 
      categories: categories.results.map(c => c.name) 
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  return new Response('Method not allowed', { status: 405, headers: corsHeaders });
}

// 密码生成器
async function handleGeneratePassword(request, env, corsHeaders) {
  const { length = 16, includeUppercase = true, includeLowercase = true, includeNumbers = true, includeSymbols = true } = await request.json();

  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (charset === '') {
    return new Response(JSON.stringify({ error: '至少选择一种字符类型' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  let password = '';
  const randomValues = crypto.getRandomValues(new Uint8Array(length));

  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }

  return new Response(JSON.stringify({ password }), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

// 加密导出
async function handleEncryptedExport(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { exportPassword } = await request.json();
  if (!exportPassword) {
    return new Response(JSON.stringify({ error: '需要导出密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const userId = session.userId;
  const passwords = await env.DB.prepare(`
    SELECT * FROM passwords WHERE user_id = ?
  `).bind(userId).all();

  const decryptedPasswords = [];
  for (const password of passwords.results) {
    const decryptedPassword = await decryptPassword(password.password, userId);
    decryptedPasswords.push({
      id: password.id,
      siteName: password.site_name,
      username: password.username,
      password: decryptedPassword,
      url: password.url,
      category: password.category,
      notes: password.notes,
      createdAt: password.created_at,
      updatedAt: password.updated_at
    });
  }

  const exportData = {
    exportDate: new Date().toISOString(),
    version: '1.0',
    encrypted: true,
    passwords: decryptedPasswords
  };

  const encryptedData = await encryptExportData(JSON.stringify(exportData), exportPassword);

  return new Response(JSON.stringify({
    encrypted: true,
    data: encryptedData,
    exportDate: new Date().toISOString()
  }, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': 'attachment; filename="passwords-encrypted-export.json"',
      ...corsHeaders
    }
  });
}

// 加密导入
async function handleEncryptedImport(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { encryptedData, importPassword } = await request.json();

  if (!encryptedData || !importPassword) {
    return new Response(JSON.stringify({ error: '缺少加密数据或密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  try {
    const decryptedText = await decryptExportData(encryptedData, importPassword);
    const importData = JSON.parse(decryptedText);

    const userId = session.userId;
    let imported = 0;
    let errors = 0;

    for (const passwordData of importData.passwords || []) {
      try {
        const passwordId = generateId();
        const now = new Date().toISOString();
        
        const encryptedPassword = await encryptPassword(passwordData.password, userId);
        
        await env.DB.prepare(`
          INSERT INTO passwords (id, user_id, site_name, username, password, url, category, notes, created_at, updated_at, imported_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          passwordId,
          userId,
          passwordData.siteName,
          passwordData.username,
          encryptedPassword,
          passwordData.url || null,
          passwordData.category || null,
          passwordData.notes || null,
          passwordData.createdAt || now,
          now,
          now
        ).run();

        // 添加分类（如果不存在）
        if (passwordData.category) {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)
          `).bind(userId, passwordData.category).run();
        }
        
        imported++;
      } catch (error) {
        console.error('导入密码失败:', error);
        errors++;
      }
    }

    return new Response(JSON.stringify({ imported, errors }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '解密失败，请检查密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// WebDAV处理
async function handleWebDAV(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const url = new URL(request.url);
  const action = url.pathname.split('/').pop();

  switch (action) {
    case 'config':
      return handleWebDAVConfig(request, env, corsHeaders, session);
    case 'test':
      return handleWebDAVTest(request, env, corsHeaders, session);
    case 'backup':
      return handleWebDAVBackup(request, env, corsHeaders, session);
    case 'restore':
      return handleWebDAVRestore(request, env, corsHeaders, session);
    case 'delete':
      return handleWebDAVDelete(request, env, corsHeaders, session);
    case 'list':
      return handleWebDAVList(request, env, corsHeaders, session);
    default:
      return new Response('Invalid action', { status: 400, headers: corsHeaders });
  }
}

// WebDAV配置管理
async function handleWebDAVConfig(request, env, corsHeaders, session) {
  const userId = session.userId;

  if (request.method === 'GET') {
    const config = await env.DB.prepare(`
      SELECT * FROM webdav_configs WHERE user_id = ?
    `).bind(userId).first();

    if (config) {
      const decryptedConfig = {
        webdavUrl: config.webdav_url,
        username: config.username,
        password: await decryptPassword(config.password, userId)
      };
      return new Response(JSON.stringify(decryptedConfig), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    return new Response(JSON.stringify({}), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  if (request.method === 'POST') {
    const config = await request.json();
    const encryptedPassword = await encryptPassword(config.password, userId);
    const now = new Date().toISOString();

    await env.DB.prepare(`
      INSERT OR REPLACE INTO webdav_configs (user_id, webdav_url, username, password, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(userId, config.webdavUrl, config.username, encryptedPassword, now).run();

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  return new Response('Method not allowed', { status: 405, headers: corsHeaders });
}

// WebDAV测试连接
async function handleWebDAVTest(request, env, corsHeaders, session) {
  const { webdavUrl, username, password } = await request.json();

  if (!webdavUrl || !username || !password) {
    return new Response(JSON.stringify({ error: '请填写完整的WebDAV配置' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  try {
    const testResponse = await fetch(webdavUrl, {
      method: 'PROPFIND',
      headers: {
        'Authorization': `Basic ${btoa(`${username}:${password}`)}`,
        'Depth': '0',
        'Content-Type': 'application/xml'
      },
      body: `<?xml version="1.0" encoding="utf-8" ?>
      <D:propfind xmlns:D="DAV:">
        <D:prop>
          <D:displayname/>
          <D:getcontentlength/>
          <D:getcontenttype/>
          <D:getlastmodified/>
          <D:resourcetype/>
        </D:prop>
      </D:propfind>`
    });

    if (testResponse.ok || testResponse.status === 207) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: 'WebDAV连接成功',
        status: testResponse.status
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`连接失败: HTTP ${testResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({
      success: false,
      error: `WebDAV连接失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// WebDAV加密备份
async function handleWebDAVBackup(request, env, corsHeaders, session) {
  const { backupPassword } = await request.json();

  if (!backupPassword) {
    return new Response(JSON.stringify({ error: '需要备份密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  try {
    const userId = session.userId;
    const config = await env.DB.prepare(`
      SELECT * FROM webdav_configs WHERE user_id = ?
    `).bind(userId).first();

    if (!config) {
      return new Response(JSON.stringify({ error: '请先配置WebDAV' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const decryptedPassword = await decryptPassword(config.password, userId);

    // 获取用户所有密码数据
    const passwords = await env.DB.prepare(`
      SELECT * FROM passwords WHERE user_id = ?
    `).bind(userId).all();

    const decryptedPasswords = [];
    for (const password of passwords.results) {
      const decryptedPasswordText = await decryptPassword(password.password, userId);
      decryptedPasswords.push({
        id: password.id,
        siteName: password.site_name,
        username: password.username,
        password: decryptedPasswordText,
        url: password.url,
        category: password.category,
        notes: password.notes,
        createdAt: password.created_at,
        updatedAt: password.updated_at
      });
    }

    const backupData = {
      backupDate: new Date().toISOString(),
      version: '1.0',
      encrypted: true,
      user: session.username,
      passwords: decryptedPasswords
    };

    // 加密备份数据
    const encryptedData = await encryptExportData(JSON.stringify(backupData), backupPassword);
    const backupContent = JSON.stringify({
      encrypted: true,
      data: encryptedData,
      backupDate: new Date().toISOString()
    }, null, 2);

    const backupFilename = `password-backup-${new Date().toISOString().split('T')[0]}.json`;

    // 上传到WebDAV
    const uploadUrl = `${config.webdav_url.replace(/\/$/, '')}/${backupFilename}`;
    const uploadResponse = await fetch(uploadUrl, {
      method: 'PUT',
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${decryptedPassword}`)}`,
        'Content-Type': 'application/json'
      },
      body: backupContent
    });

    if (uploadResponse.ok) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: '加密备份成功',
        filename: backupFilename
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`Upload failed: ${uploadResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({
      error: `备份失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// WebDAV加密恢复
async function handleWebDAVRestore(request, env, corsHeaders, session) {
  const { filename, restorePassword } = await request.json();

  if (!filename || !restorePassword) {
    return new Response(JSON.stringify({ error: '缺少文件名或恢复密码' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  try {
    const userId = session.userId;
    const config = await env.DB.prepare(`
      SELECT * FROM webdav_configs WHERE user_id = ?
    `).bind(userId).first();

    if (!config) {
      return new Response(JSON.stringify({ error: '请先配置WebDAV' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const decryptedPassword = await decryptPassword(config.password, userId);

    // 从WebDAV下载备份文件
    const downloadUrl = `${config.webdav_url.replace(/\/$/, '')}/${filename}`;
    const downloadResponse = await fetch(downloadUrl, {
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${decryptedPassword}`)}`,
      }
    });

    if (!downloadResponse.ok) {
      throw new Error(`Download failed: ${downloadResponse.status}`);
    }

    const encryptedBackup = await downloadResponse.json();

    // 解密备份数据
    const decryptedText = await decryptExportData(encryptedBackup.data, restorePassword);
    const backupData = JSON.parse(decryptedText);

    let imported = 0;
    let errors = 0;
    let duplicates = 0;

    for (const passwordData of backupData.passwords || []) {
      try {
        // 检查是否存在重复
        const duplicateCheck = await checkForDuplicates(passwordData, userId, env, true);
        
        if (duplicateCheck.isDuplicate && duplicateCheck.isIdentical) {
          duplicates++;
          continue;
        }
        
        const passwordId = generateId();
        const now = new Date().toISOString();
        
        const encryptedPassword = await encryptPassword(passwordData.password, userId);
        
        await env.DB.prepare(`
          INSERT INTO passwords (id, user_id, site_name, username, password, url, category, notes, created_at, updated_at, imported_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          passwordId,
          userId,
          passwordData.siteName,
          passwordData.username,
          encryptedPassword,
          passwordData.url || null,
          passwordData.category || null,
          passwordData.notes || null,
          passwordData.createdAt || now,
          now,
          now
        ).run();

        // 添加分类（如果不存在）
        if (passwordData.category) {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)
          `).bind(userId, passwordData.category).run();
        }
        
        imported++;
      } catch (error) {
        console.error('恢复密码失败:', error);
        errors++;
      }
    }

    return new Response(JSON.stringify({ 
      success: true, 
      imported, 
      errors,
      duplicates,
      message: `恢复完成：成功 ${imported} 条，跳过重复 ${duplicates} 条，失败 ${errors} 条`
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: `恢复失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// WebDAV删除
async function handleWebDAVDelete(request, env, corsHeaders, session) {
  const { filename } = await request.json();

  if (!filename) {
    return new Response(JSON.stringify({ error: '缺少文件名' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  try {
    const userId = session.userId;
    const config = await env.DB.prepare(`
      SELECT * FROM webdav_configs WHERE user_id = ?
    `).bind(userId).first();

    if (!config) {
      return new Response(JSON.stringify({ error: '请先配置WebDAV' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const decryptedPassword = await decryptPassword(config.password, userId);

    const deleteUrl = `${config.webdav_url.replace(/\/$/, '')}/${filename}`;
    const deleteResponse = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${decryptedPassword}`)}`,
      }
    });

    if (deleteResponse.ok) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: '删除成功' 
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`Delete failed: ${deleteResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({
      error: `删除失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// WebDAV列表
async function handleWebDAVList(request, env, corsHeaders, session) {
  try {
    const userId = session.userId;
    const config = await env.DB.prepare(`
      SELECT * FROM webdav_configs WHERE user_id = ?
    `).bind(userId).first();

    if (!config) {
      return new Response(JSON.stringify({ error: '请先配置WebDAV' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const decryptedPassword = await decryptPassword(config.password, userId);

    const listResponse = await fetch(config.webdav_url, {
      method: 'PROPFIND',
      headers: {
        'Authorization': `Basic ${btoa(`${config.username}:${decryptedPassword}`)}`,
        'Depth': '1'
      }
    });

    if (listResponse.ok) {
      const xmlText = await listResponse.text();
      const files = [];
      const regex = /<d:href>([^<]+\.json)<\/d:href>/g;
      let match;
      
      while ((match = regex.exec(xmlText)) !== null) {
        const filename = match[1].split('/').pop();
        if (filename.includes('password-backup')) {
          files.push(filename);
        }
      }
      
      return new Response(JSON.stringify({ 
        success: true, 
        files 
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } else {
      throw new Error(`List failed: ${listResponse.status}`);
    }
  } catch (error) {
    return new Response(JSON.stringify({
      error: `获取文件列表失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 登录检测API
async function handleDetectLogin(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { url, username, password } = await request.json();

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace('www.', '');
    const userId = session.userId;

    // 检查是否已存在该域名和用户名的密码
    const duplicateCheck = await checkForDuplicates({ url, username, password }, userId, env, true);

    if (duplicateCheck.isDuplicate) {
      if (duplicateCheck.isIdentical) {
        return new Response(JSON.stringify({ 
          exists: true,
          identical: true,
          password: duplicateCheck.existing,
          message: '账户已存在且密码相同：' + duplicateCheck.existing.siteName + ' - ' + duplicateCheck.existing.username
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      } else if (duplicateCheck.passwordChanged) {
        return new Response(JSON.stringify({ 
          exists: true,
          passwordChanged: true,
          existing: duplicateCheck.existing,
          newPassword: password,
          message: '检测到相同账号的密码变更，是否更新现有账户的密码？',
          updateAction: 'update_password',
          shouldUpdate: true
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }

    // 如果不存在重复，创建新的密码条目
    const passwordId = generateId();
    const now = new Date().toISOString();
    const encryptedPassword = await encryptPassword(password, userId);

    await env.DB.prepare(`
      INSERT INTO passwords (id, user_id, site_name, username, password, url, category, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      passwordId,
      userId,
      domain,
      username,
      encryptedPassword,
      url,
      '自动保存',
      '由浏览器扩展自动保存',
      now,
      now
    ).run();

    // 添加分类
    await env.DB.prepare(`
      INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)
    `).bind(userId, '自动保存').run();

    return new Response(JSON.stringify({ 
      exists: false, 
      saved: true,
      password: {
        id: passwordId,
        siteName: domain,
        username: username,
        password: '••••••••',
        url: url,
        category: '自动保存',
        notes: '由浏览器扩展自动保存'
      },
      message: '新账户已自动保存'
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: `处理失败: ${error.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 自动填充API
async function handleAutoFill(request, env, corsHeaders) {
  const session = await verifySession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: '未授权' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { url } = await request.json();

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace('www.', '');

    const userId = session.userId;
    const passwords = await env.DB.prepare(`
      SELECT * FROM passwords WHERE user_id = ?
    `).bind(userId).all();

    const matches = [];

    for (const password of passwords.results) {
      let isMatch = false;
      let matchType = '';
      let matchScore = 0;
      
      // 检查完整URL匹配
      if (password.url) {
        try {
          const savedUrlObj = new URL(password.url);
          const savedDomain = savedUrlObj.hostname.replace('www.', '');
          
          // 精确域名匹配
          if (savedDomain === domain) {
            isMatch = true;
            matchType = 'exact';
            matchScore = 100;
          }
          // 子域名匹配
          else if (domain.includes(savedDomain) || savedDomain.includes(domain)) {
            isMatch = true;
            matchType = 'subdomain';
            matchScore = 80;
          }
        } catch (e) {
          // URL解析失败，继续其他匹配方式
        }
      }
      
      // 检查网站名称匹配
      if (!isMatch && password.site_name) {
        const siteName = password.site_name.toLowerCase();
        const currentDomain = domain.toLowerCase();
        
        if (siteName.includes(currentDomain) || currentDomain.includes(siteName)) {
          isMatch = true;
          matchType = 'sitename';
          matchScore = 60;
        }
      }
      
      if (isMatch) {
        // 解密密码并返回
        const decryptedPassword = await decryptPassword(password.password, userId);
        matches.push({
          id: password.id,
          siteName: password.site_name,
          username: password.username,
          password: decryptedPassword,
          url: password.url,
          category: password.category,
          notes: password.notes,
          matchType: matchType,
          matchScore: matchScore,
          createdAt: password.created_at,
          updatedAt: password.updated_at
        });
      }
    }

    // 按匹配度和更新时间排序
    matches.sort((a, b) => {
      if (a.matchScore !== b.matchScore) {
        return b.matchScore - a.matchScore;
      }
      return new Date(b.updatedAt) - new Date(a.updatedAt);
    });

    return new Response(JSON.stringify({ 
      matches: matches,
      total: matches.length,
      exactMatches: matches.filter(m => m.matchType === 'exact').length,
      subdomainMatches: matches.filter(m => m.matchType === 'subdomain').length,
      sitenameMatches: matches.filter(m => m.matchType === 'sitename').length
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });

  } catch (error) {
    console.error('Auto-fill error:', error);
    return new Response(JSON.stringify({
      error: `查询失败: ${error.message}`,
      matches: [],
      total: 0
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// 工具函数
async function verifySession(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;

  const session = await env.DB.prepare(`
    SELECT user_data FROM sessions WHERE token = ? AND expires_at > ?
  `).bind(token, new Date().toISOString()).first();

  if (!session) return null;

  const userData = JSON.parse(session.user_data);

  // 检查用户授权
  if (env.OAUTH_ID && userData.userId !== env.OAUTH_ID) {
    return null;
  }

  return userData;
}

async function encryptPassword(password, userId) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(userId.slice(0, 32).padEnd(32, '0')),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(password)
  );

  return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptPassword(encryptedPassword, userId) {
  try {
    const data = atob(encryptedPassword);
    const iv = new Uint8Array(data.slice(0, 12).split('').map(c => c.charCodeAt(0)));
    const encrypted = new Uint8Array(data.slice(12).split('').map(c => c.charCodeAt(0)));

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(userId.slice(0, 32).padEnd(32, '0')),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    return encryptedPassword;
  }
}

async function encryptExportData(data, password) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password.slice(0, 32).padEnd(32, '0')),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(data)
  );

  return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptExportData(encryptedData, password) {
  const data = atob(encryptedData);
  const iv = new Uint8Array(data.slice(0, 12).split('').map(c => c.charCodeAt(0)));
  const encrypted = new Uint8Array(data.slice(12).split('').map(c => c.charCodeAt(0)));

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password.slice(0, 32).padEnd(32, '0')),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );

  return new TextDecoder().decode(decrypted);
}

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = crypto.getRandomValues(new Uint8Array(length));

  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }

  return result;
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// 生成错误页面
function generateErrorPage(title, message, details = '') {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>${title}</title>
    <style>
      body { 
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        height: 100vh; 
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); 
        margin: 0; 
      }
      .message { 
        background: white; 
        padding: 30px; 
        border-radius: 15px; 
        text-align: center; 
        box-shadow: 0 10px 25px rgba(0,0,0,0.1); 
        max-width: 500px; 
      }
      h3 { color: #ef4444; margin-bottom: 15px; }
      .error-details { 
        background: #fef2f2; 
        border: 1px solid #fecaca; 
        border-radius: 8px; 
        padding: 15px; 
        margin: 15px 0; 
        text-align: left; 
        font-family: monospace; 
        font-size: 12px; 
        color: #991b1b; 
      }
    </style>
  </head>
  <body>
    <div class="message">
      <h3>❌ ${title}</h3>
      <p>${message}</p>
      ${details ? `<div class="error-details">${details}</div>` : ''}
      <button onclick="window.location.href='/'" style="padding: 10px 20px; background: #6366f1; color: white; border: none; border-radius: 5px; cursor: pointer;">返回首页</button>
    </div>
  </body>
  </html>`;
}

// 生成成功页面
function generateSuccessPage(userSession, sessionToken) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <title>登录成功</title>
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
          display: flex; 
          justify-content: center; 
          align-items: center; 
          height: 100vh; 
          background: linear-gradient(135deg, #10b981 0%, #059669 100%);
          margin: 0;
        }
        .message { 
          background: white; 
          padding: 30px; 
          border-radius: 15px; 
          text-align: center;
          box-shadow: 0 10px 25px rgba(0,0,0,0.1);
          max-width: 400px;
        }
        h3 { color: #10b981; margin-bottom: 15px; }
        .user-info {
          display: flex;
          align-items: center;
          gap: 15px;
          margin: 20px 0;
          padding: 15px;
          background: #f8fafc;
          border-radius: 10px;
        }
        .avatar {
          width: 50px;
          height: 50px;
          border-radius: 50%;
          background: linear-gradient(135deg, #6366f1, #8b5cf6);
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: bold;
          font-size: 18px;
        }
        .loading {
          display: inline-block;
          width: 20px;
          height: 20px;
          border: 3px solid #f3f3f3;
          border-top: 3px solid #10b981;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="message">
        <h3>✅ 登录成功</h3>
        <div class="user-info">
          <div class="avatar">${userSession.avatar ? `<img src="${userSession.avatar}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">` : userSession.nickname.charAt(0).toUpperCase()}</div>
          <div>
            <div style="font-weight: bold;">${userSession.nickname}</div>
            <div style="color: #6b7280; font-size: 14px;">${userSession.email}</div>
          </div>
        </div>
        <p><div class="loading"></div> 正在跳转到密码管理器...</p>
      </div>
      <script>
        localStorage.setItem('authToken', '${sessionToken}');
        setTimeout(() => {
          window.location.href = '/';
        }, 1000);
      </script>
    </body>
  </html>`;
}

// HTML5界面（保持原样）
function getHTML5() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 密码管理器 Pro</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔐</text></svg>">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">

    <style>
        :root {
            --primary-color: #6366f1;
            --primary-dark: #4f46e5;
            --secondary-color: #8b5cf6;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --info-color: #3b82f6;
            --dark-color: #1f2937;
            --light-color: #f8fafc;
            --border-color: #e5e7eb;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --text-muted: #9ca3af;
            --background-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-background: rgba(255, 255, 255, 0.95);
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            --border-radius-sm: 8px;
            --border-radius-md: 12px;
            --border-radius-lg: 16px;
            --border-radius-xl: 20px;
            --border-radius-2xl: 24px;
            --transition-fast: 0.15s ease;
            --transition-normal: 0.3s ease;
            --transition-slow: 0.5s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--background-gradient);
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
        }

        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            overflow: hidden;
        }

        .particle {
            position: absolute;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            animation: float 20s infinite linear;
        }

        @keyframes float {
            0% {
                transform: translateY(100vh) rotate(0deg);
                opacity: 0;
            }
            10% {
                opacity: 1;
            }
            90% {
                opacity: 1;
            }
            100% {
                transform: translateY(-100px) rotate(360deg);
                opacity: 0;
            }
        }

        /* 登录界面 */
        .auth-section {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1.25rem;
        }

        .auth-card {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            padding: 3rem 2.5rem;
            border-radius: var(--border-radius-2xl);
            box-shadow: var(--shadow-xl);
            text-align: center;
            max-width: 28rem;
            width: 100%;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .auth-card .logo {
            font-size: 4rem;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .auth-card h1 {
            color: var(--text-primary);
            margin-bottom: 0.75rem;
            font-size: 2rem;
            font-weight: 700;
        }

        .auth-card p {
            color: var(--text-secondary);
            margin-bottom: 2.5rem;
            font-size: 1rem;
        }

        /* 主应用容器 */
        .app-container {
            max-width: 87.5rem;
            margin: 0 auto;
            padding: 1.25rem;
        }

        /* 头部区域 */
        .app-header {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            padding: 1.5rem;
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            margin-bottom: 1.875rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-avatar {
            width: 3.5rem;
            height: 3.5rem;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.25rem;
            overflow: hidden;
            box-shadow: var(--shadow-md);
        }

        .user-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .user-info h2 {
            color: var(--text-primary);
            margin-bottom: 0.25rem;
            font-size: 1.125rem;
            font-weight: 600;
        }

        .user-info p {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        .header-actions {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }

        /* 按钮组件 */
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 50px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all var(--transition-normal);
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
            box-shadow: var(--shadow-sm);
            white-space: nowrap;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white;
        }

        .btn-secondary {
            background: #f1f5f9;
            color: var(--text-primary);
        }

        .btn-danger {
            background: linear-gradient(135deg, var(--danger-color), #dc2626);
            color: white;
        }

        .btn-success {
            background: linear-gradient(135deg, var(--success-color), #059669);
            color: white;
        }

        .btn-warning {
            background: linear-gradient(135deg, var(--warning-color), #d97706);
            color: white;
        }

        .btn-info {
            background: linear-gradient(135deg, var(--info-color), #2563eb);
            color: white;
        }

        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
        }

        .btn-lg {
            padding: 1rem 2rem;
            font-size: 1.125rem;
        }

        /* 导航标签 */
        .nav-tabs {
            display: flex;
            background: var(--card-background);
            border-radius: var(--border-radius-xl);
            padding: 0.5rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .nav-tab {
            flex: 1;
            padding: 1rem;
            text-align: center;
            border-radius: var(--border-radius-lg);
            cursor: pointer;
            transition: all var(--transition-normal);
            font-weight: 600;
            color: var(--text-secondary);
        }

        .nav-tab.active {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            box-shadow: var(--shadow-md);
        }

        .nav-tab:hover:not(.active) {
            background: rgba(99, 102, 241, 0.1);
            color: var(--primary-color);
        }

        /* 内容区域 */
        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* 工具栏 */
        .toolbar {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            padding: 1.5rem;
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            margin-bottom: 1.875rem;
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .search-container {
            flex: 1;
            min-width: 18.75rem;
            position: relative;
        }

        .search-input {
            width: 100%;
            padding: 0.875rem 1rem 0.875rem 3rem;
            border: 2px solid var(--border-color);
            border-radius: 50px;
            font-size: 1rem;
            transition: all var(--transition-normal);
            background: rgba(255, 255, 255, 0.8);
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        .search-icon {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-secondary);
            font-size: 1.125rem;
        }

        .filter-select {
            padding: 0.875rem 1.25rem;
            border: 2px solid var(--border-color);
            border-radius: 50px;
            font-size: 1rem;
            background: rgba(255, 255, 255, 0.8);
            cursor: pointer;
            transition: all var(--transition-normal);
        }

        .filter-select:focus {
            outline: none;
            border-color: var(--primary-color);
        }

        /* 密码网格 */
        .passwords-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(23.75rem, 1fr));
            gap: 1.5rem;
        }

        /* 密码卡片 */
        .password-card {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius-xl);
            padding: 1.75rem;
            box-shadow: var(--shadow-lg);
            transition: all var(--transition-normal);
            position: relative;
            border: 1px solid rgba(255, 255, 255, 0.2);
            overflow: hidden;
        }

        .password-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        }

        .password-card:hover {
            transform: translateY(-8px);
            box-shadow: var(--shadow-xl);
        }

        .password-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .site-icon {
            width: 3.5rem;
            height: 3.5rem;
            border-radius: var(--border-radius-lg);
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5rem;
            box-shadow: var(--shadow-md);
        }

        .password-meta h3 {
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            font-size: 1.25rem;
            font-weight: 700;
        }

        .category-badge {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: var(--border-radius-xl);
            font-size: 0.75rem;
            font-weight: 600;
            display: inline-block;
        }

        .password-field {
            margin: 1rem 0;
        }

        .password-field label {
            display: block;
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 0.375rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .password-field .value {
            color: var(--text-primary);
            font-size: 1rem;
            word-break: break-all;
            font-family: 'SF Mono', 'Monaco', 'Cascadia Code', monospace;
        }

        .password-field .value a {
            color: var(--primary-color);
            text-decoration: none;
        }

        .password-field .value a:hover {
            text-decoration: underline;
        }

        .password-actions {
            display: flex;
            gap: 0.5rem;
            margin-top: 1.5rem;
            flex-wrap: wrap;
        }

        .password-actions .btn {
            flex: 1;
            min-width: 3rem;
            justify-content: center;
        }

        /* 密码历史记录模态框 */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            z-index: 1000;
            display: none;
            justify-content: center;
            align-items: center;
            padding: 1rem;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: var(--card-background);
            border-radius: var(--border-radius-xl);
            padding: 2rem;
            max-width: 50rem;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: var(--shadow-xl);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--border-color);
        }

        .modal-header h3 {
            color: var(--text-primary);
            font-size: 1.5rem;
            font-weight: 700;
        }

        .modal-header-actions {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0.5rem;
            border-radius: var(--border-radius-sm);
            transition: all var(--transition-normal);
        }

        .close-btn:hover {
            background: var(--border-color);
            color: var(--text-primary);
        }

        .history-item {
            background: #f8fafc;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius-lg);
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: all var(--transition-normal);
        }

        .history-item:hover {
            box-shadow: var(--shadow-md);
        }

        .history-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .history-date {
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 600;
        }

        .history-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .history-password {
            font-family: 'SF Mono', 'Monaco', 'Cascadia Code', monospace;
            background: white;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius-sm);
            padding: 0.75rem;
            margin: 0.5rem 0;
            word-break: break-all;
        }

        .empty-history {
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }

        .empty-history .icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        /* 分页组件 */
        .pagination-container {
            margin-top: 2rem;
            padding: 1.5rem;
            background: var(--card-background);
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .pagination-info {
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .pagination-controls {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .pagination-ellipsis {
            color: var(--text-secondary);
            padding: 0 0.5rem;
            font-weight: 600;
        }

        /* 表单组件 */
        .form-section {
            background: var(--card-background);
            backdrop-filter: blur(20px);
            border-radius: var(--border-radius-xl);
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: 0.875rem;
        }

        .form-control {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 2px solid var(--border-color);
            border-radius: var(--border-radius-md);
            font-size: 1rem;
            transition: all var(--transition-normal);
            background: rgba(255, 255, 255, 0.8);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }

        .input-group {
            position: relative;
        }

        .input-group-append {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
        }

        .toggle-btn {
            background: none;
            border: none;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0.5rem;
            border-radius: var(--border-radius-sm);
            transition: all var(--transition-normal);
        }

        .toggle-btn:hover {
            background: var(--border-color);
            color: var(--text-primary);
        }

        /* 密码生成器 */
        .password-generator {
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            padding: 1.5rem;
            border-radius: var(--border-radius-lg);
            margin-bottom: 1.5rem;
            border: 2px solid var(--border-color);
        }

        .password-generator h4 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1rem;
            font-weight: 700;
        }

        .generator-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(12.5rem, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .checkbox-group input[type="checkbox"] {
            width: auto;
            accent-color: var(--primary-color);
        }

        .range-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .range-input {
            width: 100%;
            accent-color: var(--primary-color);
        }

        .range-value {
            font-weight: 600;
            color: var(--primary-color);
        }

        /* WebDAV配置 */
        .webdav-section {
            background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
            padding: 1.5rem;
            border-radius: var(--border-radius-lg);
            margin-bottom: 1.5rem;
            border: 2px solid #bae6fd;
        }

        .webdav-section h4 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.125rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .backup-files {
            max-height: 12.5rem;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius-sm);
            padding: 0.75rem;
            background: white;
        }

        .backup-file {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .backup-file:last-child {
            border-bottom: none;
        }

        .backup-file-actions {
            display: flex;
            gap: 0.5rem;
        }

        /* 重复提示 */
        .duplicate-warning {
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            border: 2px solid #f59e0b;
            border-radius: var(--border-radius-lg);
            padding: 1rem;
            margin-bottom: 1.5rem;
            color: #92400e;
        }

        .duplicate-warning h4 {
            margin: 0 0 0.5rem 0;
            color: #92400e;
            font-size: 1rem;
            font-weight: 700;
        }

        .duplicate-warning p {
            margin: 0;
            font-size: 0.875rem;
        }

        /* 空状态 */
        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 5rem 1.25rem;
            color: var(--text-secondary);
        }

        .empty-state .icon {
            font-size: 4rem;
            margin-bottom: 1.5rem;
            opacity: 0.5;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .empty-state h3 {
            font-size: 1.5rem;
            margin-bottom: 0.75rem;
            color: var(--text-primary);
        }

        .empty-state p {
            font-size: 1rem;
        }

        /* 通知组件 */
        .notification {
            position: fixed;
            top: 1.5rem;
            right: 1.5rem;
            background: var(--success-color);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius-md);
            box-shadow: var(--shadow-lg);
            z-index: 1001;
            transform: translateX(25rem);
            transition: transform var(--transition-normal);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 600;
            max-width: 20rem;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification.error {
            background: var(--danger-color);
        }

        .notification.warning {
            background: var(--warning-color);
        }

        .notification.info {
            background: var(--info-color);
        }

        /* 加载动画 */
        .loading {
            display: inline-block;
            width: 1.25rem;
            height: 1.25rem;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* 响应式设计 */
        @media (max-width: 768px) {
            .app-container { 
                padding: 0.75rem; 
            }
            
            .app-header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .header-actions {
                justify-content: center;
            }
            
            .toolbar {
                flex-direction: column;
                align-items: stretch;
            }
            
            .search-container {
                min-width: auto;
            }
            
            .passwords-grid {
                grid-template-columns: 1fr;
            }
            
            .password-actions {
                flex-direction: column;
            }

            .generator-options {
                grid-template-columns: 1fr;
            }

            .notification {
                right: 0.75rem;
                left: 0.75rem;
                max-width: none;
                transform: translateY(-5rem);
            }

            .notification.show {
                transform: translateY(0);
            }

            .pagination {
                flex-direction: column;
                text-align: center;
            }
            
            .pagination-controls {
                justify-content: center;
            }

            .modal-content {
                margin: 1rem;
                max-height: 90vh;
            }

            .history-header {
                flex-direction: column;
                align-items: stretch;
                gap: 1rem;
            }

            .history-actions {
                justify-content: center;
            }

            .modal-header-actions {
                flex-direction: column;
                gap: 0.5rem;
            }
        }

        /* 工具类 */
        .hidden { 
            display: none !important; 
        }

        .text-center { 
            text-align: center; 
        }

        .flex { display: flex; }
        .flex-col { flex-direction: column; }
        .items-center { align-items: center; }
        .justify-center { justify-content: center; }
        .justify-between { justify-content: space-between; }
        .gap-1 { gap: 0.25rem; }
        .gap-2 { gap: 0.5rem; }
        .gap-3 { gap: 0.75rem; }
        .gap-4 { gap: 1rem; }

        .w-full { width: 100%; }
        .h-full { height: 100%; }

        .mb-0 { margin-bottom: 0; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 0.75rem; }
        .mb-4 { margin-bottom: 1rem; }

        .mt-0 { margin-top: 0; }
        .mt-1 { margin-top: 0.25rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mt-3 { margin-top: 0.75rem; }
        .mt-4 { margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="particles" id="particles"></div>

    <!-- 登录界面 -->
    <section id="authSection" class="auth-section">
        <article class="auth-card">
            <div class="logo">🔐</div>
            <header>
                <h1>密码管理器 Pro</h1>
                <p>安全、便捷、智能的密码管理解决方案</p>
            </header>
            <button id="oauthLoginBtn" class="btn btn-primary btn-lg" type="button">
                <i class="fas fa-sign-in-alt"></i>
                开始使用 OAuth 登录
            </button>
        </article>
    </section>

    <!-- 主应用界面 -->
    <div id="mainApp" class="app-container hidden">
        <!-- 应用头部 -->
        <header class="app-header">
            <div class="user-profile">
                <div class="user-avatar" id="userAvatar">
                    <i class="fas fa-user"></i>
                </div>
                <div class="user-info">
                    <h2 id="userName">用户名</h2>
                    <p id="userEmail">user@example.com</p>
                </div>
            </div>
            <nav class="header-actions">
                <button class="btn btn-danger" onclick="logout()" type="button">
                    <i class="fas fa-sign-out-alt"></i> 
                    <span>登出</span>
                </button>
            </nav>
        </header>

        <!-- 导航标签 -->
        <nav class="nav-tabs">
            <div class="nav-tab active" onclick="switchTab('passwords')">
                <i class="fas fa-key"></i> 密码管理
            </div>
            <div class="nav-tab" onclick="switchTab('add-password')">
                <i class="fas fa-plus"></i> 添加密码
            </div>
            <div class="nav-tab" onclick="switchTab('backup')">
                <i class="fas fa-cloud"></i> 云备份
            </div>
            <div class="nav-tab" onclick="switchTab('import-export')">
                <i class="fas fa-exchange-alt"></i> 导入导出
            </div>
        </nav>

        <!-- 密码管理标签页 -->
        <div id="passwords-tab" class="tab-content active">
            <!-- 工具栏 -->
            <section class="toolbar">
                <div class="search-container">
                    <i class="fas fa-search search-icon"></i>
                    <input 
                        type="search" 
                        id="searchInput" 
                        class="search-input"
                        placeholder="搜索网站、用户名或备注..."
                        autocomplete="off"
                    >
                </div>
                <div>
                    <select id="categoryFilter" class="filter-select">
                        <option value="">🏷️ 所有分类</option>
                    </select>
                </div>
            </section>

            <!-- 密码列表 -->
            <main>
                <section class="passwords-grid" id="passwordsGrid">
                    <!-- 密码卡片将在这里动态生成 -->
                </section>
                <!-- 分页容器将在这里动态生成 -->
            </main>
        </div>

        <!-- 添加密码标签页 -->
        <div id="add-password-tab" class="tab-content">
            <div class="form-section">
                <h2 style="margin-bottom: 1.5rem; color: var(--text-primary);">✨ 添加新密码</h2>
                
                <!-- 重复检查提示 -->
                <div id="duplicateWarning" class="duplicate-warning hidden">
                    <h4>⚠️ 检测到重复账户</h4>
                    <p id="duplicateMessage"></p>
                </div>
                
                <form id="passwordForm">
                    <div class="form-group">
                        <label for="siteName">🌐 网站名称 *</label>
                        <input type="text" id="siteName" class="form-control" required placeholder="例如：GitHub、Gmail" autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label for="username">👤 用户名/邮箱 *</label>
                        <input type="text" id="username" class="form-control" required placeholder="your@email.com" autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="password">🔑 密码 *</label>
                        <div class="input-group">
                            <input type="password" id="password" class="form-control" required placeholder="输入密码" autocomplete="new-password">
                            <div class="input-group-append">
                                <button type="button" class="toggle-btn" onclick="togglePasswordVisibility('password')">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 密码生成器 -->
                    <fieldset class="password-generator">
                        <legend>🎲 智能密码生成器</legend>
                        <div class="generator-options">
                            <div class="form-group">
                                <label for="passwordLength">长度: <span id="lengthValue" class="range-value">16</span></label>
                                <input type="range" id="passwordLength" class="range-input" min="8" max="32" value="16">
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeUppercase" checked>
                                <label for="includeUppercase">ABC 大写字母</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeLowercase" checked>
                                <label for="includeLowercase">abc 小写字母</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeNumbers" checked>
                                <label for="includeNumbers">123 数字</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="includeSymbols">
                                <label for="includeSymbols">!@# 特殊符号</label>
                            </div>
                        </div>
                        <button type="button" class="btn btn-secondary" onclick="generatePassword()">
                            <i class="fas fa-magic"></i> 生成强密码
                        </button>
                    </fieldset>

                    <div class="form-group">
                        <label for="category">📁 选择分类</label>
                        <select id="category" class="form-control">
                            <option value="">选择分类</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="url">🔗 网站链接</label>
                        <input type="url" id="url" class="form-control" placeholder="https://example.com" autocomplete="url">
                    </div>
                    <div class="form-group">
                        <label for="notes">📝 备注信息</label>
                        <textarea id="notes" class="form-control" rows="3" placeholder="添加备注信息..."></textarea>
                    </div>
                    <div class="flex gap-4 mt-4">
                        <button type="submit" class="btn btn-primary w-full">
                            <i class="fas fa-save"></i> 保存密码
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="clearForm()">
                            <i class="fas fa-eraser"></i> 清空表单
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- 云备份标签页 -->
        <div id="backup-tab" class="tab-content">
            <!-- WebDAV配置 -->
            <div class="form-section">
                <h2 style="margin-bottom: 1.5rem; color: var(--text-primary);">☁️ WebDAV 云备份配置</h2>
                <div class="webdav-section">
                    <h4><i class="fas fa-cog"></i> 连接配置</h4>
                    <div class="form-group">
                        <label for="webdavUrl">🌐 WebDAV 地址</label>
                        <input type="url" id="webdavUrl" class="form-control" placeholder="https://webdav.teracloud.jp/dav/" autocomplete="url">
                        <small style="color: var(--text-secondary); margin-top: 0.5rem; display: block;">
                            支持 TeraCloud、坚果云、NextCloud 等 WebDAV 服务
                        </small>
                    </div>
                    <div class="form-group">
                        <label for="webdavUsername">👤 用户名</label>
                        <input type="text" id="webdavUsername" class="form-control" placeholder="WebDAV用户名" autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="webdavPassword">🔑 密码</label>
                        <input type="password" id="webdavPassword" class="form-control" placeholder="WebDAV密码" autocomplete="current-password">
                    </div>
                    <div class="flex gap-3 mt-4">
                        <button class="btn btn-info" onclick="testWebDAVConnection()" type="button">
                            <i class="fas fa-wifi"></i> 测试连接
                        </button>
                        <button class="btn btn-primary" onclick="saveWebDAVConfig()" type="button">
                            <i class="fas fa-save"></i> 保存配置
                        </button>
                        <button class="btn btn-secondary" onclick="loadWebDAVFiles()" type="button">
                            <i class="fas fa-list"></i> 列出文件
                        </button>
                    </div>
                </div>
                
                <!-- 备份操作 -->
                <div class="webdav-section">
                    <h4><i class="fas fa-cloud-upload-alt"></i> 创建加密备份</h4>
                    <div class="form-group">
                        <label for="backupPassword">🔐 备份密码</label>
                        <input type="password" id="backupPassword" class="form-control" placeholder="设置备份密码" autocomplete="new-password">
                    </div>
                    <button class="btn btn-success w-full" onclick="createWebDAVBackup()" type="button">
                        <i class="fas fa-cloud-upload-alt"></i> 创建加密备份
                    </button>
                </div>

                <!-- 备份文件列表 -->
                <div class="webdav-section">
                    <h4><i class="fas fa-history"></i> 备份文件</h4>
                    <div class="backup-files" id="backupFilesList">
                        <p class="text-center" style="color: #6b7280;">点击"列出文件"查看备份</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- 导入导出标签页 -->
        <div id="import-export-tab" class="tab-content">
            <div class="form-section">
                <h2 style="margin-bottom: 1.5rem; color: var(--text-primary);">📤 加密导出</h2>
                <div class="form-group">
                    <label for="exportPassword">🔐 导出密码</label>
                    <input type="password" id="exportPassword" class="form-control" placeholder="设置导出密码" autocomplete="new-password">
                </div>
                <button class="btn btn-primary w-full" onclick="exportData()" type="button">
                    <i class="fas fa-download"></i> 加密导出数据
                </button>
            </div>

            <div class="form-section" style="margin-top: 1.5rem;">
                <h2 style="margin-bottom: 1.5rem; color: var(--text-primary);">📥 加密导入</h2>
                <div class="form-group">
                    <label for="importFile">📁 选择加密文件</label>
                    <input type="file" id="importFile" class="form-control" accept=".json" onchange="handleFileSelect()">
                </div>
                <div id="encryptedImportForm" class="hidden">
                    <div class="form-group">
                        <label for="importPassword">🔐 导入密码</label>
                        <input type="password" id="importPassword" class="form-control" placeholder="输入导入密码" autocomplete="off">
                    </div>
                </div>
                <div class="flex gap-4 mt-4">
                    <button class="btn btn-primary w-full" onclick="importData()" type="button">
                        <i class="fas fa-upload"></i> 开始导入
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- 密码历史记录模态框 -->
    <div id="historyModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-history"></i> 密码历史记录</h3>
                <div class="modal-header-actions">
                    <button class="btn btn-danger btn-sm" onclick="deleteAllHistory()" type="button" title="删除所有历史记录">
                        <i class="fas fa-trash-alt"></i> 清空历史
                    </button>
                    <button class="close-btn" onclick="closeHistoryModal()" type="button">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
            <div id="historyContent">
                <!-- 历史记录内容将在这里动态生成 -->
            </div>
        </div>
    </div>

    <script>
        // 全局变量
        let authToken = localStorage.getItem('authToken');
        let currentUser = null;
        let passwords = [];
        let categories = [];
        let editingPasswordId = null;
        let selectedFile = null;
        let currentTab = 'passwords';
        let currentPasswordId = null; // 当前查看历史记录的密码ID
        
        // 分页相关变量
        let currentPage = 1;
        let totalPages = 1;
        let pageLimit = 50;
        let searchQuery = '';
        let categoryFilter = '';

        // 创建粒子背景
        function createParticles() {
            const particles = document.getElementById('particles');
            for (let i = 0; i < 50; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.width = particle.style.height = Math.random() * 10 + 5 + 'px';
                particle.style.animationDelay = Math.random() * 20 + 's';
                particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
                particles.appendChild(particle);
            }
        }

        // 初始化应用
        document.addEventListener('DOMContentLoaded', function() {
            createParticles();
            
            if (authToken) {
                verifyAuth();
            } else {
                showAuthSection();
            }
            
            setupEventListeners();
        });

        // 设置事件监听器 - 支持分页
        function setupEventListeners() {
            const searchInput = document.getElementById('searchInput');
            const categoryFilter = document.getElementById('categoryFilter');
            
            // 防抖搜索
            let searchTimeout;
            searchInput.addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    filterPasswords();
                }, 500);
            });
            
            categoryFilter.addEventListener('change', filterPasswords);
            
            document.getElementById('passwordLength').addEventListener('input', function() {
                document.getElementById('lengthValue').textContent = this.value;
            });
            document.getElementById('passwordForm').addEventListener('submit', handlePasswordSubmit);
            document.getElementById('oauthLoginBtn').addEventListener('click', handleOAuthLogin);
            
            // 添加重复检查监听器
            document.getElementById('url').addEventListener('blur', checkForDuplicates);
            document.getElementById('username').addEventListener('blur', checkForDuplicates);
            
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    hideDuplicateWarning();
                    closeHistoryModal();
                }
                if (e.ctrlKey && e.key === 'k') {
                    e.preventDefault();
                    document.getElementById('searchInput').focus();
                }
            });
        }

        // 检查重复账户
        async function checkForDuplicates() {
            const url = document.getElementById('url').value;
            const username = document.getElementById('username').value;
            
            if (!url || !username || editingPasswordId) {
                hideDuplicateWarning();
                return;
            }
            
            try {
                const response = await fetch('/api/check-duplicate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ url, username })
                });
                
                const result = await response.json();
                
                if (result.isDuplicate) {
                    showDuplicateWarning(result.existing);
                } else {
                    hideDuplicateWarning();
                }
            } catch (error) {
                console.error('检查重复失败:', error);
                hideDuplicateWarning();
            }
        }

        // 显示重复警告
        function showDuplicateWarning(existing) {
            const warning = document.getElementById('duplicateWarning');
            const message = document.getElementById('duplicateMessage');
            
            message.textContent = \`该网站已存在相同用户名的账户：\${existing.siteName} - \${existing.username}\`;
            warning.classList.remove('hidden');
        }

        // 隐藏重复警告
        function hideDuplicateWarning() {
            const warning = document.getElementById('duplicateWarning');
            warning.classList.add('hidden');
        }

        // 标签页切换
        function switchTab(tabName) {
            // 移除所有活动状态
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // 激活当前标签
            event.target.classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
            currentTab = tabName;
            
            // 隐藏重复警告
            hideDuplicateWarning();
            
            // 如果切换到密码管理页面，刷新数据
            if (tabName === 'passwords') {
                loadPasswords(1);
            } else if (tabName === 'backup') {
                loadWebDAVConfig();
            }
        }

        // OAuth登录处理 - 修正版本
        async function handleOAuthLogin() {
            const button = document.getElementById('oauthLoginBtn');
            const originalText = button.innerHTML;
            
            try {
                button.innerHTML = '<div class="loading"></div> 正在获取授权链接...';
                button.disabled = true;
                
                const response = await fetch('/api/oauth/login', {
                    method: 'GET'
                });
                
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error('HTTP ' + response.status + ': ' + errorText);
                }
                
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error + (data.details ? ': ' + data.details : ''));
                }
                
                if (!data.authUrl) {
                    throw new Error('响应中缺少授权URL');
                }
                
                // 更新按钮状态
                button.innerHTML = '<div class="loading"></div> 正在跳转到授权页面...';
                
                // 跳转到授权页面
                window.location.href = data.authUrl;
                
            } catch (error) {
                console.error('OAuth登录失败:', error);
                showNotification('登录失败: ' + error.message, 'error');
                
                button.innerHTML = originalText;
                button.disabled = false;
            }
        }

        // 验证登录状态
        async function verifyAuth() {
            try {
                const response = await fetch('/api/auth/verify', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const data = await response.json();
                
                if (data.authenticated) {
                    currentUser = data.user;
                    showMainApp();
                    loadData();
                } else {
                    localStorage.removeItem('authToken');
                    authToken = null;
                    showAuthSection();
                }
            } catch (error) {
                console.error('Auth verification failed:', error);
                showAuthSection();
            }
        }

        // 显示界面
        function showAuthSection() {
            document.getElementById('authSection').classList.remove('hidden');
            document.getElementById('mainApp').classList.add('hidden');
        }

        function showMainApp() {
            document.getElementById('authSection').classList.add('hidden');
            document.getElementById('mainApp').classList.remove('hidden');
            
            if (currentUser) {
                const displayName = currentUser.nickname || currentUser.username || '用户';
                document.getElementById('userName').textContent = displayName;
                document.getElementById('userEmail').textContent = currentUser.email || '';
                
                const avatar = document.getElementById('userAvatar');
                if (currentUser.avatar) {
                    avatar.innerHTML = \`<img src="\${currentUser.avatar}" alt="用户头像">\`;
                } else {
                    avatar.innerHTML = displayName.charAt(0).toUpperCase();
                }
            }
        }

        // 加载数据
        async function loadData() {
            await Promise.all([
                loadPasswords(1),
                loadCategories()
            ]);
        }

        // 加载密码列表 - 支持分页，增强错误处理
        async function loadPasswords(page = 1, search = '', category = '') {
            try {
                currentPage = page;
                searchQuery = search;
                categoryFilter = category;
                
                const params = new URLSearchParams({
                    page: page.toString(),
                    limit: pageLimit.toString()
                });
                
                if (search) params.append('search', search);
                if (category) params.append('category', category);
                
                const response = await fetch(\`/api/passwords?\${params}\`, {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (!response.ok) {
                    throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
                }
                
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await response.text();
                    throw new Error('服务器返回非JSON响应: ' + text.substring(0, 100));
                }
                
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error + (data.message ? ': ' + data.message : ''));
                }
                
                passwords = data.passwords || [];
                
                if (data.pagination) {
                    currentPage = data.pagination.page;
                    totalPages = data.pagination.totalPages;
                    updatePaginationInfo(data.pagination);
                }
                
                renderPasswords();
                renderPagination(data.pagination);
            } catch (error) {
                console.error('Failed to load passwords:', error);
                showNotification('加载密码失败: ' + error.message, 'error');
                
                // 在错误情况下显示空状态
                const grid = document.getElementById('passwordsGrid');
                grid.innerHTML = \`
                    <div class="empty-state">
                        <div class="icon">⚠️</div>
                        <h3>加载失败</h3>
                        <p>无法加载密码数据，请稍后重试</p>
                    </div>
                \`;
            }
        }

        // 加载分类
        async function loadCategories() {
            try {
                const response = await fetch('/api/categories', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                categories = await response.json();
                updateCategorySelects();
            } catch (error) {
                console.error('Failed to load categories:', error);
            }
        }

        // 更新分类选择器
        function updateCategorySelects() {
            const categoryFilterSelect = document.getElementById('categoryFilter');
            const categorySelect = document.getElementById('category');
            
            categoryFilterSelect.innerHTML = '<option value="">🏷️ 所有分类</option>';
            categorySelect.innerHTML = '<option value="">选择分类</option>';
            
            categories.forEach(category => {
                categoryFilterSelect.innerHTML += \`<option value="\${category}">🏷️ \${category}</option>\`;
                categorySelect.innerHTML += \`<option value="\${category}">\${category}</option>\`;
            });
        }

        // 渲染密码列表 - 添加历史记录按钮
        function renderPasswords() {
            const grid = document.getElementById('passwordsGrid');
            
            if (passwords.length === 0) {
                grid.innerHTML = \`
                    <div class="empty-state">
                        <div class="icon">🔑</div>
                        <h3>没有找到密码</h3>
                        <p>\${searchQuery || categoryFilter ? '尝试调整搜索条件或清空筛选' : '点击"添加密码"标签页开始管理您的密码吧！'}</p>
                    </div>
                \`;
                return;
            }
            
            grid.innerHTML = passwords.map(password => \`
                <article class="password-card">
                    <header class="password-header">
                        <div class="site-icon">
                            <i class="fas fa-globe"></i>
                        </div>
                        <div class="password-meta">
                            <h3>\${password.siteName}</h3>
                            \${password.category ? \`<span class="category-badge">\${password.category}</span>\` : ''}
                        </div>
                    </header>
                    
                    <div class="password-field">
                        <label>👤 用户名</label>
                        <div class="value">\${password.username}</div>
                    </div>
                    
                    <div class="password-field">
                        <label>🔑 密码</label>
                        <div class="value" id="pwd-\${password.id}">••••••••</div>
                    </div>
                    
                    \${password.url ? \`
                        <div class="password-field">
                            <label>🔗 网址</label>
                            <div class="value"><a href="\${password.url}" target="_blank" rel="noopener noreferrer">\${password.url}</a></div>
                        </div>
                    \` : ''}
                    
                    \${password.notes ? \`
                        <div class="password-field">
                            <label>📝 备注</label>
                            <div class="value">\${password.notes}</div>
                        </div>
                    \` : ''}
                    
                    <footer class="password-actions">
                        <button class="btn btn-secondary btn-sm" onclick="togglePasswordDisplay('\${password.id}')" type="button" title="显示/隐藏密码">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="copyPassword('\${password.id}')" type="button" title="复制密码">
                            <i class="fas fa-copy"></i>
                        </button>
                        <button class="btn btn-info btn-sm" onclick="showPasswordHistory('\${password.id}')" type="button" title="查看历史">
                            <i class="fas fa-history"></i>
                        </button>
                        <button class="btn btn-warning btn-sm" onclick="editPassword('\${password.id}')" type="button" title="编辑">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deletePassword('\${password.id}')" type="button" title="删除">
                            <i class="fas fa-trash"></i>
                        </button>
                    </footer>
                </article>
            \`).join('');
        }

        // 显示密码历史记录
        async function showPasswordHistory(passwordId) {
            currentPasswordId = passwordId;
            try {
                const response = await fetch(\`/api/passwords/\${passwordId}/history\`, {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (!response.ok) {
                    throw new Error('获取历史记录失败');
                }
                
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                renderPasswordHistory(data.history);
                document.getElementById('historyModal').classList.add('show');
            } catch (error) {
                console.error('获取密码历史失败:', error);
                showNotification('获取历史记录失败: ' + error.message, 'error');
            }
        }

        // 渲染密码历史记录 - 添加删除按钮
        function renderPasswordHistory(history) {
            const content = document.getElementById('historyContent');
            
            if (!history || history.length === 0) {
                content.innerHTML = \`
                    <div class="empty-history">
                        <div class="icon">📜</div>
                        <h4>暂无历史记录</h4>
                        <p>该密码尚未有变更记录</p>
                    </div>
                \`;
                return;
            }
            
            content.innerHTML = history.map(entry => \`
                <div class="history-item">
                    <div class="history-header">
                        <span class="history-date">
                            <i class="fas fa-clock"></i> 
                            \${new Date(entry.changedAt).toLocaleString('zh-CN')}
                        </span>
                        <div class="history-actions">
                            <button class="btn btn-success btn-sm" onclick="restorePassword('\${entry.passwordId}', '\${entry.id}')" type="button" title="恢复此密码">
                                <i class="fas fa-undo"></i> 恢复
                            </button>
                            <button class="btn btn-danger btn-sm" onclick="deleteHistoryEntry('\${entry.passwordId}', '\${entry.id}')" type="button" title="删除此历史记录">
                                <i class="fas fa-trash"></i> 删除
                            </button>
                        </div>
                    </div>
                    <div class="password-field">
                        <label>🔑 历史密码</label>
                        <div class="history-password">\${entry.oldPassword}</div>
                    </div>
                    <div class="password-field">
                        <label>📝 变更原因</label>
                        <div class="value">\${entry.reason === 'password_update' ? '密码更新' : entry.reason}</div>
                    </div>
                </div>
            \`).join('');
        }

        // 删除单个历史记录
        async function deleteHistoryEntry(passwordId, historyId) {
            if (!confirm('确定要删除这条历史记录吗？')) {
                return;
            }
            
            try {
                const response = await fetch('/api/passwords/delete-history', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({
                        passwordId: passwordId,
                        historyId: historyId
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('历史记录已删除 🗑️');
                    // 重新加载历史记录
                    showPasswordHistory(passwordId);
                } else {
                    throw new Error(result.error || '删除失败');
                }
            } catch (error) {
                console.error('删除历史记录失败:', error);
                showNotification('删除历史记录失败: ' + error.message, 'error');
            }
        }

        // 删除所有历史记录
        async function deleteAllHistory() {
            if (!currentPasswordId) {
                showNotification('无法确定密码ID', 'error');
                return;
            }
            
            if (!confirm('确定要删除所有历史记录吗？此操作无法撤销。')) {
                return;
            }
            
            try {
                const response = await fetch('/api/passwords/delete-history', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({
                        passwordId: currentPasswordId,
                        historyId: 'all'
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification(result.message + ' 🗑️');
                    // 重新加载历史记录
                    showPasswordHistory(currentPasswordId);
                } else {
                    throw new Error(result.error || '删除失败');
                }
            } catch (error) {
                console.error('删除所有历史记录失败:', error);
                showNotification('删除所有历史记录失败: ' + error.message, 'error');
            }
        }

        // 恢复历史密码
        async function restorePassword(passwordId, historyId) {
            if (!confirm('确定要恢复到这个历史密码版本吗？当前密码将被替换。')) {
                return;
            }
            
            try {
                const response = await fetch('/api/passwords/restore', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({
                        passwordId: passwordId,
                        historyId: historyId
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('密码已恢复到历史版本 🔄');
                    closeHistoryModal();
                    loadPasswords(currentPage, searchQuery, categoryFilter);
                } else {
                    throw new Error(result.error || '恢复失败');
                }
            } catch (error) {
                console.error('恢复密码失败:', error);
                showNotification('恢复密码失败: ' + error.message, 'error');
            }
        }

        // 关闭历史记录模态框
        function closeHistoryModal() {
            document.getElementById('historyModal').classList.remove('show');
            currentPasswordId = null;
        }

        // 渲染分页
        function renderPagination(pagination) {
            let container = document.getElementById('paginationContainer');
            if (!container) {
                // 创建分页容器
                container = document.createElement('div');
                container.id = 'paginationContainer';
                container.className = 'pagination-container';
                document.getElementById('passwordsGrid').parentNode.appendChild(container);
            }
            
            if (!pagination || pagination.totalPages <= 1) {
                container.innerHTML = '';
                return;
            }
            
            let paginationHTML = \`
                <div class="pagination">
                    <div class="pagination-info">
                        显示第 \${((pagination.page - 1) * pagination.limit) + 1}-\${Math.min(pagination.page * pagination.limit, pagination.total)} 条，共 \${pagination.total} 条
                    </div>
                    <div class="pagination-controls">
            \`;
            
            // 上一页按钮
            if (pagination.hasPrev) {
                paginationHTML += \`
                    <button class="btn btn-secondary btn-sm" onclick="loadPasswords(\${pagination.page - 1}, '\${searchQuery}', '\${categoryFilter}')" type="button">
                        <i class="fas fa-chevron-left"></i> 上一页
                    </button>
                \`;
            }
            
            // 页码按钮
            const startPage = Math.max(1, pagination.page - 2);
            const endPage = Math.min(pagination.totalPages, pagination.page + 2);
            
            if (startPage > 1) {
                paginationHTML += \`
                    <button class="btn btn-secondary btn-sm" onclick="loadPasswords(1, '\${searchQuery}', '\${categoryFilter}')" type="button">1</button>
                \`;
                if (startPage > 2) {
                    paginationHTML += \`<span class="pagination-ellipsis">...</span>\`;
                }
            }
            
            for (let i = startPage; i <= endPage; i++) {
                const isActive = i === pagination.page;
                paginationHTML += \`
                    <button class="btn \${isActive ? 'btn-primary' : 'btn-secondary'} btn-sm" 
                            onclick="loadPasswords(\${i}, '\${searchQuery}', '\${categoryFilter}')" 
                            type="button" \${isActive ? 'disabled' : ''}>
                        \${i}
                    </button>
                \`;
            }
            
            if (endPage < pagination.totalPages) {
                if (endPage < pagination.totalPages - 1) {
                    paginationHTML += \`<span class="pagination-ellipsis">...</span>\`;
                }
                paginationHTML += \`
                    <button class="btn btn-secondary btn-sm" onclick="loadPasswords(\${pagination.totalPages}, '\${searchQuery}', '\${categoryFilter}')" type="button">\${pagination.totalPages}</button>
                \`;
            }
            
            // 下一页按钮
            if (pagination.hasNext) {
                paginationHTML += \`
                    <button class="btn btn-secondary btn-sm" onclick="loadPasswords(\${pagination.page + 1}, '\${searchQuery}', '\${categoryFilter}')" type="button">
                        下一页 <i class="fas fa-chevron-right"></i>
                    </button>
                \`;
            }
            
            paginationHTML += \`
                    </div>
                </div>
            \`;
            
            container.innerHTML = paginationHTML;
        }

        // 更新分页信息
        function updatePaginationInfo(pagination) {
            console.log('分页信息:', pagination);
        }

        // 过滤密码 - 支持分页
        function filterPasswords() {
            const searchTerm = document.getElementById('searchInput').value;
            const categoryFilter = document.getElementById('categoryFilter').value;
            
            // 重置到第一页并重新加载
            loadPasswords(1, searchTerm, categoryFilter);
        }

        // 显示/隐藏密码
        async function togglePasswordDisplay(passwordId) {
            const element = document.getElementById(\`pwd-\${passwordId}\`);
            const button = event.target.closest('button');
            
            if (element.textContent === '••••••••') {
                try {
                    const response = await fetch(\`/api/passwords/\${passwordId}/reveal\`, {
                        headers: {
                            'Authorization': 'Bearer ' + authToken
                        }
                    });
                    
                    const data = await response.json();
                    element.textContent = data.password;
                    button.innerHTML = '<i class="fas fa-eye-slash"></i>';
                } catch (error) {
                    showNotification('获取密码失败', 'error');
                }
            } else {
                element.textContent = '••••••••';
                button.innerHTML = '<i class="fas fa-eye"></i>';
            }
        }

        // 复制密码
        async function copyPassword(passwordId) {
            try {
                const response = await fetch(\`/api/passwords/\${passwordId}/reveal\`, {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const data = await response.json();
                await navigator.clipboard.writeText(data.password);
                showNotification('密码已复制到剪贴板 📋');
            } catch (error) {
                showNotification('复制失败', 'error');
            }
        }

        // 编辑密码
        function editPassword(passwordId) {
            const password = passwords.find(p => p.id === passwordId);
            if (!password) return;
            
            editingPasswordId = passwordId;
            
            document.getElementById('siteName').value = password.siteName;
            document.getElementById('username').value = password.username;
            document.getElementById('password').value = '';
            document.getElementById('category').value = password.category || '';
            document.getElementById('url').value = password.url || '';
            document.getElementById('notes').value = password.notes || '';
            
            // 隐藏重复警告
            hideDuplicateWarning();
            
            // 切换到添加密码标签页
            switchTab('add-password');
            
            // 更新按钮文本
            const submitBtn = document.querySelector('#passwordForm button[type="submit"]');
            submitBtn.innerHTML = '<i class="fas fa-save"></i> 更新密码';
        }

        // 删除密码 - 支持分页
        async function deletePassword(passwordId) {
            if (!confirm('🗑️ 确定要删除这个密码吗？此操作无法撤销。')) return;
            
            try {
                const response = await fetch(\`/api/passwords/\${passwordId}\`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    showNotification('密码已删除 🗑️');
                    // 重新加载当前页
                    loadPasswords(currentPage, searchQuery, categoryFilter);
                } else {
                    showNotification('删除失败', 'error');
                }
            } catch (error) {
                showNotification('删除失败', 'error');
            }
        }

        // 处理密码表单提交 - 改进版本，处理重复检查
        async function handlePasswordSubmit(e) {
            e.preventDefault();
            
            const formData = {
                siteName: document.getElementById('siteName').value,
                username: document.getElementById('username').value,
                password: document.getElementById('password').value,
                category: document.getElementById('category').value,
                url: document.getElementById('url').value,
                notes: document.getElementById('notes').value
            };
            
            // 如果是编辑模式，添加ID
            if (editingPasswordId) {
                formData.id = editingPasswordId;
            }
            
            try {
                const url = editingPasswordId ? \`/api/passwords/\${editingPasswordId}\` : '/api/passwords';
                const method = editingPasswordId ? 'PUT' : 'POST';
                
                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(formData)
                });
                
                if (response.ok) {
                    showNotification(editingPasswordId ? '密码已更新 ✅' : '密码已添加 ✅');
                    clearForm();
                    loadPasswords(currentPage, searchQuery, categoryFilter);
                } else if (response.status === 409) {
                    // 处理重复冲突
                    const result = await response.json();
                    showDuplicateWarning(result.existing);
                    showNotification(result.message, 'warning');
                } else {
                    showNotification('保存失败', 'error');
                }
            } catch (error) {
                showNotification('保存失败', 'error');
            }
        }

        // 清空表单
        function clearForm() {
            document.getElementById('passwordForm').reset();
            document.getElementById('lengthValue').textContent = '16';
            editingPasswordId = null;
            hideDuplicateWarning();
            
            // 恢复按钮文本
            const submitBtn = document.querySelector('#passwordForm button[type="submit"]');
            submitBtn.innerHTML = '<i class="fas fa-save"></i> 保存密码';
        }

        // 生成密码
        async function generatePassword() {
            const options = {
                length: parseInt(document.getElementById('passwordLength').value),
                includeUppercase: document.getElementById('includeUppercase').checked,
                includeLowercase: document.getElementById('includeLowercase').checked,
                includeNumbers: document.getElementById('includeNumbers').checked,
                includeSymbols: document.getElementById('includeSymbols').checked
            };
            
            try {
                const response = await fetch('/api/generate-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(options)
                });
                
                const data = await response.json();
                document.getElementById('password').value = data.password;
                document.getElementById('password').type = 'text';
                showNotification('强密码已生成 🎲');
            } catch (error) {
                showNotification('生成密码失败', 'error');
            }
        }

        // 切换密码可见性
        function togglePasswordVisibility(fieldId) {
            const field = document.getElementById(fieldId);
            const button = event.target.closest('button');
            const icon = button.querySelector('i');
            
            if (field.type === 'password') {
                field.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                field.type = 'password';
                icon.className = 'fas fa-eye';
            }
        }

        // WebDAV测试连接
        async function testWebDAVConnection() {
            const config = {
                webdavUrl: document.getElementById('webdavUrl').value,
                username: document.getElementById('webdavUsername').value,
                password: document.getElementById('webdavPassword').value
            };
            
            if (!config.webdavUrl || !config.username || !config.password) {
                showNotification('请填写完整的WebDAV配置', 'error');
                return;
            }
            
            const button = event.target;
            const originalText = button.innerHTML;
            button.innerHTML = '<div class="loading"></div> 测试中...';
            button.disabled = true;
            
            try {
                const response = await fetch('/api/webdav/test', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(config)
                });
                
                const result = await response.json();
                if (result.success) {
                    showNotification('✅ WebDAV连接成功！', 'success');
                } else {
                    showNotification(result.error || 'WebDAV连接失败', 'error');
                }
            } catch (error) {
                showNotification('WebDAV连接测试失败', 'error');
            } finally {
                button.innerHTML = originalText;
                button.disabled = false;
            }
        }

        // WebDAV配置管理
        async function saveWebDAVConfig() {
            const config = {
                webdavUrl: document.getElementById('webdavUrl').value,
                username: document.getElementById('webdavUsername').value,
                password: document.getElementById('webdavPassword').value
            };
            
            if (!config.webdavUrl || !config.username || !config.password) {
                showNotification('请填写完整的WebDAV配置', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/webdav/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify(config)
                });
                
                if (response.ok) {
                    showNotification('WebDAV配置已保存 ✅');
                } else {
                    showNotification('保存配置失败', 'error');
                }
            } catch (error) {
                showNotification('保存配置失败', 'error');
            }
        }

        async function loadWebDAVConfig() {
            try {
                const response = await fetch('/api/webdav/config', {
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                if (response.ok) {
                    const config = await response.json();
                    if (config.webdavUrl) {
                        document.getElementById('webdavUrl').value = config.webdavUrl;
                        document.getElementById('webdavUsername').value = config.username;
                        document.getElementById('webdavPassword').value = config.password;
                    }
                }
            } catch (error) {
                console.error('Failed to load WebDAV config:', error);
            }
        }

        async function loadWebDAVFiles() {
            try {
                const response = await fetch('/api/webdav/list', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
                
                const result = await response.json();
                if (result.success) {
                    renderBackupFiles(result.files);
                } else {
                    showNotification(result.error || '获取文件列表失败', 'error');
                }
            } catch (error) {
                showNotification('获取文件列表失败', 'error');
            }
        }

        async function createWebDAVBackup() {
            const backupPassword = document.getElementById('backupPassword').value;
            if (!backupPassword) {
                showNotification('请设置备份密码', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/webdav/backup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ backupPassword })
                });
                
                const result = await response.json();
                if (result.success) {
                    showNotification(\`备份成功：\${result.filename} ☁️\`);
                    document.getElementById('backupPassword').value = '';
                    loadWebDAVFiles();
                } else {
                    showNotification(result.error || '备份失败', 'error');
                }
            } catch (error) {
                showNotification('备份失败', 'error');
            }
        }

        async function restoreWebDAVBackup(filename) {
            const restorePassword = prompt(\`请输入备份文件 \${filename} 的密码：\`);
            if (!restorePassword) return;
            
            if (!confirm(\`确定要从 \${filename} 恢复数据吗？\`)) return;
            
            try {
                const response = await fetch('/api/webdav/restore', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({
                        filename: filename,
                        restorePassword: restorePassword
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    showNotification(result.message + ' 🔄');
                    loadPasswords(currentPage, searchQuery, categoryFilter);
                } else {
                    showNotification(result.error || '恢复失败', 'error');
                }
            } catch (error) {
                showNotification('恢复失败', 'error');
            }
        }

        async function deleteWebDAVBackup(filename) {
            if (!confirm(\`确定要删除 \${filename} 吗？\`)) return;
            
            try {
                const response = await fetch('/api/webdav/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ filename: filename })
                });
                
                const result = await response.json();
                if (result.success) {
                    showNotification('删除成功 🗑️');
                    loadWebDAVFiles();
                } else {
                    showNotification(result.error || '删除失败', 'error');
                }
            } catch (error) {
                showNotification('删除失败', 'error');
            }
        }

        function renderBackupFiles(files) {
            const container = document.getElementById('backupFilesList');
            
            if (files.length === 0) {
                container.innerHTML = '<p class="text-center" style="color: #6b7280;">没有找到备份文件</p>';
                return;
            }
            
            container.innerHTML = files.map(file => \`
                <div class="backup-file">
                    <span>📁 \${file}</span>
                    <div class="backup-file-actions">
                        <button class="btn btn-success btn-sm" onclick="restoreWebDAVBackup('\${file}')" type="button">
                            <i class="fas fa-download"></i> 恢复
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deleteWebDAVBackup('\${file}')" type="button">
                            <i class="fas fa-trash"></i> 删除
                        </button>
                    </div>
                </div>
            \`).join('');
        }

        // 导出数据
        async function exportData() {
            const exportPassword = document.getElementById('exportPassword').value;
            if (!exportPassword) {
                showNotification('请设置导出密码', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/export-encrypted', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + authToken
                    },
                    body: JSON.stringify({ exportPassword })
                });
                
                const blob = await response.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = \`passwords-encrypted-export-\${new Date().toISOString().split('T')[0]}.json\`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(downloadUrl);
                
                showNotification('加密数据导出成功 📤');
                document.getElementById('exportPassword').value = '';
            } catch (error) {
                showNotification('导出失败', 'error');
            }
        }

        // 处理文件选择
        function handleFileSelect() {
            const fileInput = document.getElementById('importFile');
            selectedFile = fileInput.files[0];
            
            if (selectedFile) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    try {
                        const data = JSON.parse(e.target.result);
                        if (data.encrypted) {
                            document.getElementById('encryptedImportForm').classList.remove('hidden');
                        } else {
                            showNotification('只支持加密文件导入', 'error');
                            fileInput.value = '';
                            selectedFile = null;
                        }
                    } catch (error) {
                        showNotification('文件格式错误', 'error');
                    }
                };
                reader.readAsText(selectedFile);
            }
        }

        // 导入数据
        async function importData() {
            if (!selectedFile) {
                showNotification('请选择文件', 'error');
                return;
            }
            
            const importPassword = document.getElementById('importPassword').value;
            if (!importPassword) {
                showNotification('请输入导入密码', 'error');
                return;
            }
            
            try {
                const reader = new FileReader();
                reader.onload = async function(e) {
                    const fileContent = e.target.result;
                    const data = JSON.parse(fileContent);
                    
                    const response = await fetch('/api/import-encrypted', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + authToken
                        },
                        body: JSON.stringify({
                            encryptedData: data.data,
                            importPassword: importPassword
                        })
                    });
                    
                    const result = await response.json();
                    if (response.ok) {
                        showNotification(\`导入完成：成功 \${result.imported} 条，失败 \${result.errors} 条 📥\`);
                        document.getElementById('importFile').value = '';
                        document.getElementById('importPassword').value = '';
                        document.getElementById('encryptedImportForm').classList.add('hidden');
                        selectedFile = null;
                        loadPasswords(currentPage, searchQuery, categoryFilter);
                    } else {
                        showNotification(result.error || '导入失败', 'error');
                    }
                };
                reader.readAsText(selectedFile);
            } catch (error) {
                showNotification('导入失败：文件格式错误', 'error');
            }
        }

        // 登出
        async function logout() {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + authToken
                    }
                });
            } catch (error) {
                console.error('Logout error:', error);
            }
            
            localStorage.removeItem('authToken');
            authToken = null;
            currentUser = null;
            showAuthSection();
        }

        // 显示通知
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = \`notification \${type}\`;
            
            const icons = {
                success: 'check-circle',
                error: 'exclamation-triangle',
                warning: 'exclamation-circle',
                info: 'info-circle'
            };
            
            notification.innerHTML = \`
                <i class="fas fa-\${icons[type] || icons.success}"></i>
                \${message}
            \`;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (document.body.contains(notification)) {
                        document.body.removeChild(notification);
                    }
                }, 300);
            }, 3000);
        }
    </script>
</body>
</html>`;
}
