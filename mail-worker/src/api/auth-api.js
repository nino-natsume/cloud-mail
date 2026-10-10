import app from '../hono/hono';
import oauthService from '../service/oauth-service';

/**
 * 统一授权中心 (anime 内那套 oauth.107211.xyz) 接入
 *
 * 流程:
 *   前端点击「统一登录」 -> GET  /api/auth/oauth
 *     -> 302 跳转 `${oauthBase}/oauth?ref=<本站 SSO 回调>&redirect=<本站 SSO 回调>`
 *     -> 用户在授权中心任选第三方 (github/google/linuxdo/...) 完成登录
 *     -> 授权中心 302 回跳本站 `GET|POST /api/auth/sso?oauth_success=1&provider=...&...`
 *     -> 本站据回传身份落库 oauth 表, 已绑定邮箱 -> 发 token 回前端, 未绑定 -> 回前端弹绑定框
 */

// 授权中心地址 (可用 vars 覆盖)
function oauthBase(c) {
	return String(c.env.oauth_url || c.env.OAUTH_URL || 'https://oauth.107211.xyz').replace(/\/+$/, '');
}

// 本站对外地址 (用于拼接 SSO 回调与前端回跳地址)
function siteBase(c) {
	const configured = c.env.site_url || c.env.SITE_URL;
	if (configured) return String(configured).replace(/\/+$/, '');
	return new URL(c.req.url).origin;
}

function ssoEndpoint(c) {
	return `${siteBase(c)}/api/auth/sso`;
}

// 判断是否来自 APK 内 WebView (UA 带 NarumiApp 标记)
function isNarumiApp(ua) {
	return /narumi(?:app)?\/?[0-9.]*/i.test(String(ua || ''));
}

// 统一登录入口: 跳转授权中心 /oauth 页面
app.get('/auth/oauth', (c) => {
	const ref = ssoEndpoint(c);
	// APK 内 WebView 的 UA 带 NarumiApp 标记 -> 只在 ref 上追加 app=1,
	// 以便登录若在外部浏览器/第三方 App 内完成时, SSO 端点用 narumi:// 深链把结果交还 APK
	const isApp = isNarumiApp(c.req.header('User-Agent'));
	const refFinal = isApp ? `${ref}?app=1` : ref;
	const q = `ref=${encodeURIComponent(refFinal)}&redirect=${encodeURIComponent(ref)}`;
	return c.redirect(`${oauthBase(c)}/oauth?${q}`);
});

async function handleSso(c) {
	const url = new URL(c.req.url);

	// 回跳参数可能在 query, 也可能在 hash fragment
	const params = new URLSearchParams(url.search);
	const hashIdx = url.hash.indexOf('?');
	if (hashIdx >= 0) {
		for (const [k, v] of new URLSearchParams(url.hash.slice(hashIdx + 1))) {
			if (!params.has(k)) params.set(k, v);
		}
	}

	// 兼容 form_post (response_mode=form_post)
	if (c.req.method === 'POST') {
		try {
			const form = await c.req.formData();
			for (const [k, v] of form.entries()) {
				if (!params.has(k)) params.set(k, String(v));
			}
		} catch {
			// 非表单 POST, 忽略
		}
	}

	// 归一化取值: 依次尝试多个参数名, 取第一个非空值 (与 anime 保持一致)
	const get = (...names) => {
		for (const n of names) {
			const v = (params.get(n) || '').trim();
			if (v) return v;
		}
		return '';
	};

	const successRaw = get('oauth_success', 'status', 'success');
	const success = ['1', 'true', 'success', 'ok', 'yes'].includes(successRaw.toLowerCase());
	const platform = get('provider', 'platform');
	const username = get('username', 'login', 'preferred_username', 'nickname');
	const name = get('name', 'display_name', 'realname');
	const email = get('email', 'mail');
	const avatar = get('avatar', 'avatar_url', 'avatarUrl', 'picture', 'photo');
	const oauthIdRaw = get('id', 'sub', 'uid', 'openid');

	const loginUrl = `${siteBase(c)}/login`;
	// APK 外部流程 (登录在外部浏览器/App 内完成) -> 用 narumi:// 深链把结果交还 APK
	const fromApp = params.get('app') === '1' && !isNarumiApp(c.req.header('User-Agent'));
	const fail = (msg) => c.redirect(
		fromApp
			? `narumi://auth?error=${encodeURIComponent(msg)}`
			: `${loginUrl}?error=${encodeURIComponent(msg)}`
	);

	if (!success || !platform) return fail('未获得第三方授权, 请重新尝试');
	if (!/^[a-z0-9_-]{1,32}$/i.test(platform)) return fail('登录来源无效');

	// 稳定身份键: 授权中心回传里没有平台数字 id, 按 email > username > name 回退 (与 anime 一致);
	// 加平台前缀避免不同平台同名冲突
	const identity = (email || username || name || oauthIdRaw || '').slice(0, 120).trim();
	if (!identity) return fail('未能识别第三方账号身份');
	const oauthUserId = `${platform}:${identity}`;

	let token = null;
	try {
		const data = await oauthService.saveAndLogin(c, {
			oauthUserId,
			username: username || name || platform,
			name: name || username || '',
			avatar: avatar || '',
			platform,
			active: 1,
			trustLevel: 0,
			silenced: 0
		});
		token = data && data.token;
	} catch (err) {
		console.error('cloud-mail SSO error:', err);
		return fail('登录处理异常, 请稍后再试');
	}

	// 已绑定邮箱 -> 携带 token 回前端登录
	if (token) {
		return c.redirect(
			fromApp
				? `narumi://auth?token=${encodeURIComponent(token)}`
				: `${loginUrl}?token=${encodeURIComponent(token)}`
		);
	}

	// 未绑定邮箱 -> 带 oauthUserId 回前端弹绑定框 (复用既有绑定流程)
	const bindParams = new URLSearchParams({ oauthUserId, platform });
	if (username) bindParams.set('username', username);
	if (avatar) bindParams.set('avatar', avatar);
	// APK 外部流程: 用深链把 pending 绑定信息交还 APK (由 App 构造站内 /login 回调)
	const bindQuery = fromApp ? `narumi://auth?${bindParams.toString()}` : `${loginUrl}?${bindParams.toString()}`;
	return c.redirect(bindQuery);
}

app.get('/auth/sso', handleSso);
app.post('/auth/sso', handleSso);
