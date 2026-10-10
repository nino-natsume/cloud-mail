# cloud-mail Android (WebView APK)

将 cloud-mail 网页封装为原生 Android APK，WebView 加载线上站点，**零白屏**启动。

## 构建方式

### 方式一：GitHub Actions（推荐，云构建）

仓库已包含 `.github/workflows/android-build.yml`：

1. 把 `android/` 目录推送到 GitHub 仓库 `main` 分支
2. 自动触发构建（或到 Actions 页手动 Run workflow）
3. 构建完成 → 进入本次运行 → **Artifacts** 下载 `Narumi-Debug-APK`

> Release 打包：创建 GitHub Release 时自动把 APK 挂到附件。

### 方式二：Android Studio / 本地

```powershell
cd <repo>\android
.\build_apk.ps1        # 需已装 Java 17 + Android SDK
# 或将 android/ 用 Android Studio 打开, 直接 Run / Build APK
```

## 零白屏实现

| 层 | 方案 |
|----|------|
| Android 窗口背景 | `#0A0A0F`（与网页暗色一致），冷启动屏幕即主题色，无白色闪屏 |
| Splash | 无独立 Splash，窗口背景即首帧，点击图标直接进入首屏 |
| WebView | 启动即 `loadUrl()`，无任何延时 |
| 前端 | `init()` 同步渲染骨架屏 + 立即移除 Loader，网络请求后台并行 |
| 加载进度 | 顶部 3dp 渐变进度条，页面加载完自动隐藏 |
| 断网兜底 | 暗色错误页 + 重试按钮，不白屏 |

## 注意

- 默认加载 `https://107211.xyz`，如需改地址编辑 `MainActivity.java` 里的 `SITE_URL`
- Debug APK 已带调试签名，可直接安装到手机（需允许「安装未知来源应用」）
- Release 包：`gradle assembleRelease`（需配置签名 keystore）

## OAuth 登录（全程应用内完成）

登录完整在 WebView 内完成（站点整页进入授权中心），**不跳外部浏览器**：

1. WebView 的 UA 附加 `NarumiApp/1.0` 标记，后端据此识别登录由 APK 发起
2. 站内 `openAuthCenter` 检测到 APK UA 时整页跳转授权中心（`oauth.107211.xyz`），
   不再使用 iframe 弹层，避免第三方授权页被 `X-Frame-Options` 拦截
3. `shouldOverrideUrlLoading` 将授权中心并提升为主框架展示；授权流程（`inAuthFlow`）期间
   所有第三方授权页（QQ/微信/GitHub/Google 等）都留在 WebView 内，不打开系统浏览器
4. 需要拉起对应 App 的登录（QQ 等）：`mqqapi://`、`weixin://`、`intent://` 等自定义
   scheme 仍会交给系统里对应的 App 处理；若该 App 的流程被迫转到外部浏览器，
   后端会用 `narumi://auth?token=...&user=...` 深链交还 APK
   （`singleTask` + `onNewIntent` 接收，再以站内 `#/auth-callback` URL 注入 WebView）

> 配套后端：`mail-worker/src/api/auth-api.js` 的 `/auth/oauth`、`/auth/sso` 已处理 `app=1`
> 标记、`narumi://` 交还逻辑。若在 APK 内登录不回来，先确认后端已更新部署。