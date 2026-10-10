package com.narumi.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;

public class MainActivity extends Activity {

    private WebView webView;
    private ProgressBar progressBar;
    private ValueCallback<Uri[]> fileChooserCallback;
    private static final int FILE_CHOOSER_REQUEST = 100;

    private static final String SITE_URL = "https://107211.xyz";
    private static final String AUTH_CENTER_URL = "https://oauth.107211.xyz";

    // 是否正处于登录授权流程中 (从站内 /api/auth/ 入口进入, 到站内 /login 回调结束)。
    // 流程期间所有第三方授权页都留在 WebView 内, 不跳外部浏览器。
    private volatile boolean inAuthFlow = false;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 零白屏: 透明状态栏 + 沉浸式
        Window window = getWindow();
        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(0xFF0A0A0F);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.getDecorView().setSystemUiVisibility(0); // light icons off (暗色背景)
        }

        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webView);
        progressBar = findViewById(R.id.progressBar);

        // WebView 配置
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
        settings.setMediaPlaybackRequiresUserGesture(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);

        // 附加应用标记: 后端 (cloud-mail /api/auth) 据此识别登录由 APK 发起,
        // 登录若在外部浏览器/对应 App 内完成时, 会用 narumi:// 深链把结果交还本应用
        String defaultUa = settings.getUserAgentString();
        if (defaultUa == null || !defaultUa.contains("NarumiApp")) {
            settings.setUserAgentString((defaultUa == null ? "" : defaultUa) + " NarumiApp/1.0");
        }

        // Cookie 支持 (登录态保持)
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true);

        // 防止外部浏览器打断登录流程 (授权页全部留在 WebView, 见 shouldOverrideUrlLoading)
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                String scheme = request.getUrl().getScheme();
                scheme = scheme == null ? "" : scheme.toLowerCase();

                // 1) 自定义 scheme (mqqapi:// 拉起 QQ、weixin:// 拉起微信等 OAuth 客户端)
                //    → 交给系统里对应的 App 处理
                if (!scheme.equals("http") && !scheme.equals("https")) {
                    return launchExternalApp(url);
                }

                // 若当前页面已是授权中心/正在第三方授权, 视为处于授权流程中
                String current = view.getUrl();
                if (current != null && current.startsWith(AUTH_CENTER_URL)) {
                    inAuthFlow = true;
                }

                // 2) 统一 OAuth 授权中心: APK 内站点整页进入, 若偶发被放进了 iframe 则提升为主框架,
                //    避免第三方授权页被 X-Frame-Options 拦截无法渲染
                if (url.startsWith(AUTH_CENTER_URL)) {
                    inAuthFlow = true;
                    if (!request.isForMainFrame()) {
                        view.loadUrl(url);
                        return true;
                    }
                    return false;
                }

                // 3) 站内页面留在 WebView; 回到站内登录回调 (/login?...token=...) 即授权流程结束
                if (url.startsWith(SITE_URL)) {
                    if (url.contains("/login")) inAuthFlow = false;
                    return false;
                }

                // 4) 授权流程中的第三方授权页 (QQ/微信/GitHub/Google 等)
                //    → 全部留在 WebView 内完成, 不再打开外部浏览器
                if (inAuthFlow) {
                    return false;
                }

                // 5) 其余外部链接 → 系统浏览器
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                    return true;
                } catch (Exception e) {
                    return false; // 没有可用浏览器时让 WebView 自行处理
                }
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                progressBar.setVisibility(View.VISIBLE);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                progressBar.setVisibility(View.GONE);
                // 注入 CSS: 隐藏加载动画, 确保即开即显示
                view.evaluateJavascript(
                    "(function(){" +
                    "  var l=document.getElementById('loader');" +
                    "  if(l)l.style.display='none';" +
                    "  document.body.classList.remove('no-scroll');" +
                    "})()", null
                );
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    view.loadData(
                        "<html><body style='background:#0a0a0f;color:#a0a0b8;display:flex;align-items:center;justify-content:center;height:100vh;font-family:system-ui;margin:0'>" +
                        "<div style='text-align:center'>" +
                        "<div style='font-size:48px;margin-bottom:16px'>🌸</div>" +
                        "<h2 style='color:#f0f0f5;margin-bottom:8px'>Narumi</h2>" +
                        "<p>网络连接失败，请检查网络后重试</p>" +
                        "<button onclick='location.reload()' style='margin-top:16px;padding:8px 24px;border-radius:20px;border:1px solid #00d4ff;background:transparent;color:#00d4ff;font-size:14px;cursor:pointer'>重试</button>" +
                        "</div></body></html>",
                        "text/html", "UTF-8"
                    );
                }
            }
        });

        // 文件选择支持 (头像上传等)
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileChooserCallback != null) {
                    fileChooserCallback.onReceiveValue(null);
                }
                fileChooserCallback = callback;
                Intent intent = params.createIntent();
                try {
                    startActivityForResult(intent, FILE_CHOOSER_REQUEST);
                } catch (Exception e) {
                    fileChooserCallback = null;
                    return false;
                }
                return true;
            }

            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (newProgress < 100) {
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setProgress(newProgress);
                } else {
                    progressBar.setVisibility(View.GONE);
                }
            }
        });

        // 立即加载, 无延迟; 若由 narumi:// 深链拉起则直接进入登录回调
        Uri launchData = getIntent().getData();
        String callbackUrl = (launchData != null && "narumi".equals(launchData.getScheme()))
                ? buildAuthCallbackUrl(launchData) : null;
        webView.loadUrl(callbackUrl != null ? callbackUrl : SITE_URL);
    }

    /** 拉起系统内能处理该自定义 scheme 的 App (QQ/微信等 OAuth 客户端); 失败时安静吞掉 */
    private boolean launchExternalApp(String url) {
        try {
            Intent intent;
            if (url.startsWith("intent://")) {
                intent = Intent.parseUri(url, Intent.URI_INTENT_SCHEME); // 含浏览器 fallback 时系统自行处理
            } else {
                intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                intent.addCategory(Intent.CATEGORY_BROWSABLE);
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if (intent.resolveActivity(getPackageManager()) != null) {
                startActivity(intent);
                return true;
            }
        } catch (Exception ignored) {
            // 未安装对应 App / 无法解析: 静默吞掉, 避免 WebView 报 ERR_UNKNOWN_URL_SCHEME
        }
        return true; // 已被消费 (即使拉起失败也不再让 WebView 处理)
    }

    /** 把 narumi://auth?token=...&user=... (或 error=... / oauthUserId=...) 转成站内 /login 回调 URL */
    private String buildAuthCallbackUrl(Uri data) {
        String token = data.getQueryParameter("token");
        String error = data.getQueryParameter("error");
        String oauthUserId = data.getQueryParameter("oauthUserId");
        String platform = data.getQueryParameter("platform");
        String user = data.getQueryParameter("user");
        if (token == null && error == null && oauthUserId == null) return null;
        StringBuilder sb = new StringBuilder(SITE_URL).append("/login?");
        if (error != null) {
            sb.append("error=").append(Uri.encode(error));
        } else if (token != null) {
            sb.append("token=").append(Uri.encode(token));
            // user 经深链解析后已是原始 JSON, 需重新编码再注入站内回调 URL
            if (user != null) sb.append("&user=").append(Uri.encode(user));
        } else {
            // 未绑定邮箱: 交还 oauthUserId 让站内弹绑定框
            sb.append("oauthUserId=").append(Uri.encode(oauthUserId));
            if (platform != null) sb.append("&platform=").append(Uri.encode(platform));
        }
        return sb.toString();
    }

    /** 应用已运行 (singleTask) 时收到 narumi:// 深链: 直接转入登录回调 */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        Uri data = intent.getData();
        if (data != null && "narumi".equals(data.getScheme()) && webView != null) {
            String callbackUrl = buildAuthCallbackUrl(data);
            if (callbackUrl != null) {
                webView.loadUrl(callbackUrl);
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_CHOOSER_REQUEST) {
            if (fileChooserCallback != null) {
                Uri[] results = null;
                if (resultCode == RESULT_OK && data != null) {
                    results = new Uri[]{data.getData()};
                }
                fileChooserCallback.onReceiveValue(results);
                fileChooserCallback = null;
            }
        }
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            // 双击退出
            moveTaskToBack(true);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        webView.onResume();
        // 恢复 Cookie 同步
        CookieManager.getInstance().flush();
    }

    @Override
    protected void onPause() {
        webView.onPause();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        webView.destroy();
        super.onDestroy();
    }
}
