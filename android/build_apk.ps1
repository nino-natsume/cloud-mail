# ═══════════════════════════════════════════════
#  Narumi APK 本地构建脚本 (可选, 推荐用 GitHub Actions)
# ═══════════════════════════════════════════════
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "🌸 Narumi APK 构建开始 (推荐用 GitHub Actions, 本脚本为本地备选)" -ForegroundColor Cyan

# ── 1. 检查 Java 17 ──
$javaOk = $false
if (Get-Command java -ErrorAction SilentlyContinue) {
    $ver = (java -version 2>&1 | Select-Object -First 1)
    if ($ver -match '"(17|2[0-9])\.') { $javaOk = $true; Write-Host "✓ Java: $ver" -ForegroundColor Green }
}
if (-not $javaOk) {
    Write-Host "需要 Java 17+。安装: https://adoptium.net/  (winget install EclipseAdoptium.Temurin.17.JDK)" -ForegroundColor Yellow
    exit 1
}

# ── 2. 检查 Android SDK ──
$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = "$env:LOCALAPPDATA\Android\Sdk" }
if (-not (Test-Path "$sdk\platform-tools\adb.exe")) {
    Write-Host "需要 Android SDK。安装 Android Studio 或命令行工具: https://developer.android.com/studio#command-line-tools-only" -ForegroundColor Yellow
    exit 1
}
Write-Host "✓ Android SDK: $sdk" -ForegroundColor Green

# ── 3. local.properties ──
$sdkForward = $sdk -replace '\\', '/'
if (-not (Test-Path "$Root\local.properties")) {
    Set-Content -Path "$Root\local.properties" -Value "sdk.dir=$sdkForward`n" -Encoding UTF8
}

# ── 4. Gradle wrapper (若无则下载) ──
if (-not (Test-Path "$Root\gradlew.bat") -or -not (Test-Path "$Root\gradle\wrapper\gradle-wrapper.jar")) {
    Write-Host "下载 Gradle Wrapper 8.5..." -ForegroundColor Yellow
    Invoke-WebRequest "https://raw.githubusercontent.com/gradle/gradle/v8.5.0/gradlew.bat" -OutFile "$Root\gradlew.bat" -ErrorAction SilentlyContinue
    Invoke-WebRequest "https://services.gradle.org/distributions/gradle-8.5-bin.zip" -OutFile "$env:TEMP\gradle-8.5-bin.zip" -ErrorAction SilentlyContinue
}

# ── 5. 构建 ──
Push-Location $Root
try {
    if (Get-Command gradle -ErrorAction SilentlyContinue) {
        & gradle assembleDebug --no-daemon
    } elseif (Test-Path "$Root\gradlew.bat") {
        & "$Root\gradlew.bat" assembleDebug --no-daemon
    } else {
        Write-Host "未找到 gradle, 请安装并加入 PATH" -ForegroundColor Red
        exit 1
    }
    if ($LASTEXITCODE -ne 0) { Write-Host "✗ 构建失败" -ForegroundColor Red; exit 1 }

    $apk = Get-ChildItem "$Root\app\build\outputs\apk\debug\*.apk" | Select-Object -First 1
    if ($apk) {
        Write-Host ""
        Write-Host "✓✓✓ 构建成功!" -ForegroundColor Green
        Write-Host "APK: $($apk.FullName)" -ForegroundColor Cyan
        Write-Host "大小: $([math]::Round($apk.Length / 1MB, 2)) MB"
    } else {
        Write-Host "✗ 未找到 APK 输出" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}