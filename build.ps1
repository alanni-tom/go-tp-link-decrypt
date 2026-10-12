# build.ps1 — 交叉编译 tp-link-decrypt 到 Windows 与 Linux
# 用法:
#   .\build.ps1              # 同时构建 Windows 与 Linux（默认）
#   .\build.ps1 -win         # 仅 Windows
#   .\build.ps1 -linux       # 仅 Linux
#   .\build.ps1 -arch amd64  # 指定架构 (amd64/arm64)，默认 amd64

param(
    [switch]$win,
    [switch]$linux,
    [string]$arch = "amd64"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Build-Target {
    param(
        [string]$Name,
        [string]$GOOS,
        [string]$Ext
    )
    $out = "dist/tp-link-decrypt-$GOOS-$arch$Ext"
    Write-Host "==> 构建 $Name ($GOOS/$arch) -> $out" -ForegroundColor Cyan
    $env:GOOS = $GOOS
    $env:GOARCH = $arch
    go build -trimpath -ldflags "-s -w" -o $out .
    if ($LASTEXITCODE -ne 0) { throw "构建 $Name 失败" }
    Write-Host "    ✓ 完成" -ForegroundColor Green
}

# 默认：未指定任何参数时，同时构建两者
if (-not $win -and -not $linux) {
    $win = $true
    $linux = $true
}

if ($win) { Build-Target "Windows" "windows" ".exe" }
if ($linux) { Build-Target "Linux" "linux" "" }

Write-Host "`n全部构建完成，输出目录: $PSScriptRoot\dist" -ForegroundColor Yellow
