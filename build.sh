#!/usr/bin/env bash
# build.sh — 在 Linux/macOS 上构建 tp-link-decrypt
# 用法:
#   ./build.sh              # 构建本机平台与 Linux（默认）
#   ./build.sh --linux      # 仅构建 Linux amd64
#   ./build.sh --win        # 仅构建 Windows amd64
#   ./build.sh --arch arm64 # 指定架构 (amd64/arm64)，默认 amd64

set -euo pipefail
cd "$(dirname "$0")"

ARCH="amd64"
BUILD_LINUX=0
BUILD_WIN=0

for arg in "$@"; do
  case "$arg" in
    --linux) BUILD_LINUX=1 ;;
    --win)   BUILD_WIN=1 ;;
    --arch)  ARCH="${2:-amd64}"; shift ;;
    *) echo "未知参数: $arg"; exit 1 ;;
  esac
done

# 默认都构建
if [[ "$BUILD_LINUX" == "0" && "$BUILD_WIN" == "0" ]]; then
  BUILD_LINUX=1
  BUILD_WIN=1
fi

mkdir -p dist

build_target() {
  local name="$1" goos="$2" ext="$3"
  local out="dist/tp-link-decrypt-${goos}-${ARCH}${ext}"
  echo "==> 构建 $name ($goos/$ARCH) -> $out"
  GOOS="$goos" GOARCH="$ARCH" go build -trimpath -ldflags "-s -w" -o "$out" .
  echo "    ✓ 完成"
}

[[ "$BUILD_WIN" == "1" ]] && build_target "Windows" "windows" ".exe"
[[ "$BUILD_LINUX" == "1" ]] && build_target "Linux" "linux" ""

echo
echo "全部构建完成，输出目录: $(pwd)/dist"
