#!/usr/bin/env bash
# build-release.sh — 交叉编译发布用的静态二进制，打包成 tar.gz 并生成 SHA256SUMS。
#
# 用法：scripts/build-release.sh <版本号> [输出目录，默认仓库根目录下的 dist]
#
# 产物（每个包里是 httpgrep 可执行文件和 LICENSE，放在同名目录下）：
#   httpgrep-<版本号>-linux-x86_64.tar.gz
#   httpgrep-<版本号>-linux-arm64.tar.gz
#   httpgrep-<版本号>-mac-arm64.tar.gz
#   httpgrep-<版本号>-mac-x86_64.tar.gz
#   SHA256SUMS
#
# 全部用 CGO_ENABLED=0 编译，不依赖 libc；版本号经 -X main.version 注入，--version 可见。
# GitHub 的 CI 和 Release 流水线都调用这个脚本。
set -euo pipefail

version=${1:?usage: scripts/build-release.sh VERSION [OUTDIR]}
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$repo/dist}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$repo"

# macOS 的 tar 会把扩展属性打成 ._ 文件，关掉。
export COPYFILE_DISABLE=1

if command -v sha256sum >/dev/null 2>&1; then
  sum=(sha256sum)
else
  sum=(shasum -a 256)
fi

# GOOS/GOARCH/产物名里的平台标签
targets=(
  linux/amd64/linux-x86_64
  linux/arm64/linux-arm64
  darwin/arm64/mac-arm64
  darwin/amd64/mac-x86_64
)

archives=()
for t in "${targets[@]}"; do
  IFS=/ read -r goos goarch label <<<"$t"
  name="httpgrep-$version-$label"
  rm -rf "${out:?}/$name" "$out/$name.tar.gz"
  mkdir -p "$out/$name"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath \
    -ldflags "-s -w -X main.version=$version" \
    -o "$out/$name/httpgrep" ./cmd/httpgrep
  cp LICENSE "$out/$name/"
  tar -C "$out" -czf "$out/$name.tar.gz" "$name"
  rm -rf "${out:?}/$name"
  archives+=("$name.tar.gz")
  echo "built $name.tar.gz"
done

(cd "$out" && "${sum[@]}" "${archives[@]}" >SHA256SUMS)
echo "wrote $out/SHA256SUMS"
