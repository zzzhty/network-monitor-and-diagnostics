#!/usr/bin/env bash
# 下载被 .gitignore 排除的二进制资产 (mihomo deb + geodata)
# 如需代理下载，请由操作者显式设置 HTTPS_PROXY；仓库不预设个人出口。
set -euo pipefail
cd "$(dirname "$0")"
VER=v1.19.30
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo '仅支持 Linux amd64 / arm64' >&2; exit 1 ;;
esac
stage=$(mktemp -d .assets.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
echo ">> mihomo $VER"
curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 -o "$stage/mihomo.deb" "https://github.com/MetaCubeX/mihomo/releases/download/$VER/mihomo-linux-$ARCH-$VER.deb"
echo ">> geodata (latest)"
curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 -o "$stage/geoip.metadb" https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb
curl -fsSL --connect-timeout 10 --max-time 180 --retry 3 -o "$stage/GeoSite.dat" https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat
mv -f "$stage/mihomo.deb" "$stage/geoip.metadb" "$stage/GeoSite.dat" .
ls -lh mihomo.deb geoip.metadb GeoSite.dat
echo "== 完成 =="
