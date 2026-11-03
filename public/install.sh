#!/bin/sh
set -eu
umask 077
REPO=cloverstd/fail2ban-mate
CONFIG=/etc/fail2ban-mate/config.json
BIN=/usr/local/bin/fail2ban-mate-client
SERVER=
ENROLLMENT=
VERSION=
ACTION=install
die() { printf '%s\n' "错误：$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --server|--enrollment|--version) [ "$#" -ge 2 ] || die "缺少 $1 参数"; case "$1" in --server) SERVER=$2;; --enrollment) ENROLLMENT=$2;; --version) VERSION=$2;; esac; shift 2;;
    --upgrade) ACTION=upgrade; shift;;
    --uninstall) ACTION=uninstall; shift;;
    *) die "未知参数 $1";;
  esac
done
[ "$(id -u)" -eq 0 ] || die '请通过 sudo 或 root 执行'
[ "$(uname -s)" = Linux ] || die '仅支持 Linux'
command -v systemctl >/dev/null 2>&1 || die '需要 systemd'
[ -d /run/systemd/system ] || die 'systemd 必须正在运行'
if [ "$ACTION" = uninstall ]; then
  systemctl stop fail2ban-mate.service 2>/dev/null || true
  if [ -x "$BIN" ] && [ -f "$CONFIG" ]; then "$BIN" cleanup --config "$CONFIG" || die '无法清理本项目的白名单条目，已保留配置和客户端，请修复 fail2ban 后重试'; fi
  systemctl disable --now fail2ban-mate.service fail2ban-mate-geo.timer 2>/dev/null || true
  rm -f /etc/systemd/system/fail2ban-mate.service /etc/systemd/system/fail2ban-mate-geo.service /etc/systemd/system/fail2ban-mate-geo.timer "$BIN"
  systemctl daemon-reload
  printf '%s\n' '客户端已卸载，fail2ban、原有 jail 配置及 /etc/fail2ban-mate、/var/lib/fail2ban-mate 已保留。'
  exit 0
fi
if [ "$ACTION" = install ]; then
  [ -n "$SERVER" ] || die '需要 --server https://your-worker.example'
  case "$SERVER" in https://*) ;; *) die '控制端必须使用 HTTPS';; esac
  [ -n "$ENROLLMENT" ] || [ -f "$CONFIG" ] || die '首次安装需要 --enrollment'
else
  [ -f "$CONFIG" ] || die '尚未安装，请先在后台创建节点'
fi
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die '仅支持 amd64 / arm64';; esac
if ! command -v fail2ban-client >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y fail2ban ca-certificates curl
  elif command -v dnf >/dev/null 2>&1; then
    if ! dnf install -y fail2ban ca-certificates curl; then
      dnf install -y epel-release || die '请先为此发行版启用 EPEL，再安装 fail2ban'
      dnf install -y fail2ban ca-certificates curl
    fi
  elif command -v yum >/dev/null 2>&1; then
    yum install -y epel-release || true
    yum install -y fail2ban ca-certificates curl
  else die '无法识别包管理器，请手动安装 fail2ban 后重试'; fi
fi
systemctl enable --now fail2ban.service || die 'fail2ban 无法启动，请先检查 jail 配置和日志'
for TOOL in curl tar sha256sum; do command -v "$TOOL" >/dev/null 2>&1 || die "缺少 $TOOL"; done
TMP=$(mktemp -d)
WAS_RUNNING=no
REPLACED=no
cleanup() {
  result=$?
  if [ "$result" -ne 0 ] && [ "$REPLACED" = yes ]; then
    if [ -f "$TMP/previous" ]; then install -m 0755 "$TMP/previous" "$BIN"; fi
    if [ "$WAS_RUNNING" = yes ]; then systemctl start fail2ban-mate.service || true; fi
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
download() { curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$1" -o "$2"; }
if [ -z "$VERSION" ]; then
  RELEASE_URL=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
  VERSION=${RELEASE_URL##*/}
fi
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die '无法找到有效发行版本';; esac
case "$VERSION" in *[!A-Za-z0-9._-]*) die '无效版本号';; esac
ARCHIVE=fail2ban-mate-client_linux_$ARCH.tar.gz
BASE=https://github.com/$REPO/releases/download/$VERSION
download "$BASE/$ARCHIVE" "$TMP/$ARCHIVE"
download "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"
(cd "$TMP" && awk -v archive="$ARCHIVE" '$2 == archive {print}' SHA256SUMS > CHECKSUM && [ -s CHECKSUM ] && sha256sum -c CHECKSUM) || die '二进制校验失败'
tar -xzf "$TMP/$ARCHIVE" -C "$TMP" fail2ban-mate-client
install -d -m 0700 /etc/fail2ban-mate /var/lib/fail2ban-mate
if [ -f "$BIN" ]; then cp "$BIN" "$TMP/previous"; fi
if systemctl is-active --quiet fail2ban-mate.service; then WAS_RUNNING=yes; systemctl stop fail2ban-mate.service; fi
install -m 0755 "$TMP/fail2ban-mate-client" "$BIN.new"
mv "$BIN.new" "$BIN"
REPLACED=yes
if [ -n "$ENROLLMENT" ]; then "$BIN" enroll --server "$SERVER" --enrollment "$ENROLLMENT" --config "$CONFIG"; fi
[ -f "$CONFIG" ] || die '客户端配置不存在'
chmod 0600 "$CONFIG"
cat > /etc/systemd/system/fail2ban-mate.service <<'UNIT'
[Unit]
Description=Fail2ban Mate node client
Wants=network-online.target
After=network-online.target fail2ban.service
[Service]
Type=simple
ExecStart=/usr/local/bin/fail2ban-mate-client run --config /etc/fail2ban-mate/config.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/fail2ban-mate /run/fail2ban
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/fail2ban-mate-geo.service <<'UNIT'
[Unit]
Description=Update DB-IP City Lite database
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/fail2ban-mate-client geo-update --path /var/lib/fail2ban-mate/city.mmdb
UMask=0077
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/fail2ban-mate
PrivateTmp=true
UNIT
cat > /etc/systemd/system/fail2ban-mate-geo.timer <<'UNIT'
[Unit]
Description=Monthly DB-IP City Lite update
[Timer]
OnCalendar=monthly
RandomizedDelaySec=12h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
if [ ! -f /var/lib/fail2ban-mate/city.mmdb ]; then
  "$BIN" geo-update --path /var/lib/fail2ban-mate/city.mmdb || printf '%s\n' '定位库下载失败，客户端仍可工作；稍后执行 systemctl start fail2ban-mate-geo.service 重试。' >&2
fi
systemctl daemon-reload
systemctl enable --now fail2ban-mate.service fail2ban-mate-geo.timer
REPLACED=no
printf '%s\n' "Fail2ban Mate $VERSION 已安装。查看日志：journalctl -u fail2ban-mate -f"
printf '%s\n' '若节点没有 service，请自行在 /etc/fail2ban/jail.d/ 启用所需 jail。'
