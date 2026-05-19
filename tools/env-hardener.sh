#!/usr/bin/env bash
# CIS Benchmark Linux hardening and audit script
# Maps findings to CIS Benchmark controls and exports Cataam-importable JSON
# Usage: sudo ./env-hardener.sh [--level 1|2] [--dry-run] [--fix] [--json FILE] [--report FILE]

set -euo pipefail

SCRIPT_VERSION="1.3.0"
CIS_LEVEL=1
DRY_RUN=false
FIX_MODE=false
JSON_OUTPUT=""
REPORT_OUTPUT=""
PASS=0
FAIL=0
WARN=0
declare -a FINDINGS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

usage() {
  cat <<EOF
Usage: sudo $0 [OPTIONS]
  --level 1|2     CIS Benchmark level to apply (default: 1)
  --dry-run       Audit only, no changes
  --fix           Apply remediations automatically
  --json FILE     Write Cataam-importable JSON findings to FILE
  --report FILE   Write human-readable report to FILE
  -h, --help      Show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --level)   CIS_LEVEL="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --fix)     FIX_MODE=true; shift ;;
    --json)    JSON_OUTPUT="$2"; shift 2 ;;
    --report)  REPORT_OUTPUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[ERROR]${NC} This script must be run as root." >&2
  exit 1
fi

log() {
  local level=$1 control=$2 title=$3 status=$4 detail=${5:-""}
  local color=$NC
  case $status in
    PASS) color=$GREEN; ((PASS++)) ;;
    FAIL) color=$RED;  ((FAIL++)) ;;
    WARN) color=$YELLOW; ((WARN++)) ;;
  esac
  echo -e "${color}[${status}]${NC} [${control}] ${title}"
  [[ -n $detail ]] && echo -e "       ${detail}"

  local escaped_detail
  escaped_detail=$(echo "$detail" | sed 's/"/\\"/g')
  FINDINGS+=("{\"control\":\"${control}\",\"level\":${CIS_LEVEL},\"title\":\"${title}\",\"status\":\"${status}\",\"detail\":\"${escaped_detail}\",\"framework\":\"CIS Benchmark Linux v3.0\"}")
}

fix_if_enabled() {
  if $FIX_MODE && ! $DRY_RUN; then
    eval "$1" && echo -e "       ${BLUE}[FIXED]${NC} $2"
  fi
}

echo "========================================================"
echo " Cataam CIS Benchmark Linux Hardening Script v${SCRIPT_VERSION}"
echo " Level: ${CIS_LEVEL} | Mode: $(${DRY_RUN} && echo 'Audit' || (${FIX_MODE} && echo 'Fix' || echo 'Audit'))"
echo " Host: $(hostname) | Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================================"

# ── Section 1: Filesystem Configuration ──────────────────────────────────────

echo -e "\n${BLUE}=== Section 1: Filesystem Configuration ===${NC}"

# 1.1.1 Disable unused filesystems
for fs in cramfs squashfs udf freevxfs jffs2 hfs hfsplus; do
  if lsmod | grep -q "^${fs}" 2>/dev/null; then
    log 1 "1.1.1.${fs}" "Ensure ${fs} filesystem is disabled" "FAIL" "Module ${fs} is loaded"
    fix_if_enabled "echo 'install ${fs} /bin/true' >> /etc/modprobe.d/disable-filesystems.conf && rmmod ${fs} 2>/dev/null || true" "Added modprobe disable rule for ${fs}"
  else
    log 1 "1.1.1.${fs}" "Ensure ${fs} filesystem is disabled" "PASS"
  fi
done

# 1.1.2 /tmp configuration
if mount | grep -q ' /tmp '; then
  TMP_OPTIONS=$(findmnt -n /tmp -o OPTIONS 2>/dev/null || echo "")
  for opt in nodev nosuid noexec; do
    if echo "$TMP_OPTIONS" | grep -q "$opt"; then
      log 1 "1.1.2" "Ensure /tmp is configured with ${opt}" "PASS"
    else
      log 1 "1.1.2" "Ensure /tmp is configured with ${opt}" "FAIL" "/tmp mount is missing '${opt}' option"
    fi
  done
else
  log 1 "1.1.2" "Ensure /tmp is a separate partition" "WARN" "/tmp is not a separate partition — consider adding tmpfs entry to /etc/fstab"
fi

# 1.1.3 Sticky bit on world-writable directories
STICKY_FAIL=$(find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | head -20)
if [[ -z "$STICKY_FAIL" ]]; then
  log 1 "1.1.3" "Ensure sticky bit is set on all world-writable directories" "PASS"
else
  log 1 "1.1.3" "Ensure sticky bit is set on all world-writable directories" "FAIL" "Directories missing sticky bit: ${STICKY_FAIL}"
  fix_if_enabled "find / -xdev -type d -perm -0002 -exec chmod +t {} \;" "Set sticky bit on world-writable directories"
fi

# ── Section 2: Services ───────────────────────────────────────────────────────

echo -e "\n${BLUE}=== Section 2: Services ===${NC}"

UNNECESSARY_SERVICES=(avahi-daemon cups isc-dhcp-server isc-dhcp-server6 slapd nfs-server rpcbind bind9 vsftpd apache2 dovecot smbd squid snmpd rsync nis)
for svc in "${UNNECESSARY_SERVICES[@]}"; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    log 1 "2.1" "Ensure ${svc} is not active" "FAIL" "Service ${svc} is running — disable if not required"
    fix_if_enabled "systemctl disable --now ${svc}" "Disabled ${svc}"
  else
    log 1 "2.1" "Ensure ${svc} is not active" "PASS"
  fi
done

# ── Section 3: Network Configuration ─────────────────────────────────────────

echo -e "\n${BLUE}=== Section 3: Network Configuration ===${NC}"

check_sysctl() {
  local control=$1 param=$2 expected=$3 description=$4
  local actual
  actual=$(sysctl -n "$param" 2>/dev/null || echo "not_found")
  if [[ "$actual" == "$expected" ]]; then
    log 1 "$control" "$description" "PASS"
  else
    log 1 "$control" "$description" "FAIL" "${param} = ${actual} (expected ${expected})"
    fix_if_enabled "sysctl -w ${param}=${expected} && echo '${param} = ${expected}' >> /etc/sysctl.d/99-cis-hardening.conf" "Set ${param}=${expected}"
  fi
}

check_sysctl "3.1.1" "net.ipv4.ip_forward"                    "0" "Ensure IP forwarding is disabled"
check_sysctl "3.1.2" "net.ipv4.conf.all.send_redirects"       "0" "Ensure packet redirect sending is disabled"
check_sysctl "3.2.1" "net.ipv4.conf.all.accept_source_route"  "0" "Ensure source routed packets are not accepted"
check_sysctl "3.2.2" "net.ipv4.conf.all.accept_redirects"     "0" "Ensure ICMP redirects are not accepted"
check_sysctl "3.2.3" "net.ipv4.conf.all.secure_redirects"     "0" "Ensure secure ICMP redirects are not accepted"
check_sysctl "3.2.4" "net.ipv4.conf.all.log_martians"         "1" "Ensure suspicious packets are logged"
check_sysctl "3.2.5" "net.ipv4.icmp_echo_ignore_broadcasts"   "1" "Ensure broadcast ICMP requests are ignored"
check_sysctl "3.2.6" "net.ipv4.icmp_ignore_bogus_error_responses" "1" "Ensure bogus ICMP responses are ignored"
check_sysctl "3.3.1" "net.ipv6.conf.all.disable_ipv6"         "1" "Ensure IPv6 is disabled (if not required)"
check_sysctl "3.3.2" "net.ipv4.tcp_syncookies"                "1" "Ensure TCP SYN cookies are enabled"

# ── Section 4: Access Control ─────────────────────────────────────────────────

echo -e "\n${BLUE}=== Section 4: Access Control ===${NC}"

# 4.1 Password policy
if command -v pwquality >/dev/null 2>&1 || [[ -f /etc/security/pwquality.conf ]]; then
  MINLEN=$(grep -E "^minlen" /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}')
  if [[ -n "$MINLEN" && "$MINLEN" -ge 14 ]]; then
    log 1 "4.1.1" "Ensure password minimum length is 14+" "PASS"
  else
    log 1 "4.1.1" "Ensure password minimum length is 14+" "FAIL" "minlen = ${MINLEN:-not set} (expected >= 14)"
  fi
else
  log 1 "4.1.1" "Ensure password minimum length is 14+" "WARN" "pam_pwquality not installed"
fi

# 4.2 UID 0 accounts
ROOT_ACCOUNTS=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$' || true)
if [[ -z "$ROOT_ACCOUNTS" ]]; then
  log 1 "4.2.1" "Ensure only root has UID 0" "PASS"
else
  log 1 "4.2.1" "Ensure only root has UID 0" "FAIL" "Additional UID 0 accounts: ${ROOT_ACCOUNTS}"
fi

# 4.3 No empty passwords
EMPTY_PASS=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "*") && $1 != "root" { print $1 }' /etc/shadow 2>/dev/null || true)
if [[ -z "$EMPTY_PASS" ]]; then
  log 1 "4.3.1" "Ensure no accounts have empty passwords" "PASS"
else
  log 1 "4.3.1" "Ensure no accounts have empty passwords" "FAIL" "Accounts with empty passwords: ${EMPTY_PASS}"
fi

# 4.4 Root login restricted to console
SECURETTY=$(cat /etc/securetty 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^console$' | grep -v '^tty[0-9]*$' || true)
if [[ -z "$SECURETTY" ]]; then
  log 1 "4.4.1" "Ensure root login is restricted to system console" "PASS"
else
  log 1 "4.4.1" "Ensure root login is restricted to system console" "WARN" "Non-console TTYs allowed for root: ${SECURETTY}"
fi

# ── Section 5: SSH Configuration ─────────────────────────────────────────────

echo -e "\n${BLUE}=== Section 5: SSH Configuration ===${NC}"

SSH_CONFIG="/etc/ssh/sshd_config"

check_ssh() {
  local control=$1 param=$2 expected=$3 description=$4
  if [[ ! -f "$SSH_CONFIG" ]]; then
    log 1 "$control" "$description" "WARN" "sshd_config not found"
    return
  fi
  local actual
  actual=$(grep -iE "^${param}\s" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' | head -1 || echo "")
  if [[ "${actual,,}" == "${expected,,}" ]]; then
    log 1 "$control" "$description" "PASS"
  else
    log 1 "$control" "$description" "FAIL" "${param} = '${actual:-not set}' (expected '${expected}')"
    fix_if_enabled "sed -i 's/^#*${param}.*/${param} ${expected}/' ${SSH_CONFIG} && systemctl reload sshd 2>/dev/null || true" "Set ${param} ${expected} in sshd_config"
  fi
}

check_ssh "5.1.1" "Protocol"            "2"   "Ensure SSH Protocol is 2"
check_ssh "5.1.2" "PermitRootLogin"     "no"  "Ensure SSH root login is disabled"
check_ssh "5.1.3" "PasswordAuthentication" "no" "Ensure SSH PasswordAuthentication is disabled"
check_ssh "5.1.4" "PermitEmptyPasswords" "no" "Ensure SSH PermitEmptyPasswords is disabled"
check_ssh "5.1.5" "X11Forwarding"       "no"  "Ensure SSH X11Forwarding is disabled"
check_ssh "5.1.6" "MaxAuthTries"        "4"   "Ensure SSH MaxAuthTries is 4 or less"
check_ssh "5.1.7" "AllowAgentForwarding" "no" "Ensure SSH AllowAgentForwarding is disabled"
check_ssh "5.1.8" "AllowTcpForwarding"  "no"  "Ensure SSH AllowTcpForwarding is disabled"
check_ssh "5.1.9" "LogLevel"            "INFO" "Ensure SSH LogLevel is INFO"

# ── Section 6: Logging and Auditing ──────────────────────────────────────────

echo -e "\n${BLUE}=== Section 6: Logging and Auditing ===${NC}"

if systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog 2>/dev/null; then
  log 1 "6.1.1" "Ensure rsyslog is active" "PASS"
else
  log 1 "6.1.1" "Ensure rsyslog is active" "FAIL" "rsyslog is not running"
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
  log 1 "6.2.1" "Ensure auditd is active" "PASS"
else
  log 1 "6.2.1" "Ensure auditd is active" "FAIL" "auditd is not running — required for CIS 6.2 compliance"
  fix_if_enabled "systemctl enable --now auditd" "Enabled auditd"
fi

if [[ -f /etc/audit/auditd.conf ]]; then
  MAX_LOG=$(grep -E "^max_log_file_action" /etc/audit/auditd.conf | awk -F= '{print $2}' | tr -d ' ')
  if [[ "${MAX_LOG,,}" == "keep_logs" || "${MAX_LOG,,}" == "rotate" ]]; then
    log 1 "6.2.2" "Ensure audit log storage is configured" "PASS"
  else
    log 1 "6.2.2" "Ensure audit log storage is configured" "FAIL" "max_log_file_action = '${MAX_LOG}' (expected keep_logs or rotate)"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + WARN))
echo ""
echo "========================================================"
echo " SUMMARY"
echo "  Total checks : ${TOTAL}"
echo -e "  ${GREEN}Passed${NC}        : ${PASS}"
echo -e "  ${RED}Failed${NC}        : ${FAIL}"
echo -e "  ${YELLOW}Warnings${NC}      : ${WARN}"
SCORE=$(( PASS * 100 / (PASS + FAIL + 1) ))
echo "  CIS Score     : ${SCORE}%"
echo "========================================================"

# ── Write report ──────────────────────────────────────────────────────────────

if [[ -n "$REPORT_OUTPUT" ]]; then
  {
    echo "CIS Benchmark Linux Audit Report — $(date -u)"
    echo "Host: $(hostname) | Level: ${CIS_LEVEL}"
    echo "Pass: ${PASS} | Fail: ${FAIL} | Warn: ${WARN} | Score: ${SCORE}%"
  } > "$REPORT_OUTPUT"
  echo "Report written to ${REPORT_OUTPUT}"
fi

# ── Write Cataam-importable JSON ──────────────────────────────────────────────

if [[ -n "$JSON_OUTPUT" ]]; then
  TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  HOSTNAME=$(hostname)
  {
    echo "{"
    echo "  \"cataam_import_version\": \"1.0\","
    echo "  \"tool\": \"env-hardener\","
    echo "  \"tool_version\": \"${SCRIPT_VERSION}\","
    echo "  \"framework\": \"CIS Benchmark Linux v3.0\","
    echo "  \"cis_level\": ${CIS_LEVEL},"
    echo "  \"host\": \"${HOSTNAME}\","
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"summary\": {\"total\": ${TOTAL}, \"pass\": ${PASS}, \"fail\": ${FAIL}, \"warn\": ${WARN}, \"score_pct\": ${SCORE}},"
    echo "  \"findings\": ["
    local_ifs="$IFS"; IFS=","
    local joined
    joined=$(printf '%s,' "${FINDINGS[@]}")
    joined="${joined%,}"
    echo "    ${joined}"
    IFS="$local_ifs"
    echo "  ]"
    echo "}"
  } > "$JSON_OUTPUT"
  echo "Cataam JSON written to ${JSON_OUTPUT}"
  echo "Import at: https://cataam.com/import"
fi
