#!/bin/bash
# ============================================================
# wg-snat-lib.sh — WireGuard SNAT 管理共享库（v1.2）
# 能力层：输入校验 / nftables(map) / 状态(JSON) / 公网IP分配 / 恢复
#
# 架构要点：
#   - nft 规则模型：每接口一个命名 map + 单条 iifname 规则
#     snat 到 ip saddr map @snat_map_<iface>，增删映射 = 元素操作
#   - 状态单一来源：route_mappings_<iface>.json（used_ips.txt 已废除）
#   - 入站端口：命名 set（wg_ports），接口删除时可精确回收
#
# 路径可用环境变量覆盖（便于测试）：
#   WG_CONF_DIR / WG_PUBLIC_IP_FILE / WG_LOG_FILE
#   WG_NFT_TABLE / WG_FILTER_TABLE
# ============================================================

CONFIG_DIR="${WG_CONF_DIR:-/etc/wireguard}"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="${WG_PUBLIC_IP_FILE:-$CONFIG_DIR/public_ips.txt}"
LOG_FILE="${WG_LOG_FILE:-/var/log/wireguard-lite.log}"
NFTABLES_TABLE="${WG_NFT_TABLE:-wireguard-nat}"
WG_FILTER_TABLE="${WG_FILTER_TABLE:-wg-filter}"
WG_PORTS_SET="wg_ports"

# ---------- 日志 ----------
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# ---------- 依赖检查 ----------
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "错误: 需要命令 '$1'，但未找到，请先安装。" >&2
        return 1
    }
}

nft_available() { command -v nft >/dev/null 2>&1; }

# ---------- 输入校验 ----------
validate_ipv4() {
    local ip=$1 octet
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [ "$octet" -le 255 ] || return 1
    done
}

validate_subnet() {
    local ip mask
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || return 1
    ip="${1%/*}"
    mask="${1#*/}"
    validate_ipv4 "$ip" && [ "$mask" -ge 0 ] && [ "$mask" -le 32 ]
}

validate_iface_name() { [[ "$1" =~ ^[a-zA-Z0-9]+$ ]]; }

validate_count() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ]
}

# ---------- nftables：基础表 ----------
nft_init() {
    nft_available || { log "nft 命令不可用，跳过 nftables 初始化"; return 0; }

    # NAT 表 + postrouting 链
    if ! nft list table inet "$NFTABLES_TABLE" &>/dev/null; then
        nft add table inet "$NFTABLES_TABLE"
        nft add chain inet "$NFTABLES_TABLE" postrouting '{ type nat hook postrouting priority 100; }'
        log "创建nftables表: $NFTABLES_TABLE"
    fi

    # 入站端口放行表（命名 set，接口删除时可精确回收端口）
    if ! nft list table inet "$WG_FILTER_TABLE" &>/dev/null; then
        nft add table inet "$WG_FILTER_TABLE"
        nft add chain inet "$WG_FILTER_TABLE" input '{ type filter hook input priority 0; }'
        nft add set inet "$WG_FILTER_TABLE" "$WG_PORTS_SET" '{ type inet_service; }'
        nft add rule inet "$WG_FILTER_TABLE" input udp dport @"$WG_PORTS_SET" accept
        log "创建入站端口放行表: $WG_FILTER_TABLE"
    fi
}

# ---------- nftables：每接口 SNAT 映射 ----------
# 幂等：map/规则不存在才创建
nft_map_ensure() {
    local iface=$1
    if ! nft list map inet "$NFTABLES_TABLE" "snat_map_$iface" &>/dev/null; then
        nft add map inet "$NFTABLES_TABLE" "snat_map_$iface" '{ type ipv4_addr : ipv4_addr; }'
        nft add rule inet "$NFTABLES_TABLE" postrouting iifname \"$iface\" snat to ip saddr map "@snat_map_$iface"
        log "初始化接口 $iface 的SNAT映射"
    fi
}

nft_map_add() {
    local iface=$1 dip=$2 pub=$3
    nft_available || { log "nft 不可用，无法添加SNAT映射"; return 1; }
    nft_map_ensure "$iface" || return 1
    if nft add element inet "$NFTABLES_TABLE" "snat_map_$iface" "{ $dip : $pub }" 2>/dev/null; then
        log "添加SNAT映射: $dip => $pub (接口 $iface)"
        return 0
    fi
    log "错误: 无法添加SNAT映射: $dip => $pub (接口 $iface)"
    return 1
}

nft_map_del() {
    local iface=$1 dip=$2
    nft_available || return 1
    if nft delete element inet "$NFTABLES_TABLE" "snat_map_$iface" "{ $dip }" 2>/dev/null; then
        log "删除SNAT映射: $dip (接口 $iface)"
        return 0
    fi
    log "删除SNAT映射失败或不存在: $dip (接口 $iface)"
    return 1
}

# 删除接口时的完整清理：清空元素 -> 删除引用规则 -> 删除map
# （被规则引用的 map 无法直接 delete，实测为 Resource busy，须先删规则）
nft_map_remove() {
    local iface=$1
    nft_available || return 0
    nft flush map inet "$NFTABLES_TABLE" "snat_map_$iface" 2>/dev/null || true
    local handles h
    handles=$(nft -a list chain inet "$NFTABLES_TABLE" postrouting 2>/dev/null | \
              grep -E "iifname \"$iface\"" | grep handle | \
              awk '{for(i=1;i<=NF;i++) if ($i=="handle") print $(i+1)}')
    for h in $handles; do
        nft delete rule inet "$NFTABLES_TABLE" postrouting handle "$h" 2>/dev/null || true
    done
    nft delete map inet "$NFTABLES_TABLE" "snat_map_$iface" 2>/dev/null || true
    log "已清理接口 $iface 的SNAT映射与规则"
}

# 输出 map 元素，格式：dip : pub（一行一条）
nft_map_list() {
    local iface=$1
    nft list map inet "$NFTABLES_TABLE" "snat_map_$iface" 2>/dev/null | \
        grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ : [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true
}

# ---------- nftables：入站端口 ----------
nft_port_add() {
    local port=$1
    nft_available || return 0
    nft_init
    if nft add element inet "$WG_FILTER_TABLE" "$WG_PORTS_SET" "{ $port }" 2>/dev/null; then
        log "放行UDP端口 $port"
        return 0
    fi
    log "错误: 无法放行UDP端口 $port"
    return 1
}

nft_port_del() {
    local port=$1
    nft_available || return 0
    if nft delete element inet "$WG_FILTER_TABLE" "$WG_PORTS_SET" "{ $port }" 2>/dev/null; then
        log "回收UDP端口 $port"
        return 0
    fi
    log "回收端口 $port 失败或不存在"
    return 1
}

# ---------- 状态：路由映射 JSON（唯一权威） ----------
get_route_mapping() { echo "$CONFIG_DIR/route_mappings_$1.json"; }

mapping_write() {
    local iface=$1 content=$2
    local f tmp
    f=$(get_route_mapping "$iface")
    mkdir -p "$CONFIG_DIR"
    tmp=$(mktemp "$CONFIG_DIR/.route_tmp.XXXXXX")
    printf '%s\n' "$content" > "$tmp"
    mv "$tmp" "$f"
    chmod 600 "$f"
}

mapping_add() {
    local iface=$1 dip=$2 pub=$3
    local f tmp
    f=$(get_route_mapping "$iface")
    [ -f "$f" ] || echo "{}" > "$f"
    tmp=$(mktemp "$CONFIG_DIR/.route_tmp.XXXXXX")
    if jq --arg dip "$dip" --arg pub "$pub" '. + { ($dip): $pub }' "$f" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$f"
        chmod 600 "$f"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

mapping_del() {
    local iface=$1 dip=$2
    local f tmp
    f=$(get_route_mapping "$iface")
    [ -f "$f" ] || return 0
    tmp=$(mktemp "$CONFIG_DIR/.route_tmp.XXXXXX")
    if jq --arg k "$dip" 'del(.[$k])' "$f" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$f"
        chmod 600 "$f"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

mapping_clear() {
    mapping_write "$1" "{}"
}

# 输出映射记录，格式：dip pub（一行一条）
mapping_get() {
    local f
    f=$(get_route_mapping "$1")
    [ -f "$f" ] || return 0
    jq -r 'to_entries[] | "\(.key) \(.value)"' "$f" 2>/dev/null || true
}

mapping_count() {
    local f
    f=$(get_route_mapping "$1")
    [ -f "$f" ] || { echo 0; return; }
    jq 'length' "$f" 2>/dev/null || echo 0
}

# ---------- 公网 IP 分配（从 JSON 派生已用 IP，无 used_ips.txt） ----------
allocated_public_ips() {
    local f ip
    shopt -s nullglob
    for f in "$CONFIG_DIR"/route_mappings_*.json; do
        [ -f "$f" ] || continue
        while IFS= read -r ip; do
            [ -n "$ip" ] && printf '%s\n' "$ip"
        done < <(jq -r '.[] // empty' "$f" 2>/dev/null)
    done
    shopt -u nullglob
}

# public_ips.txt 中未分配且非保留（第一行）的 IP
available_public_ips() {
    local first
    first=$(head -n 1 "$PUBLIC_IP_FILE" 2>/dev/null || echo "")
    if [ -n "$first" ]; then
        comm -23 <(grep -v "^$first$" "$PUBLIC_IP_FILE" 2>/dev/null | sort -u) <(allocated_public_ips | sort -u)
    else
        comm -23 <(sort -u "$PUBLIC_IP_FILE" 2>/dev/null) <(allocated_public_ips | sort -u)
    fi
}

allocate_public_ips() {
    local count=$1
    local avail=() first
    mapfile -t avail < <(available_public_ips | sed '/^$/d')
    if [ ${#avail[@]} -lt "$count" ]; then
        echo "错误: 公网IP不足（需要 $count，剩余 ${#avail[@]}）" >&2
        first=$(head -n 1 "$PUBLIC_IP_FILE" 2>/dev/null || echo "")
        [ -n "$first" ] && echo "注意: 第一个公网IP $first 被保留，不分配给下游设备" >&2
        return 1
    fi
    mapfile -t ips < <(shuf -e "${avail[@]}" -n "$count")
    printf '%s\n' "${ips[@]}"
}

# ---------- 公网 IP 自动检测 ----------
detect_public_ips() {
    echo "正在自动检测公网IP..."
    log "开始检测公网IP"
    local ip a b c d private
    local public_ips=()
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        IFS=. read -r a b c d <<< "$ip"
        private=false
        [[ $a -eq 10 ]] && private=true
        [[ $a -eq 172 && $b -ge 16 && $b -le 31 ]] && private=true
        [[ $a -eq 192 && $b -eq 168 ]] && private=true
        [[ $a -eq 127 ]] && private=true
        [[ $a -eq 169 && $b -eq 254 ]] && private=true
        if ! $private; then
            public_ips+=("$ip")
        fi
    done < <(ip -4 addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
    if [ ${#public_ips[@]} -eq 0 ]; then
        log "尝试通过metadata获取云厂商公网IP"
        cloud_ip=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 || true)
        [ -n "$cloud_ip" ] && public_ips+=("$cloud_ip")
    fi
    if [ ${#public_ips[@]} -gt 0 ]; then
        printf "%s\n" "${public_ips[@]}" > "$PUBLIC_IP_FILE"
        echo "检测到公网IP：${public_ips[*]}"
        log "公网IP已保存"
    else
        echo "错误: 未检测到公网IP，请手动创建 $PUBLIC_IP_FILE" >&2
        log "公网IP检测失败"
        exit 1
    fi
}

# ---------- 接口 ----------
list_interfaces() {
    local f name
    shopt -s nullglob
    for f in "$CONFIG_DIR"/*.conf; do
        [ -f "$f" ] || continue
        name=$(basename "$f" .conf)
        [ "$name" = "wg-snat-restore" ] && continue
        echo "$name"
    done
    shopt -u nullglob
}

# ---------- 初始化 ----------
init_resources() {
    mkdir -p "$CONFIG_DIR" "$CLIENT_DIR"
    touch "$LOG_FILE"
    [ -f "$PUBLIC_IP_FILE" ] || detect_public_ips
    local iface_conf iface
    shopt -s nullglob
    for iface_conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$iface_conf" ] || continue
        iface=$(basename "$iface_conf" .conf)
        [ -f "$CONFIG_DIR/route_mappings_${iface}.json" ] || echo "{}" > "$CONFIG_DIR/route_mappings_${iface}.json"
    done
    shopt -u nullglob
    nft_init
}

# ---------- 规则恢复（从 JSON 重建，幂等） ----------
restore_wg_ports() {
    nft_available || return 0
    local conf iface port
    shopt -s nullglob
    for conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$conf" ] || continue
        iface=$(basename "$conf" .conf)
        [ "$iface" = "wg-snat-restore" ] && continue
        port=$(sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$conf" | head -n 1)
        [ -n "$port" ] && nft add element inet "$WG_FILTER_TABLE" "$WG_PORTS_SET" "{ $port }" 2>/dev/null || true
    done
    shopt -u nullglob
}

restore_nat_rules() {
    nft_init
    nft_available || { log "nft 不可用，跳过恢复"; return 0; }
    local f iface dip pub
    shopt -s nullglob
    for f in "$CONFIG_DIR"/route_mappings_*.json; do
        [ -f "$f" ] || continue
        iface=$(basename "$f" | sed 's/route_mappings_//; s/\.json//')
        nft_map_ensure "$iface"
        while IFS=' ' read -r dip pub; do
            [ -n "$dip" ] && [ -n "$pub" ] && \
                nft add element inet "$NFTABLES_TABLE" "snat_map_$iface" "{ $dip : $pub }" 2>/dev/null || true
        done < <(mapping_get "$iface")
    done
    shopt -u nullglob
    restore_wg_ports
    log "SNAT规则恢复完成"
}
