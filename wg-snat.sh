#!/bin/bash
# ============================================================
# wg-snat.sh — WireGuard SNAT 管理（v1.2）
# 交互层：菜单 + 业务编排；能力实现见 wg-snat-lib.sh
#
# 用法：
#   wg-snat.sh            交互菜单
#   wg-snat.sh --restore  从 JSON 恢复 nftables 规则（供 systemd/cron 调用）
#   wg-snat.sh --version  版本
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/wg-snat-lib.sh"

# ========================
# 接口选择
# ========================
select_interface() {
    local interfaces=()
    mapfile -t interfaces < <(list_interfaces)
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo "没有可用的WireGuard接口，请先创建一个。" >&2
        return 1
    fi

    PS3="请选择接口: "
    select iface in "${interfaces[@]}" "返回主菜单"; do
        if [[ $REPLY -ge 1 && $REPLY -le ${#interfaces[@]} ]]; then
            selected_iface="${interfaces[$((REPLY-1))]}"
            break
        elif [[ $REPLY -eq $((${#interfaces[@]}+1)) ]]; then
            return 2
        else
            echo "无效的选择，请重新输入。" >&2
        fi
    done

    echo "$selected_iface"
    return 0
}

# ========================
# 公网 IP 剩余展示
# ========================
show_remaining_public_ips() {
    local first remaining=()
    first=$(head -n 1 "$PUBLIC_IP_FILE" 2>/dev/null || echo "")
    mapfile -t remaining < <(available_public_ips | sed '/^$/d')
    echo "剩余可用公网IP数量: ${#remaining[@]}"
    [ -n "$first" ] && echo "保留的公网IP: $first (不分配给下游设备)"
}

# ========================
# 接口管理
# ========================
start_interface() {
    local iface=$1
    if systemctl start "wg-quick@$iface" 2>/dev/null || wg-quick up "$iface" 2>/dev/null; then
        return 0
    fi
    return 1
}

restart_interface_completely() {
    local iface="$1"

    echo "正在完全重启接口 $iface..."

    if [ ! -f "$CONFIG_DIR/$iface.conf" ]; then
        echo "错误: 接口配置文件 $iface.conf 不存在" >&2
        return 1
    fi

    echo "停止接口 $iface..."
    systemctl stop "wg-quick@$iface" 2>/dev/null || true
    sleep 2

    ip link delete "$iface" 2>/dev/null || true
    sleep 1

    echo "检查配置文件格式..."
    if ! wg-quick strip "$iface" >/dev/null 2>&1; then
        echo "错误: 配置文件格式有问题，请检查 $CONFIG_DIR/$iface.conf" >&2
        return 1
    fi

    echo "启动接口 $iface..."
    if start_interface "$iface"; then
        echo "接口 $iface 已成功重启"
        log "接口 $iface 已成功重启"
        return 0
    else
        echo "错误: 接口 $iface 启动失败" >&2
        echo "请检查日志: journalctl -u wg-quick@$iface" >&2
        log "接口 $iface 启动失败"
        return 1
    fi
}

# ========================
# 核心功能：创建接口
# ========================
create_interface() {
    init_resources
    echo "正在创建WireGuard接口..."
    log "创建接口开始"

    local iface server_ip port server_private
    read -p "请输入接口名称（例如wg0, wg1）: " iface
    validate_iface_name "$iface" || {
        echo "错误: 接口名称只能包含字母和数字" >&2
        return 1
    }

    [ -f "$CONFIG_DIR/$iface.conf" ] && {
        echo "错误: 接口已存在" >&2
        return 1
    }

    read -p "请输入服务器私有IP地址（例如10.0.0.1）: " server_ip
    if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        validate_ipv4 "${server_ip%/*}" || {
            echo "错误: IP地址格式无效" >&2
            return 1
        }
    else
        echo "错误: IP地址格式无效" >&2
        return 1
    fi
    [[ "$server_ip" =~ /[0-9]+$ ]] || server_ip="$server_ip/24"

    port=$(shuf -i 51620-52000 -n 1)
    server_private=$(wg genkey 2>/dev/null || true)

    cat > "$CONFIG_DIR/$iface.conf" <<EOF
[Interface]
Address = $server_ip
PrivateKey = $server_private
ListenPort = $port
SaveConfig = false
EOF

    chmod 600 "$CONFIG_DIR/$iface.conf"

    echo "正在启动接口 $iface..."
    if start_interface "$iface"; then
        echo "接口 $iface 创建成功！"
        log "接口 $iface 创建成功"
        systemctl enable "wg-quick@$iface" >/dev/null 2>&1 || true
        mkdir -p "$CLIENT_DIR/$iface"
        [ -f "$(get_route_mapping "$iface")" ] || echo "{}" > "$(get_route_mapping "$iface")"
        nft_port_add "$port" >/dev/null 2>&1 || true
    else
        echo "错误: 接口启动失败" >&2
        echo "请检查日志: journalctl -u wg-quick@$iface" >&2
        rm -f "$CONFIG_DIR/$iface.conf"
        return 1
    fi
}

# ========================
# 核心功能：添加路由型客户端
# ========================
add_client() {
    echo "正在添加路由型客户端..."
    log "添加路由型客户端开始"

    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi

    [ -z "$iface" ] && {
        echo "错误: 未选择接口" >&2
        return 1
    }

    [ ! -f "$CONFIG_DIR/$iface.conf" ] && {
        echo "错误: 接口 $iface 不存在" >&2
        return 1
    }

    local client_name client_subnet
    read -p "客户端名称（例如office-router）: " client_name
    [[ "$client_name" =~ [/\\] ]] && {
        echo "错误: 名称包含非法字符" >&2
        return 1
    }

    read -p "请输入客户端需路由的子网（例如192.168.1.0/24）: " client_subnet
    validate_subnet "$client_subnet" || {
        echo "错误: 子网格式无效（示例：192.168.1.0/24）" >&2
        return 1
    }

    client_private=$(wg genkey 2>/dev/null || true)
    client_public=$(echo "$client_private" | wg pubkey 2>/dev/null || true)
    server_public=$(wg show "$iface" public-key 2>/dev/null || true)

    server_subnet=$(grep 'Address' "$CONFIG_DIR/$iface.conf" | awk -F= '{print $2}' | tr -d ' ')
    base_net=$(echo "$server_subnet" | cut -d'/' -f1 | sed 's/\.[0-9]*$//')

    used_ips=()
    # server address
    srv_addr=$(echo "$server_subnet" | cut -d'/' -f1)
    [ -n "$srv_addr" ] && used_ips+=("$srv_addr")
    # peers' AllowedIPs
    mapfile -t peer_allowed < <(grep 'AllowedIPs' "$CONFIG_DIR/$iface.conf" 2>/dev/null | awk -F= '{print $2}' | tr ',' '\n' | awk '{print $1}' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' 2>/dev/null || true)
    used_ips+=("${peer_allowed[@]}")

    for i in {2..254}; do
        candidate_ip="${base_net}.$i"
        if ! printf '%s\n' "${used_ips[@]}" | grep -q "^${candidate_ip}$"; then
            client_tunnel_ip="$candidate_ip"
            break
        fi
    done

    [ -z "$client_tunnel_ip" ] && {
        echo "错误: 找不到可用的隧道IP地址" >&2
        return 1
    }

    {
        echo -e "\n[Peer]"
        echo "PublicKey = $client_public"
        echo "AllowedIPs = $client_subnet, $client_tunnel_ip/32"
    } >> "$CONFIG_DIR/$iface.conf"

    mkdir -p "$CLIENT_DIR/$iface"
    client_file="$CLIENT_DIR/$iface/$client_name.conf"

    server_port=$(grep 'ListenPort' "$CONFIG_DIR/$iface.conf" | awk -F= '{print $2}' | tr -d ' ')
    server_public_ip=$(head -n 1 "$PUBLIC_IP_FILE")

    if [ -z "$server_public_ip" ]; then
        echo "错误: 未找到公网IP" >&2
        return 1
    fi

    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_tunnel_ip/24
Dns = 8.8.8.8, 1.1.1.1
[Peer]
PublicKey = $server_public
Endpoint = ${server_public_ip}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    command -v qrencode >/dev/null 2>&1 && qrencode -t ansiutf8 < "$client_file" || true
    chmod 600 "$client_file"

    wg syncconf "$iface" <(wg-quick strip "$iface") >/dev/null 2>&1 || true
    echo "路由型客户端添加成功！"
    echo "接口: $iface"
    echo "客户端子网: $client_subnet"
    echo "隧道端点IP: $client_tunnel_ip（仅用于建立连接）"
    echo "服务器公网端点: $server_public_ip:$server_port"
    log "接口 $iface 添加路由型客户端 $client_name"
}

# ========================
# 核心功能：添加下游设备（SNAT）
# ========================
add_downstream() {
    echo "正在添加下游设备（SNAT）..."
    log "添加下游设备开始"

    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi

    [ -z "$iface" ] && {
        echo "错误: 未选择接口" >&2
        return 1
    }

    [ ! -f "$CONFIG_DIR/$iface.conf" ] && {
        echo "错误: 接口 $iface 不存在" >&2
        return 1
    }

    local client_subnets=() subnet_choice client_subnet mask ip_count
    client_subnets=($(grep 'AllowedIPs' "$CONFIG_DIR/$iface.conf" 2>/dev/null | awk -F= '{print $2}' | tr ',' '\n' | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort -u))
    if [ ${#client_subnets[@]} -gt 0 ]; then
        echo "检测到以下客户端子网:"
        for i in "${!client_subnets[@]}"; do
            echo "$((i+1))). ${client_subnets[$i]}"
        done
        echo "$(( ${#client_subnets[@]} + 1 )). 输入新的子网"

        read -p "请选择子网 (1-${#client_subnets[@]}, 或输入新子网): " subnet_choice

        if [[ "$subnet_choice" =~ ^[0-9]+$ ]] && [ "$subnet_choice" -ge 1 ] && [ "$subnet_choice" -le ${#client_subnets[@]} ]; then
            client_subnet="${client_subnets[$((subnet_choice-1))]}"
            echo "已选择子网: $client_subnet"
        elif [[ "$subnet_choice" =~ ^[0-9]+$ ]] && [ "$subnet_choice" -eq $((${#client_subnets[@]} + 1)) ]; then
            read -p "请输入新的客户端子网（例如192.168.1.0/24）: " client_subnet
            validate_subnet "$client_subnet" || {
                echo "错误: 子网格式无效（示例：192.168.1.0/24）" >&2
                return 1
            }
        else
            read -p "请输入客户端子网（例如192.168.1.0/24）: " client_subnet
            validate_subnet "$client_subnet" || {
                echo "错误: 子网格式无效（示例：192.168.1.0/24）" >&2
                return 1
            }
        fi
    else
        read -p "请输入客户端子网（例如192.168.1.0/24）: " client_subnet
        validate_subnet "$client_subnet" || {
            echo "错误: 子网格式无效（示例：192.168.1.0/24）" >&2
            return 1
        }
    fi

    mask="${client_subnet#*/}"
    if [ "$mask" -ne 24 ]; then
        echo "错误: 下游设备支持到/24子网" >&2
        return 1
    fi

    read -p "需要分配的公网IP数量: " ip_count
    validate_count "$ip_count" || {
        echo "错误: 请输入有效数字（至少1）" >&2
        return 1
    }

    # 下游 IP：/24 中排除已用（JSON keys）
    local used=() base_ip candidate_ip
    mapfile -t used < <(jq -r 'keys[]' "$(get_route_mapping "$iface")" 2>/dev/null || true)
    base_ip=$(echo "$client_subnet" | awk -F'[./]' '{print $1"."$2"."$3"."}')

    local available_ips=()
    for i in {2..254}; do
        candidate_ip="${base_ip}$i"
        if ! printf '%s\n' "${used[@]}" | grep -q "^${candidate_ip}$"; then
            available_ips+=("$candidate_ip")
            if [ ${#available_ips[@]} -ge "$ip_count" ]; then
                break
            fi
        fi
    done

    if [ ${#available_ips[@]} -lt "$ip_count" ]; then
        echo "错误: 子网 $client_subnet 中可用的下游IP不足（需要 $ip_count，可用 ${#available_ips[@]}）" >&2
        return 1
    fi

    # 分配公网 IP（失败即中止，不再静默继续）
    local public_ips=()
    mapfile -t public_ips < <(allocate_public_ips "$ip_count") || {
        echo "错误: 无法分配公网IP" >&2
        return 1
    }
    if [ ${#public_ips[@]} -ne "$ip_count" ]; then
        echo "错误: 公网IP分配结果异常（拿到 ${#public_ips[@]} 个，需要 $ip_count）" >&2
        return 1
    fi

    # 添加映射：nft + JSON，逐条失败即中止
    local i dip pub failed=0
    for i in $(seq 0 $((ip_count-1))); do
        dip="${available_ips[$i]}"
        pub="${public_ips[$i]}"
        if ! nft_map_add "$iface" "$dip" "$pub"; then
            echo "警告: 无法添加SNAT映射: $dip => $pub" >&2
            failed=1
            continue
        fi
        if ! mapping_add "$iface" "$dip" "$pub"; then
            echo "警告: 无法写入映射记录: $dip => $pub" >&2
            nft_map_del "$iface" "$dip" >/dev/null 2>&1
            failed=1
        fi
    done

    # 重新加载接口配置（nft 映射即时生效，无需重启接口）
    if wg syncconf "$iface" <(wg-quick strip "$iface") 2>/dev/null; then
        log "接口 $iface 配置已重新加载"
    else
        echo "警告: 无法重新加载配置" >&2
        log "接口 $iface 配置重新加载失败"
    fi

    save_nftables_rules

    echo -e "\n验证配置:"
    local verified_count=0 failed_count=0 json_pub
    for i in $(seq 0 $((ip_count-1))); do
        dip="${available_ips[$i]}"
        pub="${public_ips[$i]}"

        if nft_map_list "$iface" | grep -q "^$dip : $pub$"; then
            echo "[✓] SNAT映射有效: $dip => $pub"
            verified_count=$((verified_count + 1))
        else
            echo "[×] SNAT映射缺失: $dip => $pub" >&2
            failed_count=$((failed_count + 1))
        fi

        json_pub=$(jq -r --arg k "$dip" '.[$k] // empty' "$(get_route_mapping "$iface")" 2>/dev/null)
        if [ "$json_pub" == "$pub" ]; then
            echo "[✓] 映射文件记录有效: $dip => $pub"
        else
            echo "[×] 映射文件记录缺失: $dip => $pub" >&2
            failed_count=$((failed_count + 1))
        fi
    done

    echo -e "\n验证结果: 成功 $verified_count, 失败 $failed_count"

    if [ "$failed_count" -eq 0 ]; then
        echo -e "\n下游设备添加成功！"
        echo "接口: $iface"
        echo "子网: $client_subnet"
        echo "分配的公网IP: ${public_ips[*]}"
        echo "分配的下游IP: ${available_ips[*]}"
        show_remaining_public_ips
        log "接口 $iface 添加下游设备到子网 $client_subnet"
    else
        echo -e "\n警告: 部分配置验证失败，请检查日志" >&2
        return 1
    fi
}

# ========================
# 核心功能：删除下游设备（SNAT）
# ========================
delete_downstream() {
    echo "正在删除下游设备（SNAT）..."
    log "删除下游设备开始"

    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi

    [ -z "$iface" ] && {
        echo "错误: 未选择接口" >&2
        return 1
    }

    local route_mapping dip public_ip
    route_mapping=$(get_route_mapping "$iface")
    [ -f "$route_mapping" ] || echo "{}" > "$route_mapping"

    read -p "输入下游设备私有IP（或输入 all 删除所有）: " downstream_ip

    if [ "$downstream_ip" = "all" ]; then
        echo "正在删除接口 $iface 的所有下游设备..."
        while IFS=' ' read -r dip public_ip; do
            [ -n "$dip" ] || continue
            nft_map_del "$iface" "$dip"
        done < <(mapping_get "$iface")
        mapping_clear "$iface"
        echo "[✓] 已删除所有下游设备"
        log "接口 $iface 所有下游设备已删除"
    else
        validate_ipv4 "$downstream_ip" || {
            echo "错误: 无效的IP地址" >&2
            return 1
        }
        public_ip=$(jq -r --arg k "$downstream_ip" '.[$k] // empty' "$route_mapping" 2>/dev/null || true)
        if [ -z "$public_ip" ]; then
            echo "错误: 未找到映射记录" >&2
            return 1
        fi

        nft_map_del "$iface" "$downstream_ip" || true
        mapping_del "$iface" "$downstream_ip" || true
        echo "[✓] 已删除下游设备 $downstream_ip"
        log "接口 $iface 下游设备 $downstream_ip 已删除"
    fi

    save_nftables_rules
    show_remaining_public_ips

    echo -e "\n最终验证:"
    local remaining
    remaining=$(mapping_count "$iface")
    if [ "$remaining" -eq 0 ]; then
        echo "[✓] 确认该接口所有SNAT映射已清理"
    else
        echo "[×] 该接口仍有 $remaining 条映射记录" >&2
    fi
}

# ========================
# 核心功能：删除接口
# ========================
delete_interface() {
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi

    [ -z "$iface" ] && {
        echo "错误: 未选择接口" >&2
        return 1
    }

    read -p "确认删除接口 $iface？(y/N) " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return

    # 清理 nft 映射/规则与入站端口
    nft_map_remove "$iface"
    local port
    port=$(sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$CONFIG_DIR/$iface.conf" 2>/dev/null | head -n 1)
    [ -n "$port" ] && nft_port_del "$port"

    rm -f "$(get_route_mapping "$iface")"

    systemctl stop "wg-quick@$iface" 2>/dev/null || true
    systemctl disable "wg-quick@$iface" 2>/dev/null || true

    rm -f "$CONFIG_DIR/$iface.conf"
    rm -rf "$CLIENT_DIR/$iface"

    echo "接口 $iface 已删除"
    log "接口 $iface 已删除"
}

# ========================
# 状态展示
# ========================
show_mappings() {
    echo "当前路由映射状态："
    local f iface count has_mappings=false
    shopt -s nullglob
    for f in "$CONFIG_DIR"/route_mappings_*.json; do
        [ -f "$f" ] || continue

        iface=$(basename "$f" | sed 's/route_mappings_//; s/\.json//')
        count=$(mapping_count "$iface")

        if [ "$count" -gt 0 ]; then
            has_mappings=true
            echo "接口: $iface"
            while IFS=' ' read -r dip pub; do
                [ -n "$dip" ] && echo "  $dip => $pub"
            done < <(mapping_get "$iface")
        fi
    done
    shopt -u nullglob

    if [ "$has_mappings" = false ]; then
        echo "无映射记录"
    fi

    echo -e "\n当前nftables SNAT映射："
    if nft_available && nft list table inet "$NFTABLES_TABLE" &>/dev/null; then
        local total=0 iface2 line
        shopt -s nullglob
        for f in "$CONFIG_DIR"/route_mappings_*.json; do
            [ -f "$f" ] || continue
            iface2=$(basename "$f" | sed 's/route_mappings_//; s/\.json//')
            while IFS= read -r line; do
                [ -n "$line" ] && {
                    echo "  [$iface2] $line"
                    total=$((total + 1))
                }
            done < <(nft_map_list "$iface2")
        done
        shopt -u nullglob
        [ "$total" -eq 0 ] && echo "无SNAT映射"
        echo "总计: $total 条SNAT映射"
    else
        echo "nftables表 $NFTABLES_TABLE 不存在"
    fi
}

show_interface_status() {
    echo "正在查询接口状态..."

    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi

    [ -z "$iface" ] && {
        echo "错误: 未选择接口" >&2
        return 1
    }

    if [ ! -f "$CONFIG_DIR/$iface.conf" ]; then
        echo "错误: 接口 $iface 不存在" >&2
        return 1
    fi

    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo "接口 $iface 当前未运行" >&2
        return 1
    fi

    echo -e "\n===== 接口 $iface 状态 ====="
    echo "1. 接口基本信息:"
    echo "   状态: $(ip link show $iface | grep -o "state [A-Z]*" | cut -d' ' -f2)"
    echo "   IP地址: $(ip addr show $iface | grep 'inet ' | awk '{print $2}')"
    echo "   MTU: $(ip link show $iface | grep -o "mtu [0-9]*" | cut -d' ' -f2)"

    echo -e "\n2. WireGuard配置信息:"
    wg show "$iface" | sed 's/^/   /' 2>/dev/null || true

    listen_port=$(wg show "$iface" 2>/dev/null | grep "listening port" | awk '{print $3}' || true)
    echo "   监听端口: $listen_port"

    peer_count=$(wg show "$iface" 2>/dev/null | grep -c "peer:" || true)
    echo "   对等端数量: $peer_count"

    local route_mapping
    route_mapping=$(get_route_mapping "$iface")
    if [ -f "$route_mapping" ]; then
        mapping_count=$(mapping_count "$iface")
        echo -e "\n3. 下游设备映射状态:"
        echo "   映射数量: $mapping_count"
        if [ "$mapping_count" -gt 0 ]; then
            while IFS=' ' read -r dip pub; do
                [ -n "$dip" ] && echo "   $dip => $pub"
            done < <(mapping_get "$iface")
        fi
    fi

    echo -e "\n4. NAT规则状态:"
    if nft_available && nft list table inet "$NFTABLES_TABLE" &>/dev/null; then
        local nft_count
        nft_count=$(mapping_count "$iface")
        echo "   SNAT映射数量: $nft_count"
    else
        echo "   nftables表未初始化"
    fi

    echo -e "\n5. 流量统计:"
    rx_bytes=$(ip -s link show $iface | awk '/RX:/{getline; print $1}' || echo 0)
    tx_bytes=$(ip -s link show $iface | awk '/TX:/{getline; print $1}' || echo 0)
    command -v numfmt >/dev/null 2>&1 && \
        echo "   接收流量: $(numfmt --to=iec $rx_bytes)" || echo "   接收流量: $rx_bytes"
    command -v numfmt >/dev/null 2>&1 && \
        echo "   发送流量: $(numfmt --to=iec $tx_bytes)" || echo "   发送流量: $tx_bytes"

    echo -e "\n6. 系统服务状态:"
    if systemctl is-active "wg-quick@$iface" >/dev/null 2>&1; then
        echo "   服务状态: 运行中"
        echo "   启动时间: $(systemctl show "wg-quick@$iface" --property=ActiveEnterTimestamp | cut -d= -f2)"
    else
        echo "   服务状态: 未运行"
    fi

    echo -e "\n==================================="
}

# ========================
# 重启接口
# ========================
restart_interface() {
    iface=$(select_interface)
    if [ $? -ne 0 ]; then
        return $?
    fi

    [ -z "$iface" ] && {
        echo "错误: 未选择接口" >&2
        return 1
    }

    restart_interface_completely "$iface"

    echo "恢复NAT规则..."
    restore_nat_rules

    echo "接口状态:"
    wg show "$iface" 2>/dev/null || true
}

# ========================
# nftables 诊断
# ========================
diagnose_nftables() {
    echo "===== nftables诊断信息 ====="

    if nft_available && nft list table inet "$NFTABLES_TABLE" &>/dev/null; then
        echo "[✓] nftables表 $NFTABLES_TABLE 存在"
        echo -e "\n当前表内容:"
        nft list table inet "$NFTABLES_TABLE"
        echo -e "\n入站端口放行表 $WG_FILTER_TABLE:"
        nft list table inet "$WG_FILTER_TABLE" 2>/dev/null || echo "表不存在"
    else
        echo "[×] nftables表 $NFTABLES_TABLE 不存在"
        echo "尝试重新初始化..."
        nft_init
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active nftables &>/dev/null; then
        echo "[✓] nftables服务运行中"
    else
        echo "[×] nftables服务未运行或 systemctl 不可用"
        if command -v systemctl >/dev/null 2>&1; then
            echo "尝试启动nftables服务..."
            systemctl start nftables 2>/dev/null || true
        fi
    fi

    echo "============================"
}

# ========================
# 紧急清理
# ========================
emergency_cleanup() {
    echo "===== 紧急清理所有SNAT规则 ====="
    read -p "确定要清理所有SNAT规则吗？这将删除所有NAT规则！(y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return

    local f iface
    shopt -s nullglob
    for f in "$CONFIG_DIR"/route_mappings_*.json; do
        [ -f "$f" ] || continue
        iface=$(basename "$f" | sed 's/route_mappings_//; s/\.json//')
        nft_map_remove "$iface"
        mapping_clear "$iface"
        echo "[✓] 已清理接口 $iface 的映射"
    done
    shopt -u nullglob

    echo "[✓] 紧急清理完成"
    show_remaining_public_ips
    log "紧急清理完成"
}

# ========================
# 规则快照（仅诊断用途，恢复始终从 JSON 重建）
# ========================
save_nftables_rules() {
    if nft_available; then
        mkdir -p /etc/nftables
        nft list ruleset > /etc/nftables/wireguard-nat.rules 2>/dev/null || true
        log "nftables规则快照已保存"
    fi
}

# ========================
# 持久化：恢复入口 + 单一 systemd oneshot
# ========================
install_persistence() {
    # 恢复入口（薄壳，逻辑唯一来源为 wg-snat-lib.sh）
    cat > /usr/local/bin/restore-wg-snat.sh <<'EOF'
#!/bin/bash
source /usr/local/bin/wg-snat-lib.sh
restore_nat_rules
EOF
    chmod +x /usr/local/bin/restore-wg-snat.sh

    # 若从非 /usr/local/bin 目录运行，将三件套安装到 /usr/local/bin
    if [ -f "$SCRIPT_DIR/wg-snat-lib.sh" ] && [ "$SCRIPT_DIR" != "/usr/local/bin" ]; then
        install -m 755 "$SCRIPT_DIR/wg-snat-lib.sh" /usr/local/bin/wg-snat-lib.sh
        install -m 755 "$SCRIPT_DIR/wg-snat.sh" /usr/local/bin/wg-snat.sh
        log "已安装 wg-snat 脚本到 /usr/local/bin"
    fi

    # 迁移：移除旧机制（cron + 旧 service），统一到单一 oneshot
    (crontab -l 2>/dev/null || true) | grep -v "restore-wg-snat.sh" | crontab - 2>/dev/null || true
    systemctl disable nftables-wireguard.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/nftables-wireguard.service

    cat > /etc/systemd/system/wg-snat-restore.service <<'EOF'
[Unit]
Description=Restore WireGuard SNAT Rules
After=network.target nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/restore-wg-snat.sh

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable wg-snat-restore.service >/dev/null 2>&1 || true
    log "安装NAT规则恢复服务"
}

# ========================
# 依赖安装
# ========================
install_dependencies() {
    echo "正在安装依赖..."
    log "开始安装依赖"
    export DEBIAN_FRONTEND=noninteractive

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        echo "错误: 无法确定操作系统类型" >&2
        log "无法确定操作系统类型"
        exit 1
    fi

    apt-get update >/dev/null 2>&1 || {
        echo "错误: 无法更新包列表" >&2
        log "更新包列表失败"
        exit 1
    }

    apt-get install -y --no-install-recommends \
        nftables wireguard-tools \
        sipcalc qrencode curl jq cron iftop >/dev/null 2>&1 || true

    local missing=() pkg
    for pkg in wireguard-tools nftables sipcalc qrencode curl jq cron iftop; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo "错误: 以下依赖安装失败或缺失: ${missing[*]}" >&2
        log "依赖安装失败: ${missing[*]}"
        # 继续但提示用户检查
    fi

    systemctl enable --now nftables >/dev/null 2>&1 || true
    systemctl enable --now cron >/dev/null 2>&1 || true

    # 配置内核参数
    local sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    local param
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1 || true

    install_persistence

    echo "系统配置完成！"
    log "依赖安装完成"
}

# ========================
# 静默完全卸载
# ========================
silent_uninstall() {
    echo "正在执行静默完全卸载..."
    log "开始静默卸载"

    # 停止所有WireGuard接口
    local iface_conf iface
    shopt -s nullglob
    for iface_conf in "$CONFIG_DIR"/*.conf; do
        [ -f "$iface_conf" ] || continue
        iface=$(basename "$iface_conf" .conf)
        if [[ "$iface" == "wg-snat-restore" ]]; then
            continue
        fi

        systemctl stop "wg-quick@$iface" 2>/dev/null || true
        systemctl disable "wg-quick@$iface" 2>/dev/null || true
        ip link delete "$iface" 2>/dev/null || true
    done
    shopt -u nullglob

    # 删除系统服务
    systemctl stop wg-snat-restore 2>/dev/null || true
    systemctl disable wg-snat-restore 2>/dev/null || true
    rm -f /etc/systemd/system/wg-snat-restore.service
    rm -f /etc/systemd/system/nftables-wireguard.service
    systemctl daemon-reload 2>/dev/null || true

    # 删除定时任务
    (crontab -l 2>/dev/null || true) | grep -v "restore-wg-snat.sh" | crontab - 2>/dev/null || true

    # 删除脚本文件
    rm -f /usr/local/bin/restore-wg-snat.sh /usr/local/bin/wg-snat-lib.sh /usr/local/bin/wg-snat.sh

    # 清理nftables表
    if nft_available; then
        nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
        nft delete table inet "$WG_FILTER_TABLE" 2>/dev/null || true
    fi
    rm -f /etc/nftables/wireguard-nat.rules

    # 删除配置文件和客户端目录
    rm -rf "$CONFIG_DIR"

    # 删除日志文件
    rm -f "$LOG_FILE"

    # 尝试移除依赖包（静默）
    if command -v apt-get >/dev/null 2>&1; then
        apt-get remove -y --purge wireguard-tools nftables sipcalc qrencode jq iftop 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
    fi

    echo "静默卸载完成！"
    log "静默卸载完成"
}

# ========================
# 主菜单
# ========================
main_menu() {
    while true; do
        echo -e "\n===== WireGuard管理菜单 ====="
        echo "1. 安装依赖"
        echo "2. 创建WireGuard接口"
        echo "3. 添加路由型客户端"
        echo "4. 添加下游设备（SNAT）"
        echo "5. 删除下游设备（SNAT）"
        echo "6. 显示当前映射"
        echo "7. 显示接口状态"
        echo "8. 重启接口"
        echo "9. 删除接口"
        echo "10. nftables诊断"
        echo "11. 紧急清理SNAT规则"
        echo "12. 静默完全卸载"
        echo "13. 退出"
        echo "=============================="

        read -p "请选择操作 (1-13): " choice

        case $choice in
            1) install_dependencies ;;
            2) create_interface ;;
            3) add_client ;;
            4) add_downstream ;;
            5) delete_downstream ;;
            6) show_mappings ;;
            7) show_interface_status ;;
            8) restart_interface ;;
            9) delete_interface ;;
            10) diagnose_nftables ;;
            11) emergency_cleanup ;;
            12) silent_uninstall ;;
            13) echo "再见！"; exit 0 ;;
            *) echo "无效选择，请重新输入" >&2 ;;
        esac
    done
}

# ========================
# 入口
# ========================
main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "错误: 需要root权限运行此脚本" >&2
        exit 1
    fi

    case "${1:-}" in
        --restore)
            mkdir -p "$CONFIG_DIR" "$CLIENT_DIR"
            restore_nat_rules
            ;;
        --version)
            echo "wg-snat v1.2.0"
            ;;
        "")
            init_resources
            main_menu
            ;;
        *)
            echo "用法: $0 [--restore|--version]" >&2
            exit 1
            ;;
    esac
}

main "$@"
