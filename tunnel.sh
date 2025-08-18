#!/usr/bin/env bash
# =============================================================================
# IPTables Port Forwarding Manager (Cross-Distro)
# -----------------------------------------------------------------------------
# Author : Peyman (https://github.com/Ptechgithub)
# License: MIT
# =============================================================================

set -Eeuo pipefail

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------- Constants ----------
readonly PF_COMMENT="PF_SCRIPT"      # tag for single/multi rules
readonly ALL_COMMENT="PF_SCRIPT_ALL" # tag for ALL mode rules
RULES_DIR="/etc/iptables"
RULES_V4="$RULES_DIR/rules.v4"
readonly SSHD_CFG="/etc/ssh/sshd_config"
readonly SYSCTL_CONF="/etc/sysctl.d/30-ip_forward.conf"

# ---------- Logging ----------
info() { printf "%b%s%b\n" "$GREEN" "$*" "$NC"; }
warn() { printf "%b%s%b\n" "$YELLOW" "$*" "$NC"; }
err() { printf "%b%s%b\n" "$RED" "$*" "$NC" >&2; }
note() { printf "%b%s%b\n" "$CYAN" "$*" "$NC"; }

# ---------- Root check ----------
if [[ $(id -u) -ne 0 ]]; then
	err "Run as root."
	exit 1
fi

# ---------- Select iptables binary ----------
if command -v iptables >/dev/null 2>&1; then
	IPT="iptables"
elif command -v iptables-legacy >/dev/null 2>&1; then
	IPT="iptables-legacy"
else
	err "Neither iptables nor iptables-legacy found."
	exit 1
fi
IPT_RUN() { "$IPT" -w 5 "$@"; } # wait lock to avoid races

# ---------- Distro detection & persistence install ----------
detect_distro() {
	if [[ -f /etc/os-release ]]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		echo "$ID"
	else
		uname -s
	fi
}

install_persistent() {
	local distro
	distro=$(detect_distro)

	case "$distro" in
	ubuntu | debian)
		if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
			info "Installing iptables-persistent..."
			export DEBIAN_FRONTEND=noninteractive
			apt-get update -qq
			apt-get install -y -qq iptables-persistent >/dev/null
		fi
		RULES_DIR="/etc/iptables"
		RULES_V4="$RULES_DIR/rules.v4"
		;;
	centos | rhel | fedora)
		if ! rpm -q iptables-services >/dev/null 2>&1; then
			info "Installing iptables-services..."
			yum install -y -q iptables-services >/dev/null || dnf install -y -q iptables-services >/dev/null
		fi
		RULES_DIR="/etc/sysconfig"
		RULES_V4="$RULES_DIR/iptables"
		;;
	arch)
		if ! pacman -Qi iptables >/dev/null 2>&1; then
			info "Installing iptables..."
			pacman -Sy --noconfirm iptables >/dev/null
		fi
		RULES_DIR="/etc/iptables"
		RULES_V4="$RULES_DIR/iptables.rules"
		;;
	alpine)
		if ! apk info | grep -q '^iptables$'; then
			info "Installing iptables..."
			apk add --no-progress iptables >/dev/null
		fi
		RULES_DIR="/etc/iptables"
		RULES_V4="$RULES_DIR/rules-save"
		;;
	*)
		warn "Unknown distro ($distro). Rules might not persist after reboot."
		RULES_DIR="/etc/iptables"
		RULES_V4="$RULES_DIR/rules.v4"
		;;
	esac

	mkdir -p "$RULES_DIR"
}
install_persistent

# ---------- Enable IPv4 forwarding (idempotent) ----------
if [[ ! -f "$SYSCTL_CONF" ]] || ! grep -q '^net.ipv4.ip_forward=1' "$SYSCTL_CONF"; then
	printf "net.ipv4.ip_forward=1\n" >"$SYSCTL_CONF"
	sysctl --system >/dev/null 2>&1 || true
fi

# ---------- Detect SSH port (defaults to 22) ----------
SSH_PORT="$(awk '
  /^[[:space:]]*Port[[:space:]]+/ {p=$2}
  END { if(p) print p; else print 22 }
' "$SSHD_CFG" 2>/dev/null || printf "22")"

# ---------- Detect egress interface (override with IFACE=ens3) ----------
IFACE="${IFACE:-}"
if [[ -z "$IFACE" ]]; then
	IFACE="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')" || true
fi
IFACE="${IFACE:-eth0}"

# ---------- Validators ----------
is_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((1 <= $1 && $1 <= 65535)); }
is_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

# ---------- Save/Restore ----------
save_iptables() {
	iptables-save >"$RULES_V4"
	info "Rules saved to $RULES_V4."
}
restore_iptables() { [[ -f "$RULES_V4" ]] && iptables-restore <"$RULES_V4"; }

# ---------- State helpers ----------
current_all_target() {
	# Returns the DNAT target for ALL mode (first match), or empty if inactive.
	"$IPT" -t nat -S PREROUTING 2>/dev/null | awk -v tag="$ALL_COMMENT" '
    $0 ~ ("--comment " tag) && $0 ~ /-j DNAT/ {
      for (i=1;i<=NF;i++) if ($i=="--to-destination") { print $(i+1); exit }
    }'
}
all_ports_active() { [[ -n "$(current_all_target)" ]]; }

delete_script_rules_in_chain() {
	local table="$1" chain="$2"
	local rules
	rules=$("$IPT" -t "$table" -S "$chain" 2>/dev/null | grep -E -- "-m comment --comment ($PF_COMMENT|$ALL_COMMENT)" || true)
	while IFS= read -r rule; do
		[[ -z "$rule" ]] && continue
		# SC2295 fix: quote variable inside pattern
		local spec="${rule#-A "$chain" }"
		# SC2086 fix: split safely into an array of args
		local -a args=()
		# shellcheck disable=SC2206
		args=($spec)
		IPT_RUN -t "$table" -D "$chain" "${args[@]}" 2>/dev/null || true
	done <<<"$rules"
}

script_rules_exist() {
	"$IPT" -t nat -S PREROUTING 2>/dev/null | grep -qE -- "--comment ($PF_COMMENT|$ALL_COMMENT)" && return 0
	"$IPT" -t nat -S POSTROUTING 2>/dev/null | grep -qE -- "--comment ($PF_COMMENT|$ALL_COMMENT)" && return 0
	"$IPT" -S FORWARD 2>/dev/null | grep -qE -- "--comment ($PF_COMMENT|$ALL_COMMENT)" && return 0
	return 1
}

flush_script_rules() {
	# Optional: pass "--yes" to skip confirmation
	local force="${1:-}"
	if ! script_rules_exist; then
		warn "No script-added rules found. Nothing to remove."
		return 0
	fi

	if [[ "$force" != "--yes" ]]; then
		read -r -p "$(printf "%bAre you sure to remove all script-added rules? [y/N]: %b" "$RED" "$NC")" CONF
		if [[ ! "$CONF" =~ ^[Yy]$ ]]; then
			warn "Aborted. No rules were removed."
			return 0
		fi
	fi

	delete_script_rules_in_chain nat PREROUTING
	delete_script_rules_in_chain nat POSTROUTING
	delete_script_rules_in_chain filter FORWARD
	info "Removed rules added by this script."
	save_iptables
}

# ---------- Forwarding helpers ----------
ensure_forward_accept_for() {
	local dst="$1"
	IPT_RUN -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
		IPT_RUN -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	IPT_RUN -C FORWARD -d "$dst" -j ACCEPT -m comment --comment "$PF_COMMENT" 2>/dev/null ||
		IPT_RUN -A FORWARD -d "$dst" -j ACCEPT -m comment --comment "$PF_COMMENT"
	IPT_RUN -C FORWARD -s "$dst" -j ACCEPT -m comment --comment "$PF_COMMENT" 2>/dev/null ||
		IPT_RUN -A FORWARD -s "$dst" -j ACCEPT -m comment --comment "$PF_COMMENT"
}

ensure_snat() {
	# src="MASQ" for MASQUERADE, otherwise explicit IPv4 SNAT
	local src="${1:-MASQ}"
	if [[ "$src" != "MASQ" ]]; then
		IPT_RUN -t nat -C POSTROUTING -o "$IFACE" -j SNAT --to-source "$src" -m comment --comment "$PF_COMMENT" 2>/dev/null ||
			IPT_RUN -t nat -A POSTROUTING -o "$IFACE" -j SNAT --to-source "$src" -m comment --comment "$PF_COMMENT"
	else
		IPT_RUN -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE -m comment --comment "$PF_COMMENT" 2>/dev/null ||
			IPT_RUN -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE -m comment --comment "$PF_COMMENT"
	fi
}

dnat_any_target_for_port() {
	# Checks if a given port is already DNATed by *this script* (any proto).
	# Prints "proto:IP:port" for first match, otherwise nothing.
	local port="$1"
	"$IPT" -t nat -S PREROUTING 2>/dev/null | awk -v p="$port" -v tag="$PF_COMMENT" '
    $0 ~ ("--dport " p) && $0 ~ /-j DNAT/ && $0 ~ ("--comment " tag) {
      proto="";
      for (i=1;i<=NF;i++) {
        if ($i=="-p") proto=$(i+1);
        if ($i=="--to-destination") { print proto ":" $(i+1); exit }
      }
    }'
}

# ---------- Operations ----------
forward_port() {
	# Forward one port (adds TCP & UDP). If called from multi, batch=1 avoids extra save.
	local port="$1" dst="$2" batch="${3:-0}"

	if all_ports_active; then
		err "ALL mode is active. Disable it first (option 4) to add single-port rules."
		return 2
	fi
	if ! is_port "$port"; then
		err "Invalid port"
		return 1
	fi
	if ! is_ip "$dst"; then
		err "Destination IP required (IPv4)"
		return 1
	fi

	local exist exist_dest
	exist="$(dnat_any_target_for_port "$port" || true)"
	if [[ -n "$exist" ]]; then
		exist_dest="${exist#*:}"
		if [[ "$exist_dest" == "${dst}:${port}" ]]; then
			warn "Port $port already forwarded to $dst (no change)."
			return 0
		else
			err "Port $port already forwarded to ${exist_dest%:*}. Remove it first (option 4) and retry."
			return 2
		fi
	fi

	IPT_RUN -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$port" -j DNAT --to-destination "${dst}:${port}" -m comment --comment "$PF_COMMENT"
	IPT_RUN -t nat -A PREROUTING -i "$IFACE" -p udp --dport "$port" -j DNAT --to-destination "${dst}:${port}" -m comment --comment "$PF_COMMENT"

	ensure_forward_accept_for "$dst"
	ensure_snat "MASQ"

	((batch == 0)) && save_iptables
	info "Port $port forwarded to $dst (TCP+UDP)."
}

forward_multi_ports() {
	# Add many ports in one run; rules are saved once at the end.
	local dst="$1" ports="$2"
	if all_ports_active; then
		err "ALL mode is active. Disable it first (option 4) to add multi-port rules."
		return 2
	fi
	if ! is_ip "$dst"; then
		err "Destination IP required (IPv4)"
		return 1
	fi

	IFS=',' read -ra parr <<<"$ports"
	local added=()
	for p in "${parr[@]}"; do
		p="$(tr -d '[:space:]' <<<"$p")"
		[[ -z "$p" ]] && continue
		if forward_port "$p" "$dst" 1; then
			added+=("$p")
		fi
	done

	if ((${#added[@]} > 0)); then
		save_iptables
		info "Multi-port: forwarded [${added[*]}] to $dst"
	else
		warn "Multi-port: no new rules added."
	fi
}

forward_all_except_ssh() {
	# Enable ALL mode: forward all (TCP+UDP) except SSH to a target host.
	local dst="$1" src="${2:-MASQ}"

	if ! is_ip "$dst"; then
		err "Destination IP required (IPv4)"
		return 1
	fi

	local cur
	cur="$(current_all_target || true)"
	if [[ -n "$cur" ]]; then
		if [[ "$cur" == "$dst" ]]; then
			warn "ALL mode already active → forwarding all (except SSH:$SSH_PORT) to $dst. No changes."
			show_forwarded_rules
			return 0
		else
			read -r -p "$(printf "%bALL mode is active to %s. Replace with %s? [y/N]: %b" "$YELLOW" "$cur" "$dst" "$NC")" REPL
			if [[ ! "$REPL" =~ ^[Yy]$ ]]; then
				warn "Aborted. Kept existing ALL mode to $cur."
				show_forwarded_rules
				return 0
			fi
			flush_script_rules --yes
		fi
	fi

	IPT_RUN -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$SSH_PORT" -j ACCEPT -m comment --comment "$PF_COMMENT"
	IPT_RUN -t nat -A PREROUTING -i "$IFACE" -p tcp ! --dport "$SSH_PORT" -j DNAT --to-destination "$dst" -m comment --comment "$ALL_COMMENT"
	IPT_RUN -t nat -A PREROUTING -i "$IFACE" -p udp -j DNAT --to-destination "$dst" -m comment --comment "$ALL_COMMENT"

	ensure_forward_accept_for "$dst"
	ensure_snat "$src"

	save_iptables
	info "ALL mode enabled: forwarding all (except SSH:$SSH_PORT) to $dst"
}

show_forwarded_rules() {
	note "--- nat PREROUTING ---"
	"$IPT" -t nat -S PREROUTING | grep -E "$PF_COMMENT|$ALL_COMMENT" || true
	note "--- nat POSTROUTING ---"
	"$IPT" -t nat -S POSTROUTING | grep -E "$PF_COMMENT|$ALL_COMMENT" || true
	note "--- filter FORWARD ---"
	"$IPT" -S FORWARD | grep -F "$PF_COMMENT" || true
}

# ---------- Menu ----------
restore_iptables || true
clear || true
printf "%bBy --> Peyman • github.com/Ptechgithub%b\n\n" "$CYAN" "$NC"
printf "%b╔════════════════════════════════════════════╗%b\n" "$YELLOW" "$NC"
printf "%b║%b        💻 IPTables Port Forwarding         %b║%b\n" "$YELLOW" "$CYAN" "$YELLOW" "$NC"
printf "%b╠════════════════════════════════════════════╣%b\n" "$YELLOW" "$NC"
printf "%b║ 1️⃣  Single port forwarding (TCP+UDP)       ║%b\n" "$YELLOW" "$NC"
printf "%b║ 2️⃣  Multi port forwarding (comma-separated)║%b\n" "$YELLOW" "$NC"
printf "%b║ 3️⃣  All traffic forwarding (except SSH)    ║%b\n" "$YELLOW" "$NC"
printf "%b║ 4️⃣  Remove only script-added rules         ║%b\n" "$YELLOW" "$NC"
printf "%b║ 5️⃣  Show script-managed rules              ║%b\n" "$YELLOW" "$NC"
printf "%b║ 6️⃣  Exit                                   ║%b\n" "$YELLOW" "$NC"
printf "%b╚════════════════════════════════════════════╝%b\n\n" "$YELLOW" "$NC"

if all_ports_active; then
	note "ALL mode is ACTIVE → target: $(current_all_target)"
else
	note "ALL mode is INACTIVE."
fi
echo

read -r -p "📌 Select an option [1-6]: " CHOICE
CHOICE="${CHOICE:-}"

case "$CHOICE" in
1)
	read -r -p "Destination IP: " DST
	read -r -p "Port (TCP+UDP): " PORT
	forward_port "$PORT" "$DST"
	;;
2)
	read -r -p "Destination IP: " DST
	read -r -p "Ports (comma-separated): " PORTS
	forward_multi_ports "$DST" "$PORTS"
	;;
3)
	read -r -p "Destination IP for all traffic: " DST
	read -r -p "SNAT source (IPv4) or 'MASQ' [MASQ]: " SRC
	SRC="${SRC:-MASQ}"
	forward_all_except_ssh "$DST" "$SRC"
	;;
4) flush_script_rules ;;
5) show_forwarded_rules ;;
6)
	printf "%bExit%b\n" "$BLUE" "$NC"
	exit 0
	;;
*)
	err "Invalid option"
	exit 1
	;;
esac
