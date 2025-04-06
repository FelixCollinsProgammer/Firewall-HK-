import sys
import os
import time
import configparser
import ctypes
from datetime import datetime
from bcc import BPF
import random
import socket
import struct

# ANSI escape codes for colors
ORANGE = '\033[38;5;208m'  # More vibrant orange
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
GREEN = '\033[92m'
RESET = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
REVERSED = '\033[7m'  # Inverted colors

# Animated symbols
ANIMATED_SYMBOLS = ['◓', '◑', '◒', '◐']  # More visually appealing symbols
SUCCESS_SYMBOLS = ['✔', '✓', '✅', '✨']  # Success symbols, added sparkle
ERROR_SYMBOLS = ['✖', '✗', '❌', '❗', '🔥']  # Error symbols, added fire
INFO_SYMBOLS = ['ℹ', '💡', '📣']  # Info symbols

SETTINGS_PATH = './networkguard.conf'
EVENT_LOG_PATH = './networkguard.log'

def clear_terminal():
    os.system('clear' if os.name == 'posix' else 'cls')

def colored_print(text, color=RESET):
    print(f"{color}{text}{RESET}")

def animated_print(text, color=ORANGE, animation_speed=0.1):
    for symbol in ANIMATED_SYMBOLS:
        print(f"\r{color}{text} {symbol}{RESET}", end='')
        time.sleep(animation_speed)
    print(f"\r{color}{text}   {RESET}", end='')  # Clear the animation after it's done

def success_print(text, color=GREEN):
    symbol = random.choice(SUCCESS_SYMBOLS)
    colored_print(f"{symbol} {text}", color)

def error_print(text, color=RED):
    symbol = random.choice(ERROR_SYMBOLS)
    colored_print(f"{symbol} {text}", color)

def info_print(text):
    symbol = random.choice(INFO_SYMBOLS)
    colored_print(f"{symbol} {ORANGE}{text}{RESET}", ORANGE)

def show_help_message():
    script_name = os.path.basename(sys.argv[0])
    colored_print(f"\n{BOLD}Использование:{RESET}", BLUE)
    colored_print(f"  sudo python3 {script_name} [сетевой_интерфейс]", BLUE)
    colored_print(f"  sudo python3 {script_name} --add <порт1,порт2,...>", BLUE)
    colored_print(f"  sudo python3 {script_name} --del <порт1,порт2,...>", BLUE)
    colored_print(f"  sudo python3 {script_name} --show", BLUE)
    colored_print(f"  sudo python3 {script_name} --logs", BLUE)
    colored_print(f"  sudo python3 {script_name} --menu", BLUE)
    colored_print(f"  sudo python3 {script_name} --toggle-icmp", BLUE)
    colored_print(f"  sudo python3 {script_name} --help", BLUE)

BPF_SOURCE_CODE = """
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bcc/proto.h>

// Struct to hold IP address (either IPv4 or IPv6)
union ip_addr {
    u32 addr4; // IPv4 address
    u8 addr6[16]; // IPv6 address
};

// Hash table to store blocked IP addresses
BPF_HASH(blocked_ips, union ip_addr, u8);

// Hash map to store permitted destination ports
BPF_HASH(permitted_dst_ports, u16, u8);

// Per-CPU array to store ICMP allow/block status
BPF_PERCPU_ARRAY(allow_icmp, int, 1);

// Function to identify HTTP-like traffic
static inline int detect_http(struct tcphdr *tcp, void *data_end) {
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 7) > data_end) return 0;

    // Check for common HTTP request methods
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D') ||
        (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') ||
        (payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I') ||
        (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P'))
    {
        return 1;
    }
    return 0;
}

// Function to identify TLS-like (HTTPS) traffic
static inline int detect_tls(struct tcphdr *tcp, void *data_end) {
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 5) > data_end) return 0;

    // Check for TLS handshake initiation bytes
    if (payload[0] == 0x16 || payload[0] == 0x17 || payload[0] == 0x15 || payload[0] == 0x14) {
        if (payload[1] == 0x03) {
            return 1;
        }
    }
    return 0;
}

int network_guard_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

   // Blocked IP Handling
    union ip_addr src_addr;
    src_addr.addr4 = ip->saddr;

    u8 *is_blocked = blocked_ips.lookup(&src_addr);
    if (is_blocked) {
        bpf_trace_printk("IP BLOCKED: Source IP %x\\n", ip->saddr);
        return XDP_DROP; // Drop packet if IP is blocked
    }

    // ICMP Inspection and Filtering
    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
        if ((void *)(icmp + 1) > data_end) return XDP_PASS;

        int key = 0;
        int *allow = allow_icmp.lookup(&key);

        // Check if ICMP is explicitly allowed or blocked
        if (allow) {
            if (*allow == 0) {
                // Drop ICMP traffic if blocking is enabled
                bpf_trace_printk("ICMP BLOCKED: Type %d, Code %d\\n", icmp->type, icmp->code);
                return XDP_DROP;
            }
        } else {
            // If the map isn't initialized, block for safety
            bpf_trace_printk("ICMP BLOCKED: Default block, map not initialized\\n");
            return XDP_DROP;
        }

        // Allow ICMP if not blocked
        return XDP_PASS;
    }

    // TCP Inspection and Filtering
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        u16 dest_port = bpf_ntohs(tcp->dest);

        // HTTP/HTTPS Validation
        if (dest_port == 80) {
            void *payload_start = (void *)tcp + (tcp->doff * 4);
            if (payload_start >= data_end) return XDP_PASS;
            if (!detect_http(tcp, data_end)) {
                bpf_trace_printk("TCP BLOCKED: Non-HTTP on port 80\\n");
                return XDP_DROP;
            }
            return XDP_PASS;
        } else if (dest_port == 443) {
            void *payload_start = (void *)tcp + (tcp->doff * 4);
            if (payload_start >= data_end) return XDP_PASS;
            if (!detect_tls(tcp, data_end)) {
                bpf_trace_printk("TCP BLOCKED: Non-TLS on port 443\\n");
                return XDP_DROP;
            }
            return XDP_PASS;
        }

        // Custom Port Policy Enforcement
        if (tcp->syn && !tcp->ack) {
            u8 *is_permitted = permitted_dst_ports.lookup(&dest_port);
            if (!is_permitted) {
                bpf_trace_printk("TCP BLOCKED: Destination Port %u\\n", dest_port);
                return XDP_DROP;
            }
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}
"""

class NetworkGuardManager:
    def __init__(self):
        self.settings_file = os.path.expanduser(SETTINGS_PATH)
        self.log_file = EVENT_LOG_PATH
        self.standard_ports_config = []
        self.custom_ports = []
        self.allow_icmp = False
        self.blocked_ips = set() # Set to store blocked IPs
        self._load_settings()

    def _ensure_dir_exists(self, file_path):
        dir_name = os.path.dirname(file_path)
        if dir_name and not os.path.exists(dir_name):
            try:
                os.makedirs(dir_name, exist_ok=True)
            except OSError as e:
                error_print(f"Ошибка создания директории: {e}")

    def _load_settings(self):
        config = configparser.ConfigParser()
        self._ensure_dir_exists(self.settings_file)
        try:
            read_files = config.read(self.settings_file, encoding='utf-8')
            if not read_files:
                config['AccessControl'] = {
                    'standard_ports': '80,443',
                    'custom_ports': '',
                    'allow_icmp': '0',
                    'blocked_ips': ''  # Added blocked IPs
                }
                self._save_settings(config)

            std_ports_str = config.get('AccessControl', 'standard_ports', fallback='80,443')
            cust_ports_str = config.get('AccessControl', 'custom_ports', fallback='')
            self.standard_ports_config = [int(p.strip()) for p in std_ports_str.split(',') if p.strip().isdigit()]
            self.custom_ports = [int(p.strip()) for p in cust_ports_str.split(',') if p.strip().isdigit()]
            self.allow_icmp = config.getboolean('AccessControl', 'allow_icmp', fallback=False)
            blocked_ips_str = config.get('AccessControl', 'blocked_ips', fallback='')
            self.blocked_ips = set(ip.strip() for ip in blocked_ips_str.split(',') if ip.strip())

        except (configparser.Error, ValueError) as e:
            error_print(f"Проблема при загрузке настроек: {e}")
            self.standard_ports_config = [80, 443]
            self.custom_ports = []
            self.allow_icmp = False
            self.blocked_ips = set()

    def _save_settings(self, config_obj=None):
        if config_obj is None:
            config_obj = configparser.ConfigParser()
            config_obj.add_section('AccessControl')
            config_obj.set('AccessControl', 'standard_ports', ','.join(map(str, sorted(self.standard_ports_config))))
            config_obj.set('AccessControl', 'custom_ports', ','.join(map(str, sorted(self.custom_ports))))
            config_obj.set('AccessControl', 'allow_icmp', str(int(self.allow_icmp)))
            config_obj.set('AccessControl', 'blocked_ips', ','.join(sorted(self.blocked_ips))) # Save blocked IPs

        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                config_obj.write(f)
            success_print("Настройки успешно сохранены.")
        except IOError as e:
            error_print(f"Сбой записи настроек: {e}")

    def get_ports_for_bpf_map(self):
        return sorted(list(set(self.custom_ports)))

    def display_current_ports(self):
        ports_in_map = self.get_ports_for_bpf_map()
        colored_print("\n--- Текущая конфигурация ---", CYAN)
        colored_print("  Стандартные порты: 80, 443", GREEN)
        icmp_status = f"{GREEN}Включен{RESET}" if self.allow_icmp else f"{RED}Выключен{RESET}"
        colored_print(f"  ICMP (ping): {icmp_status}", ORANGE)
        colored_print(f"  Дополнительные порты: {', '.join(map(str, self.custom_ports)) or 'Нет'}", GREEN)
        colored_print(f"  Заблокированные IP: {', '.join(sorted(self.blocked_ips)) or 'Нет'}", RED) # Show blocked IPs

    def modify_port_list(self, action, ports_str):
        try:
            ports_to_change = set()
            for p_str in ports_str.split(','):
                p_str = p_str.strip()
                if p_str.isdigit():
                    port = int(p_str)
                    if 0 < port < 65536 and port not in [80, 443]:
                        ports_to_change.add(port)

            if not ports_to_change:
                info_print("Нет корректных портов для изменения.")
                return False

            current_ports = set(self.custom_ports)
            if action == 'add':
                updated_ports = current_ports.union(ports_to_change)
                success_print(f"Добавлено {len(updated_ports) - len(current_ports)} портов.")
            elif action == 'del':
                updated_ports = current_ports - ports_to_change
                info_print(f"Удалено {len(current_ports) - len(updated_ports)} портов.")
            else:
                return False

            if len(updated_ports) != len(current_ports):
                self.custom_ports = sorted(list(updated_ports))
                self._save_settings()
                return True
            return False
        except ValueError:
            error_print("Ошибка в формате номеров портов.")
            return False

    def modify_blocked_ips(self, action, ips_str):
         try:
            ips_to_change = set(ip.strip() for ip in ips_str.split(',') if self.is_valid_ipv4(ip.strip()))
            invalid_ips = set(ip.strip() for ip in ips_str.split(',') if ip.strip() and not self.is_valid_ipv4(ip.strip()))

            if invalid_ips:
                error_print(f"Некорректные IP адреса: {', '.join(invalid_ips)}")

            if not ips_to_change:
                info_print("Нет корректных IP адресов для изменения.")
                return False

            current_ips = set(self.blocked_ips)

            if action == 'add':
                updated_ips = current_ips.union(ips_to_change)
                success_print(f"Добавлено {len(updated_ips) - len(current_ips)} IP адресов.")
            elif action == 'del':
                updated_ips = current_ips - ips_to_change
                info_print(f"Удалено {len(current_ips) - len(updated_ips)} IP адресов.")
            else:
                return False

            if len(updated_ips) != len(current_ips):
                self.blocked_ips = sorted(list(updated_ips))
                self._save_settings()
                return True
            return False

         except ValueError:
            error_print("Ошибка в формате IP адресов.")
            return False

    def is_valid_ipv4(self, ip_address):
        try:
            socket.inet_pton(socket.AF_INET, ip_address)
        except AttributeError:  # Missing on some platforms
            try:
                socket.inet_aton(ip_address)
            except socket.error:
                return False
            return ip_address.count('.') == 3
        except socket.error:
            return False

        return True

    def log_event(self, message_type, details):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message_type.upper()} | {details}\n"
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except IOError as e:
            error_print(f"Не удалось записать в лог: {e}")

    def display_event_logs(self, limit=15):
        colored_print(f"\n--- Последние {limit} событий ---", CYAN)
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if not lines:
                        info_print("Журнал пуст.")
                        return

                    for line in lines[-limit:]:
                        colored_print(f"  {line.strip()}", MAGENTA)
            else:
                info_print("Журнал еще не создан.")
        except IOError as e:
            error_print(f"Ошибка чтения лога: {e}")

    def activate_filter(self, interface_name):
        ports_for_bpf_map = self.get_ports_for_bpf_map()

        colored_print(f"\nЗапуск защиты на интерфейсе: {interface_name}", CYAN)

        try:
            bpf_instance = BPF(text=BPF_SOURCE_CODE)

            # Blocked IP Logic
            blocked_ips_table = bpf_instance["blocked_ips"]
            blocked_ips_table.clear() # Clear existing IPs

            for ip_str in self.blocked_ips:
                try:
                    packed_ip = socket.inet_aton(ip_str)  # Pack IP as network byte order
                    ip_int = struct.unpack("!I", packed_ip)[0]  # Convert to integer
                    key = ctypes.c_uint32(ip_int)

                    # key = ctypes.c_uint32(int(ipaddress.IPv4Address(ip_str))) # Convert to integer

                    blocked_ips_table[key] = ctypes.c_ubyte(1)
                    # bpf_trace_printk("Blocking IP: %s (0x%x)\\n", ip_str, key)
                except Exception as e:
                    error_print(f"Ошибка при добавлении IP {ip_str} в BPF: {e}")

            port_map = bpf_instance["permitted_dst_ports"]
            port_map.clear()
            for port in ports_for_bpf_map:
                port_map[ctypes.c_ushort(port)] = ctypes.c_ubyte(1)

            allow_icmp_array = bpf_instance["allow_icmp"]
            key = ctypes.c_int(0)
            value = ctypes.c_int(1 if self.allow_icmp else 0)
            allow_icmp_array[key] = value

            filter_func = bpf_instance.load_func("network_guard_filter", BPF.XDP)

            animated_print("Активация защиты...")  # Start animation
            bpf_instance.attach_xdp(interface_name, filter_func, 0)
            success_print(f"Защита активирована на {interface_name}!")  # Success message

            try:
                while True:
                    try:
                        (_, _, _, _, _, msg_bytes) = bpf_instance.trace_fields()
                        message = msg_bytes.decode('utf-8', errors='replace').strip()

                        if "ICMP BLOCKED" in message:
                            icmp_info = message.split(": ", 1)[1]  # Extract ICMP info
                            colored_print(f"\r{RED}ICMP заблокирован: {icmp_info}{RESET}", end='')
                            log_details = icmp_info
                            self.log_event("ICMP_BLOCKED", log_details)
                        elif "TCP BLOCKED" in message:
                             tcp_info = message.split(": ", 1)[1]
                             colored_print(f"\r{RED}TCP заблокирован: {tcp_info}{RESET}", end='')
                             log_details = tcp_info
                             self.log_event("TCP_BLOCKED", log_details)
                        elif "IP BLOCKED" in message:
                            ip_addr = message.split(": ", 1)[1]
                            colored_print(f"\r{RED}IP заблокирован: {ip_addr}{RESET}", end='')
                            log_details = ip_addr
                            self.log_event("IP_BLOCKED", log_details)

                    except Exception:
                        time.sleep(0.1)
            except KeyboardInterrupt:
                colored_print("\nОстановка защиты...", YELLOW)
        except Exception as e:
            error_print(f"\nОшибка при активации защиты: {e}")
        finally:
            if 'bpf_instance' in locals() and interface_name:
                try:
                    bpf_instance.remove_xdp(interface_name, 0)
                except Exception as e:
                    error_print(f"Ошибка при деактивации защиты: {e}")

    def toggle_icmp(self):
        self.allow_icmp = not self.allow_icmp
        self._save_settings()
        icmp_status = f"{GREEN}Включен{RESET}" if self.allow_icmp else f"{RED}Выключен{RESET}"
        success_print(f"ICMP (ping) теперь {icmp_status}")

    def run_interactive_mode(self):
        while True:
            clear_terminal()
            # Calculate padding for the title
            title = "🛡️ Gazan Firewall 🛡️"
            width = 45  # Total width of the box
            padding = (width - len(title)) // 2
            # Build the header
            header = "╔" + "═" * (width - 2) + "╗"
            colored_print(header, ORANGE)
            # Build the title line with dynamic padding
            title_line = "║" + " " * padding + title + " " * (width - 2 - padding - len(title)) + "║"
            colored_print(title_line, ORANGE)
            # Separator line
            separator = "╠" + "═" * (width - 2) + "╣"
            colored_print(separator, ORANGE)

            icmp_status = f"{GREEN}Включен{RESET}" if self.allow_icmp else f"{RED}Выключен{RESET}"
            colored_print(f"║    ICMP (ping): {icmp_status}                      ║", ORANGE)
            colored_print("║ 1. Показать настройки                    ║", ORANGE)
            colored_print("║ 2. Добавить порты                         ║", ORANGE)
            colored_print("║ 3. Удалить порты                          ║", ORANGE)
            colored_print("║ 4. Заблокировать IP                      ║", ORANGE)
            colored_print("║ 5. Разблокировать IP                     ║", ORANGE)
            colored_print("║ 6. Запустить Firewall                    ║", ORANGE)
            colored_print("║ 7. Просмотр журнала                       ║", ORANGE)
            colored_print("║ 8. Вкл/Выкл ICMP (Ping)                    ║", ORANGE)
            colored_print("║ 9. Выход                                ║", ORANGE)

            footer = "╚" + "═" * (width - 2) + "╝"
            colored_print(footer, ORANGE)

            choice = input(f"\n{ORANGE}Ваш выбор [1-9]: {RESET}").strip()

            if choice == '1':
                self.display_current_ports()
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '2':
                self.display_current_ports()
                ports_str = input(f"\n{ORANGE}Введите порты (через запятую): {RESET}").strip()
                if ports_str:
                    self.modify_port_list('add', ports_str)
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '3':
                self.display_current_ports()
                ports_str = input(f"\n{ORANGE}Введите порты для удаления: {RESET}").strip()
                if ports_str:
                    self.modify_port_list('del', ports_str)
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '4':
                self.display_current_ports()
                ips_str = input(f"\n{RED}Введите IP для блокировки (через запятую): {RESET}").strip()
                if ips_str:
                    self.modify_blocked_ips('add', ips_str)
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '5':
                self.display_current_ports()
                ips_str = input(f"\n{GREEN}Введите IP для разблокировки (через запятую): {RESET}").strip()
                if ips_str:
                    self.modify_blocked_ips('del', ips_str)
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '6':
                if os.geteuid() != 0:
                    error_print("Требуются права администратора (sudo)!")
                    input(f"\n{YELLOW}Нажмите Enter...{RESET}")
                    continue
                interface = input(f"\n{ORANGE}Введите интерфейс [lo]: {RESET}").strip() or "lo"
                self.activate_filter(interface)
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '7':
                self.display_event_logs()
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")
            elif choice == '8':
                self.toggle_icmp()
                input(f"\n{YELLOW}Нажмите Enter...{RESET}")

            elif choice == '9':
                colored_print("\nВыход...", YELLOW)
                break
            else:
                error_print("Неверный ввод!")
                time.sleep(1)

def process_command_line_args():
    manager = NetworkGuardManager()
    args = sys.argv[1:]

    if not args:
        show_help_message()
        sys.exit(1)

    command = args[0]

    if command == '--help':
        show_help_message()
    elif command == '--menu':
        manager.run_interactive_mode()
    elif command == '--show':
        manager.display_current_ports()
    elif command == '--logs':
        manager.display_event_logs()
    elif command == '--add':
        if len(args) < 2:
            error_print("Не указаны порты для добавления.")
            sys.exit(1)
        manager.modify_port_list('add', args[1])
    elif command == '--del':
        if len(args) < 2:
            error_print("Не указаны порты для удаления.")
            sys.exit(1)
        manager.modify_port_list('del', args[1])
    elif command == '--toggle-icmp':
        manager.toggle_icmp()
    elif not command.startswith('--'):
        if os.geteuid() != 0:
            error_print("Требуются права root!")
            sys.exit(1)
        manager.activate_filter(command)
    else:
        error_print(f"Неизвестная команда: {command}")
        show_help_message()
        sys.exit(1)

if __name__ == "__main__":
    process_command_line_args()