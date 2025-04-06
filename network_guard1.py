import sys
import os
import time
import configparser
import ctypes
from datetime import datetime
from bcc import BPF

# ANSI escape codes for colors
BLUE = '\033[94m'
RESET = '\033[0m'

SETTINGS_PATH = './networkguard.conf'
EVENT_LOG_PATH = './networkguard.log'

def clear_terminal():
    os.system('clear' if os.name == 'posix' else 'cls')

def show_help_message():
    script_name = os.path.basename(sys.argv[0])
    print(f"{BLUE}\nИспользование скрипта:{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} [сетевой_интерфейс]{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} --add <порт1,порт2,...>{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} --del <порт1,порт2,...>{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} --show{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} --logs{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} --menu{RESET}")
    print(f"{BLUE}  sudo python3 {script_name} --help{RESET}")

BPF_SOURCE_CODE = """
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <bcc/proto.h>

BPF_HASH(permitted_dst_ports, u16, u8);

static inline int is_http_like(struct tcphdr *tcp, void *data_end) {
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 7) > data_end) return 0;

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

static inline int is_tls_like(struct tcphdr *tcp, void *data_end) {
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 5) > data_end) return 0;

    if (payload[0] == 0x16 || payload[0] == 0x17 || payload[0] == 0x15 || payload[0] == 0x14) {
        if (payload[1] == 0x03) {
            return 1;
        }
    }
    return 0;
}

int packet_filter_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return XDP_PASS;

    if (ethernet->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip_header = (struct iphdr *)(ethernet + 1);
    if ((void *)(ip_header + 1) > data_end) return XDP_PASS;

    /*  Блокировка ICMP - НАЧАЛО (изменено) */
    if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(ip_header + 1);
        if ((void *)(icmp + 1) > data_end) return XDP_PASS; // Пропускаем если не хватает данных

        // Проверяем, разрешен ли ICMP.  Если нет, блокируем.
        if (global_allow_icmp == 0) {
            bpf_trace_printk("BLOCKED_ICMP: type=%d code=%d\\n");
            return XDP_DROP;
        } else {
            return XDP_PASS; // Разрешаем ICMP
        }
    }
    /* Блокировка ICMP - КОНЕЦ (изменено) */

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_segment = (struct tcphdr *)(ip_header + 1);
        if ((void *)(tcp_segment + 1) > data_end) return XDP_PASS;

        u16 destination_port = bpf_ntohs(tcp_segment->dest);

        if (destination_port == 80) {
            void *payload_start = (void *)tcp_segment + (tcp_segment->doff * 4);
            if (payload_start >= data_end) return XDP_PASS;
            if (!is_http_like(tcp_segment, data_end)) {
                bpf_trace_printk("DENIED: Non-HTTP Traffic on Port 80\\n");
                return XDP_DROP;
            }
            return XDP_PASS;
        } else if (destination_port == 443) {
            void *payload_start = (void *)tcp_segment + (tcp_segment->doff * 4);
            if (payload_start >= data_end) return XDP_PASS;
            if (!is_tls_like(tcp_segment, data_end)) {
                bpf_trace_printk("DENIED: Non-TLS/HTTPS Traffic on Port 443\\n");
                return XDP_DROP;
            }
            return XDP_PASS;
        }

        if (tcp_segment->syn && !tcp_segment->ack) {
            u8 *is_permitted = permitted_dst_ports.lookup(&destination_port);
            if (!is_permitted) {
                bpf_trace_printk("DENIED: Dest Port %u Not Allowed\\n", destination_port);
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
        self.allow_icmp = False  # Добавили переменную для ICMP
        self._load_settings()

    def _ensure_dir_exists(self, file_path):
        dir_name = os.path.dirname(file_path)
        if dir_name and not os.path.exists(dir_name):
            try:
                os.makedirs(dir_name, exist_ok=True)
            except OSError as e:
                print(f"{BLUE}Ошибка создания директории {dir_name}: {e}{RESET}")

    def _load_settings(self):
        config = configparser.ConfigParser()
        self._ensure_dir_exists(self.settings_file)
        try:
            read_files = config.read(self.settings_file, encoding='utf-8')
            if not read_files:
                # Если файла нет, создаем его с настройками по умолчанию
                config['AccessControl'] = {
                    'standard_ports': '80,443',
                    'custom_ports': '',
                    'allow_icmp': '0'  # По умолчанию блокируем ICMP
                }
                self._save_settings(config)

            std_ports_str = config.get('AccessControl', 'standard_ports', fallback='80,443')
            cust_ports_str = config.get('AccessControl', 'custom_ports', fallback='')
            self.standard_ports_config = [int(p.strip()) for p in std_ports_str.split(',') if p.strip().isdigit()]
            self.custom_ports = [int(p.strip()) for p in cust_ports_str.split(',') if p.strip().isdigit()]

            # Читаем настройку allow_icmp
            self.allow_icmp = config.getboolean('AccessControl', 'allow_icmp', fallback=False)

        except (configparser.Error, ValueError) as e:
            print(f"{BLUE}Ошибка при чтении конфигурации: {e}{RESET}")
            self.standard_ports_config = [80, 443]
            self.custom_ports = []
            self.allow_icmp = False # По умолчанию блокируем ICMP в случае ошибки

    def _save_settings(self, config_obj=None):
        if config_obj is None:
            config_obj = configparser.ConfigParser()
            config_obj.add_section('AccessControl')
            config_obj.set('AccessControl', 'standard_ports', ','.join(map(str, sorted(self.standard_ports_config))))
            config_obj.set('AccessControl', 'custom_ports', ','.join(map(str, sorted(self.custom_ports))))
            config_obj.set('AccessControl', 'allow_icmp', str(int(self.allow_icmp)))  # Сохраняем настройку ICMP

        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                config_obj.write(f)
        except IOError as e:
            print(f"{BLUE}Ошибка при записи файла конфигурации: {e}{RESET}")

    def get_ports_for_bpf_map(self):
        return sorted(list(set(self.custom_ports)))

    def display_current_ports(self):
        ports_in_map = self.get_ports_for_bpf_map()
        print(f"{BLUE}\n--- Текущие Настройки Портов ---{RESET}")
        print(f"{BLUE}  Обрабатываются специально: 80, 443{RESET}")
        print(f"{BLUE}  ICMP (ping): {'Разрешено' if self.allow_icmp else 'Заблокировано'}{RESET}")  # Отображаем статус ICMP
        print(f"{BLUE}  Пользовательские порты: {', '.join(map(str, self.custom_ports)) or 'Нет'}{RESET}")

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
                print(f"{BLUE}Нет корректных портов для изменения{RESET}")
                return False

            current_ports = set(self.custom_ports)
            if action == 'add':
                updated_ports = current_ports.union(ports_to_change)
                print(f"{BLUE}Добавлено {len(updated_ports) - len(current_ports)} портов{RESET}")
            elif action == 'del':
                updated_ports = current_ports - ports_to_change
                print(f"{BLUE}Удалено {len(current_ports) - len(updated_ports)} портов{RESET}")
            else:
                return False

            if len(updated_ports) != len(current_ports):
                self.custom_ports = sorted(list(updated_ports))
                self._save_settings()
                return True
            return False
        except ValueError:
            print(f"{BLUE}Ошибка обработки номеров портов{RESET}")
            return False

    def log_event(self, message_type, details):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message_type.upper()} | {details}\n"
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except IOError as e:
            print(f"{BLUE}Ошибка записи в журнал: {e}{RESET}")

    def display_event_logs(self, limit=15):
        print(f"{BLUE}\n--- Последние {limit} записей журнала ---{RESET}")
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    for line in f.readlines()[-limit:]:
                        print(f"{BLUE}  {line.strip()}{RESET}")
            else:
                print(f"{BLUE}Журнал событий пуст{RESET}")
        except IOError as e:
            print(f"{BLUE}Ошибка чтения журнала: {e}{RESET}")

    def activate_filter(self, interface_name):
        ports_for_bpf_map = self.get_ports_for_bpf_map()

        print(f"{BLUE}\nЗапуск фильтра на интерфейсе: {interface_name}{RESET}")
        # Определяем, разрешен ли ICMP
        allow_icmp_int = 1 if self.allow_icmp else 0

        # Подставляем значение allow_icmp в BPF-код
        bpf_source = BPF_SOURCE_CODE
        bpf_source = bpf_source.replace("global_allow_icmp", str(allow_icmp_int))

        try:
            bpf_instance = BPF(text=bpf_source)
            port_map = bpf_instance["permitted_dst_ports"]
            port_map.clear()
            for port in ports_for_bpf_map:
                port_map[ctypes.c_ushort(port)] = ctypes.c_ubyte(1)

            filter_func = bpf_instance.load_func("packet_filter_xdp", BPF.XDP)
            bpf_instance.attach_xdp(interface_name, filter_func, 0)
            print(f"{BLUE}Фильтр успешно активирован на {interface_name}{RESET}")

            try:
                while True:
                    try:
                        (_, _, _, _, _, msg_bytes) = bpf_instance.trace_fields()
                        message = msg_bytes.decode('utf-8', errors='replace').strip()

                        if "BLOCKED_ICMP" in message:
                            icmp_type = message.split("type=")[1].split(" ")[0]
                            icmp_code = message.split("code=")[1].split("\\")[0]
                            print(f"{BLUE}\rБлокировка ICMP: type={icmp_type}, code={icmp_code}{RESET}", end='')
                            self.log_event("BLOCKED_ICMP", f"Type: {icmp_type}, Code: {icmp_code}")
                        elif "DENIED:" in message:
                            print(f"{BLUE}\r{message}{RESET}", end='')
                            self.log_event("DENIED", message.split("DENIED: ")[1])
                    except Exception:
                        time.sleep(0.1)
            except KeyboardInterrupt:
                print(f"{BLUE}\nОстановка фильтра...{RESET}")
        except Exception as e:
            print(f"{BLUE}\nОшибка запуска фильтра: {e}{RESET}")
        finally:
            if 'bpf_instance' in locals() and interface_name:
                try:
                    bpf_instance.remove_xdp(interface_name, 0)
                except Exception as e:
                    print(f"{BLUE}Ошибка при отсоединении XDP: {e}{RESET}")

    def toggle_icmp(self):
        self.allow_icmp = not self.allow_icmp
        self._save_settings()
        print(f"{BLUE}\nICMP (ping) {'разрешен' if self.allow_icmp else 'заблокирован'}{RESET}")

    def run_interactive_mode(self):
        while True:
            clear_terminal()
            print(f"{BLUE}\n╔═════════════════════════════════════════╗{RESET}")
            print(f"{BLUE}║    🛡️ Gazan Firewall 🛡️                   ║{RESET}")
            print(f"{BLUE}╠═════════════════════════════════════════╣{RESET}")
            print(f"{BLUE}║    ICMP (ping): {'Разрешен' if self.allow_icmp else 'Заблокировано'}     {RESET}")
            print(f"{BLUE}║ 1. Показать текущие настройки           ║{RESET}")
            print(f"{BLUE}║ 2. Добавить разрешенные порты           ║{RESET}")
            print(f"{BLUE}║ 3. Удалить разрешенные порты            ║{RESET}")
            print(f"{BLUE}║ 4. Запустить Firewall                   ║{RESET}")
            print(f"{BLUE}║ 5. Просмотр логов                       ║{RESET}")
            print(f"{BLUE}║ 6. Выход                                ║{RESET}")
            print(f"{BLUE}╚═════════════════════════════════════════╝{RESET}")
            choice = input(f"{BLUE}\n Ваш выбор [1-6]: {RESET}").strip()

            if choice == '1':
                self.display_current_ports()
                input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")
            elif choice == '2':
                self.display_current_ports()
                ports_str = input(f"{BLUE}\nВведите порты для добавления: {RESET}").strip()
                if ports_str:
                    self.modify_port_list('add', ports_str)
                input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")
            elif choice == '3':
                self.display_current_ports()
                ports_str = input(f"{BLUE}\nВведите порты для удаления: {RESET}").strip()
                if ports_str:
                    self.modify_port_list('del', ports_str)
                input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")
            elif choice == '4':
                if os.geteuid() != 0:
                    print(f"{BLUE}\nТребуется sudo!{RESET}")
                    input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")
                    continue
                interface = input(f"{BLUE}\nВведите интерфейс [lo]: {RESET}").strip() or "lo"
                self.activate_filter(interface)
                input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")
            elif choice == '5':
                self.display_event_logs()
                input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")
            elif choice == '6': # Добавлено
                self.toggle_icmp()
                input(f"{BLUE}\nНажмите Enter для возврата...{RESET}")

            elif choice == '7':
                print(f"{BLUE}\nВыход из программы...{RESET}")
                break
            else:
                print(f"{BLUE}\nНекорректный ввод!{RESET}")
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
            print(f"{BLUE}Укажите порты для добавления{RESET}")
            sys.exit(1)
        manager.modify_port_list('add', args[1])
    elif command == '--del':
        if len(args) < 2:
            print(f"{BLUE}Укажите порты для удаления{RESET}")
            sys.exit(1)
        manager.modify_port_list('del', args[1])
    elif not command.startswith('--'):
        if os.geteuid() != 0:
            print(f"{BLUE}Требуется sudo!{RESET}")
            sys.exit(1)
        manager.activate_filter(command)
    else:
        print(f"{BLUE}Неизвестная команда: {command}{RESET}")
        show_help_message()
        sys.exit(1)

if __name__ == "__main__":
    process_command_line_args()
