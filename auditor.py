import os
import socket
import subprocess
import platform
import sys

# Цвета для терминала
G = '033[92m' # Good
Y = '033[93m' # Warning
R = '033[91m' # Danger
W = '033[0m'  # Reset

def check_system():
    """Проверка, что скрипт запущен в Linux и с правами root"""
    print(f"[*] Анализ окружения...")
    
    current_os = platform.system()
    if current_os != "Linux":
        print(f"{R}[!] ОШИБКА: Скрипт предназначен только для Linux. Ваша система: {current_os}{W}")
        sys.exit(1)
    
    if os.geteuid() != 0:
        print(f"{Y}[!] ВНИМАНИЕ: Скрипт запущен БЕЗ прав root. Результаты проверки файлов будут неполными.{W}")
    else:
        print(f"{G}[+] Проверка ОС пройдена (Linux). Права администратора подтверждены.{W}")

def print_table_header(title):
    print(f"n{Y}=== {title} ==={W}")
    print(f"{'-'*105}")
    print(f"{'Объект/Параметр':<30} | {'Статус':<20} | {'Рекомендация'}")
    print(f"{'-'*105}")

def file_audit():
    print_table_header("АНАЛИЗ ПРАВ ДОСТУПА (/etc)")
    critical_files = {
        '/etc/passwd': '644',
        '/etc/shadow': '600',
        '/etc/group': '644',
        '/etc/sudoers': '440'
    }
    
    for file, target_mode in critical_files.items():
        if os.path.exists(file):
            try:
                mode = oct(os.stat(file).st_mode)[-3:]
                if mode > target_mode:
                    status = f"{R}УЯЗВИМО ({mode}){W}"
                    rec = f"Установите chmod {target_mode}"
                else:
                    status = f"{G}OK ({mode}){W}"
                    rec = "Правки не требуются"
            except PermissionError:
                status = f"{Y}НЕТ ДОСТУПА{W}"
                rec = "Запустите скрипт через sudo"
            
            print(f"{file:<30} | {status:<30} | {rec}")

def network_audit():
    print_table_header("СЕТЕВОЙ АУДИТ (Localhost)")
    check_ports = {
        21: "FTP (Небезопасно)",
        22: "SSH (Стандарт)",
        23: "Telnet (ОПАСНО)",
        80: "HTTP (Нешифрованный)",
        443: "HTTPS (Безопасно)"
    }
    
    for port, name in check_ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        result = s.connect_ex(('127.0.0.1', port))
        
        if result == 0:
            status = f"{R}ОТКРЫТ ({name}){W}"
            rec = "Закройте порт или используйте VPN/SSH" if port != 443 else "OK"
        else:
            status = f"{G}ЗАКРЫТ{W}"
            rec = "-"
            
        print(f"{f'Порт {port}':<30} | {status:<30} | {rec}")
        s.close()

def package_audit():
    print_table_header("АУДИТ ПАКЕТОВ")
    suspicious_apps = ['telnet', 'netcat', 'rsh-client', 'wireshark', 'nmap']
    
    try:
        installed = subprocess.run(['dpkg', '--get-selections'], capture_output=True, text=True).stdout
        
        for app in suspicious_apps:
            if app in installed:
                status = f"{Y}УСТАНОВЛЕН{W}"
                rec = f"Удалить, если не нужен для работы"
            else:
                status = f"{G}НЕ НАЙДЕН{W}"
                rec = "Рисков нет"
            print(f"{app:<30} | {status:<30} | {rec}")
    except FileNotFoundError:
        print(f"{R}Ошибка: Утилита dpkg не найдена (это не Debian/Ubuntu/Kali?){W}")

if __name__ == "__main__":
    os.system('clear')
    
    print(f"{G}╔════════════════════════════════════════════════════════════╗{W}")
    print(f"{G}║          АВТОМАТИЧЕСКИЙ АУДИТОР БЕЗОПАСНОСТИ LINUX         ║{W}")
    print(f"{G}╚════════════════════════════════════════════════════════════╝{W}n")
    
    check_system()
    
    file_audit()
    network_audit()
    package_audit()
    
    print(f"n{G}[+] Аудит завершен.{W}")