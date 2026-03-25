import os
import socket
import subprocess
import platform
import sys
from tkinter import *
from tkinter import ttk


root = Tk()
root.title("АВТОМАТИЧЕСКИЙ АУДИТОР БЕЗОПАСНОСТИ LINUX")
root.geometry('900x700')
root.configure(bg='black')


style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Arial', 12), background='gray20', foreground='white')
style.map('TButton', background=[('active', 'gray40')])


frame_top = Frame(root, bg='black')
frame_top.pack(fill=BOTH, expand=True, padx=10, pady=10)


text = Text(frame_top, wrap=WORD, bg='black', fg='lime', insertbackground='white', font=('Consolas', 10))
scroll = Scrollbar(frame_top, command=text.yview, bg='black')
text.configure(yscrollcommand=scroll.set)
scroll.pack(side=RIGHT, fill=Y)
text.pack(side=LEFT, fill=BOTH, expand=True)


btn_frame = Frame(root, bg='black')
btn_frame.pack(pady=10)

def log(msg):
    text.insert(END, msg + "\n")
    text.see(END)

def check_system():
    text.delete(1.0, END)
    log("Проверка, что скрипт запущен в Linux и с правами root")
    current_os = platform.system()
    if current_os != "Linux":
        log(f"[!] ОШИБКА: Скрипт предназначен только для Linux. Ваша система: {current_os}")
        return False
    if os.geteuid() != 0:
        log("[!] ВНИМАНИЕ: Скрипт запущен БЕЗ прав root. Результаты проверки файлов будут неполными.")
    else:
        log("[+] Проверка ОС пройдена (Linux). Права администратора подтверждены.")
    return True

def file_audit():
    log("\n=== Анализ прав доступа (/etc) ===")
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
                if int(mode) > int(target_mode):
                    status = f"УЯЗВИМО ({mode})"
                    rec = f"Установите chmod {target_mode}"
                else:
                    status = f"OK ({mode})"
                    rec = "Правки не требуются"
            except PermissionError:
                status = "НЕТ ДОСТУПА"
                rec = "Запустите скрипт через sudo"
            log(f"{file:<30} | {status:<15} | {rec}")
        else:
            log(f"{file:<30} | Не найден | -")

def network_audit():
    log("\n=== Сетевой аудит (localhost) ===")
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
            status = f"ОТКРЫТ ({name})"
            rec = "Закройте порт или используйте VPN/SSH" if port != 443 else "OK"
        else:
            status = "ЗАКРЫТ"
            rec = "-"
        log(f"Порт {port:<5} | {status:<20} | {rec}")
        s.close()

def package_audit():
    log("\n=== Аудит пакетов ===")
    suspicious_apps = ['telnet', 'netcat', 'rsh-client', 'wireshark', 'nmap']
    try:
        installed = subprocess.run(['dpkg', '--get-selections'], capture_output=True, text=True).stdout
        for app in suspicious_apps:
            if app in installed:
                status = "УСТАНОВЛЕН"
                rec = "Удалить, если не нужен для работы"
            else:
                status = "НЕ НАЙДЕН"
                rec = "Рисков нет"
            log(f"{app:<15} | {status:<10} | {rec}")
    except FileNotFoundError:
        log("Ошибка: Утилита dpkg не найдена (это не Debian/Ubuntu/Kali?)")

def run_audit():
    if check_system():
        file_audit()
        network_audit()
        package_audit()
        log("\n[+] Аудит завершен.")

btn_check = ttk.Button(btn_frame, text="Запустить аудит", command=run_audit)
btn_check.pack(side=LEFT, padx=5)
btn_clear = ttk.Button(btn_frame, text="Очистить", command=lambda: text.delete(1.0, END))
btn_clear.pack(side=LEFT, padx=5)


frame_stats = Frame(root, bg='black', bd=2, relief='groove')
frame_stats.pack(fill=X, padx=10, pady=10)

label_stats_title = Label(frame_stats, text="СТАТИСТИКА", bg='black', fg='lime', font=('Arial', 14, 'bold'))
label_stats_title.pack(anchor='w', padx=10, pady=5)

stats_frame = Frame(frame_stats, bg='black')
stats_frame.pack(fill=X, padx=10)


ports_scanned = IntVar(value=0)
open_ports = IntVar(value=0)
closed_ports = IntVar(value=0)
filtered_ports = IntVar(value=0)
scan_speed = StringVar(value='0 p/s')

def update_stats():

    ports_scanned.set(0)
    open_ports.set(0)
    closed_ports.set(0)
    filtered_ports.set(0)
    scan_speed.set('0 p/s')


Label(stats_frame, text="PORTS SCANNED", bg='black', fg='lime').grid(row=0, column=0, sticky='w')
Label(stats_frame, textvariable=ports_scanned, bg='black', fg='green', font=('Consolas', 12)).grid(row=0, column=1, sticky='w')

Label(stats_frame, text="OPEN PORTS", bg='black', fg='lime').grid(row=1, column=0, sticky='w')
Label(stats_frame, textvariable=open_ports, bg='black', fg='green', font=('Consolas', 12)).grid(row=1, column=1, sticky='w')

Label(stats_frame, text="CLOSED PORTS", bg='black', fg='lime').grid(row=2, column=0, sticky='w')
Label(stats_frame, textvariable=closed_ports, bg='black', fg='red', font=('Consolas', 12)).grid(row=2, column=1, sticky='w')

Label(stats_frame, text="FILTERED PORTS", bg='black', fg='lime').grid(row=3, column=0, sticky='w')
Label(stats_frame, textvariable=filtered_ports, bg='black', fg='orange', font=('Consolas', 12)).grid(row=3, column=1, sticky='w')

Label(stats_frame, text="SCAN SPEED", bg='black', fg='lime').grid(row=4, column=0, sticky='w')
Label(stats_frame, textvariable=scan_speed, bg='black', fg='cyan', font=('Consolas', 12)).grid(row=4, column=1, sticky='w')


update_stats()

root.mainloop()