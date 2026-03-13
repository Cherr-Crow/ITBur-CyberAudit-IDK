import os
import socket
import subprocess

def file_audit():
    print("\n--- [1] Анализ прав доступа ---")
    path = "/etc" 
    print(f"Проверка директории: {path}")

def network_audit():
    print("\n--- [2] Сетевой аудит ---")
    target = "127.0.0.1"
    ports = [21, 22, 23, 80, 443]
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"[!] Порт {port} ОТКРЫТ")
        s.close()

def package_audit():
    print("\n--- [3] Аудит пакетов ---")

    try:
        result = subprocess.run(['dpkg', '--list'], capture_output=True, text=True)
        print("Список пакетов получен (первые 5 строк):")
        print("\n".join(result.stdout.splitlines()[:5]))
    except FileNotFoundError:
        print("Команда dpkg не найдена (возможно, вы не в Linux)")

if __name__ == "__main__":
    print("Запуск автоматического аудитора безопасности...")
    file_audit()
    network_audit()
    package_audit()
    print("\nАудит завершен.")
