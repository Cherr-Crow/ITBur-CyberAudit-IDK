#!/bin/bash
echo "🔧 Настройка аудитора безопасности..."

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не найден!"
    exit 1
fi

# Установка tkinter (Linux)
if [ -f /etc/debian_version ]; then
    echo "📦 Установка python3-tk..."
    sudo apt update && sudo apt install -y python3-tk
fi

# Установка зависимостей
echo "📦 Установка Python-зависимостей..."
pip3 install -r requirements.txt

# Права на выполнение
chmod +x auditor.py

echo "✅ Готово! Запуск: sudo ./auditor.py"
