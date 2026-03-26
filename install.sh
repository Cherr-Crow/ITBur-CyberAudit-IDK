#!/bin/bash
# 🛡️ Автоустановщик аудитора безопасности

echo "╔════════════════════════════════════════╗"
echo "║  🛡️ УСТАНОВКА АУДИТОРА БЕЗОПАСНОСТИ   ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не найден! Установите: sudo apt install python3"
    exit 1
fi

# Определение системы
if [ -f /etc/debian_version ]; then
    echo "📦 Установка системных зависимостей (Debian/Ubuntu)..."
    sudo apt update
    sudo apt install -y python3-tk fonts-dejavu-core
elif [ -f /etc/redhat-release ]; then
    echo "📦 Установка системных зависимостей (RHEL/CentOS)..."
    sudo yum install -y python3-tkinter dejavu-sans-fonts
else
    echo "⚠ Неизвестная система. Возможно, потребуется ручная установка."
fi

# Установка Python-зависимостей
echo "📦 Установка Python-библиотек..."
pip3 install -r requirements.txt --user

# Права на выполнение
chmod +x auditor.py
chmod +x install.sh

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  ✅ УСТАНОВКА ЗАВЕРШЕНА!               ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "🚀 Запуск: sudo ./auditor.py"
echo "📄 Или: sudo python3 auditor.py"
echo ""
