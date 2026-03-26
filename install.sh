#!/bin/bash
# 🛡️ Автоустановщик аудитора безопасности v2.0

set -e  # Остановка при ошибке

echo "╔════════════════════════════════════════"
echo "║  🛡️ АУДИТОР БЕЗОПАСНОСТИ - УСТАНОВКА   "
echo "╚════════════════════════════════════════"
echo ""

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не найден!"
    exit 1
fi

# Системные зависимости
if [ -f /etc/debian_version ]; then
    echo "📦 Системные пакеты..."
    sudo apt update -qq
    sudo apt install -y python3-tk fonts-dejavu-core python3-pip
elif [ -f /etc/redhat-release ]; then
    echo "📦 Системные пакеты (RHEL)..."
    sudo yum install -y python3-tkinter python3-pip
fi

# 🔴 Python-библиотеки (для root!)
echo "📦 Python-библиотеки..."
sudo pip3 install reportlab --break-system-packages -q

# Права
chmod +x auditor.py
chmod +x install.sh

echo ""
echo "╔════════════════════════════════════════"
echo "║  ✅ УСТАНОВКА ЗАВЕРШЕНА!               "
echo "╚════════════════════════════════════════"
echo ""
echo "🚀 Запуск: sudo ./auditor.py"
echo ""
