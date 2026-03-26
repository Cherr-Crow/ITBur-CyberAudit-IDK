#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ Автоматический аудитор безопасности Linux (GUI версия)
Версия: 3.2.4 (Оценка 0 до аудита + защита от пустого сохранения)
"""
import os
import re
import socket
import subprocess
import platform
import sys
from datetime import datetime
from collections import OrderedDict
from tkinter import *
from tkinter import ttk
from tkinter import messagebox

# ═══════════════════════════════════════════════════════════════
# 📊 СТАТИСТИКА
# ═══════════════════════════════════════════════════════════════
class AuditStats:
    def __init__(self):
        self.start_time = datetime.now()
        self.categories = {
            'system': {'p': 0, 'w': 0, 'c': 0, 't': 0},
            'files': {'p': 0, 'w': 0, 'c': 0, 't': 0},
            'network': {'p': 0, 'w': 0, 'c': 0, 't': 0},
            'users': {'p': 0, 'w': 0, 'c': 0, 't': 0},
            'services': {'p': 0, 'w': 0, 'c': 0, 't': 0},
            'hardening': {'p': 0, 'w': 0, 'c': 0, 't': 0},
        }
        self.findings = []

    def add(self, cat, status, msg, simple_msg=None, details=None, fix=None, simple_fix=None):
        if cat not in self.categories:
            cat = 'system'
        self.categories[cat]['t'] += 1
        if status == 'good':
            self.categories[cat]['p'] += 1
        elif status == 'warning':
            self.categories[cat]['w'] += 1
        elif status == 'critical':
            self.categories[cat]['c'] += 1
        self.findings.append({
            'cat': cat,
            'status': status,
            'msg': msg,
            'simple_msg': simple_msg or msg,
            'details': details,
            'fix': fix,
            'simple_fix': simple_fix or fix
        })

    def score(self):
        """Формула подсчёта безопасности"""
        t = sum(c['t'] for c in self.categories.values())
        if t == 0:
            return 0  # ✅ ВОЗВРАЩАЕМ 0 ЕСЛИ ПРОВЕРОК НЕ БЫЛО
        p = sum(c['p'] for c in self.categories.values())
        w = sum(c['w'] for c in self.categories.values())
        c = sum(c['c'] for c in self.categories.values())

        raw_score = (p * 100 + w * 50 + c * 0) / t
        critical_penalty = min(30, c * 5)
        final_score = raw_score - critical_penalty

        return max(0, min(100, round(final_score)))

    def summary(self):
        return {
            'dur': (datetime.now() - self.start_time).total_seconds(),
            'total': sum(c['t'] for c in self.categories.values()),
            'passed': sum(c['p'] for c in self.categories.values()),
            'warn': sum(c['w'] for c in self.categories.values()),
            'crit': sum(c['c'] for c in self.categories.values()),
            'score': self.score()
        }

stats = AuditStats()

# ═══════════════════════════════════════════════════════════════
# ⚙️ КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════
CONFIG = {
    'critical_files': OrderedDict([
        ('/etc/passwd', ('644', 'Список пользователей')),
        ('/etc/shadow', ('600', 'Пароли пользователей')),
        ('/etc/group', ('644', 'Группы пользователей')),
        ('/etc/sudoers', ('440', 'Настройки администратора')),
        ('/etc/ssh/sshd_config', ('600', 'Настройки подключения')),
        ('/etc/crontab', ('600', 'Расписание задач')),
    ]),
    'suspicious_ports': OrderedDict([
        (21, ('FTP', 'critical', 'Передача без шифрования')),
        (22, ('SSH', 'info', 'Безопасное подключение')),
        (23, ('Telnet', 'critical', 'Пароли видны всем')),
        (80, ('HTTP', 'warning', 'Сайт без защиты')),
        (443, ('HTTPS', 'good', 'Сайт с защитой')),
        (3306, ('MySQL', 'warning', 'База данных')),
        (6379, ('Redis', 'critical', 'Часто без пароля')),
    ]),
    'suspicious_packages': [
        'telnet', 'netcat', 'nmap', 'tcpdump', 'john', 'hashcat'
    ],
    'export_pdf': 'security_report.pdf',
    'export_txt': 'security_report.txt'
}

# ═══════════════════════════════════════════════════════════════
# 🛡️ ЗАЩИТА ОТ ДУРАКОВ
# ═══════════════════════════════════════════════════════════════
audit_completed = False  # Флаг: был ли проведён аудит
audit_timestamp = None   # Время последнего аудита

# ═══════════════════════════════════════════════════════════════
# 🖥️ GUI ПРИЛОЖЕНИЕ
# ═══════════════════════════════════════════════════════════════
root = Tk()
root.title("🛡️ АВТОМАТИЧЕСКИЙ АУДИТОР БЕЗОПАСНОСТИ LINUX v3.2.4")
root.geometry('1100x800')
root.configure(bg='#1a1a1a')

style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Arial', 11, 'bold'), background='#2d2d2d', foreground='white')
style.map('TButton', background=[('active', '#404040')])

# Верхний фрейм для текста
frame_top = Frame(root, bg='#1a1a1a')
frame_top.pack(fill=BOTH, expand=True, padx=10, pady=10)

text = Text(frame_top, wrap=WORD, bg='#0d0d0d', fg='#00ff00', insertbackground='white',
            font=('Consolas', 10), state='normal')
scroll = Scrollbar(frame_top, command=text.yview, bg='#1a1a1a')
text.configure(yscrollcommand=scroll.set)
scroll.pack(side=RIGHT, fill=Y)
text.pack(side=LEFT, fill=BOTH, expand=True)

# Фрейм для кнопок
btn_frame = Frame(root, bg='#1a1a1a')
btn_frame.pack(pady=10)

# Фрейм статистики
frame_stats = Frame(root, bg='#1a1a1a', bd=2, relief='groove')
frame_stats.pack(fill=X, padx=10, pady=10)

label_stats_title = Label(frame_stats, text="📊 СТАТИСТИКА АУДИТА", bg='#1a1a1a',
                          fg='#00ff00', font=('Arial', 14, 'bold'))
label_stats_title.pack(anchor='w', padx=10, pady=5)

stats_frame = Frame(frame_stats, bg='#1a1a1a')
stats_frame.pack(fill=X, padx=10)

# Переменные статистики
total_checks = IntVar(value=0)
passed_checks = IntVar(value=0)
warning_checks = IntVar(value=0)
critical_checks = IntVar(value=0)
security_score = StringVar(value='0/100')  # ✅ ИЗНАЧАЛЬНО 0
scan_duration = StringVar(value='0.0 сек')

# ═══════════════════════════════════════════════════════════════
# 📝 ФУНКЦИИ ВЫВОДА
# ═══════════════════════════════════════════════════════════════
def log(msg, color='#00ff00'):
    """Вывод сообщения в текстовое поле GUI"""
    text.config(state='normal')
    text.insert(END, msg + "\n")
    text.see(END)
    text.config(state='normal')

def clear_log():
    """Очистка текстового поля"""
    text.config(state='normal')
    text.delete(1.0, END)

def update_stats_display():
    """Обновление отображения статистики"""
    s = stats.summary()
    total_checks.set(s['total'])
    passed_checks.set(s['passed'])
    warning_checks.set(s['warn'])
    critical_checks.set(s['crit'])
    security_score.set(f"{s['score']}/100")
    scan_duration.set(f"{s['dur']:.1f} сек")

def create_stats_labels():
    """Создание меток статистики"""
    Label(stats_frame, text="ВСЕГО ПРОВЕРОК:", bg='#1a1a1a', fg='#00ff00',
          font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5)
    Label(stats_frame, textvariable=total_checks, bg='#1a1a1a', fg='#00ffff',
          font=('Consolas', 12, 'bold')).grid(row=0, column=1, sticky='w', padx=5)

    Label(stats_frame, text="✅ ПРОЙДЕНО:", bg='#1a1a1a', fg='#00ff00',
          font=('Arial', 10, 'bold')).grid(row=0, column=2, sticky='w', padx=20)
    Label(stats_frame, textvariable=passed_checks, bg='#1a1a1a', fg='#00ff00',
          font=('Consolas', 12, 'bold')).grid(row=0, column=3, sticky='w', padx=5)

    Label(stats_frame, text="⚠ ПРЕДУПРЕЖДЕНИЯ:", bg='#1a1a1a', fg='#00ff00',
          font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', padx=5)
    Label(stats_frame, textvariable=warning_checks, bg='#1a1a1a', fg='#ffff00',
          font=('Consolas', 12, 'bold')).grid(row=1, column=1, sticky='w', padx=5)

    Label(stats_frame, text="🔴 КРИТИЧЕСКИЕ:", bg='#1a1a1a', fg='#00ff00',
          font=('Arial', 10, 'bold')).grid(row=1, column=2, sticky='w', padx=20)
    Label(stats_frame, textvariable=critical_checks, bg='#1a1a1a', fg='#ff0000',
          font=('Consolas', 12, 'bold')).grid(row=1, column=3, sticky='w', padx=5)

    Label(stats_frame, text="📈 ОЦЕНКА БЕЗОПАСНОСТИ:", bg='#1a1a1a', fg='#00ff00',
          font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='w', padx=5)
    Label(stats_frame, textvariable=security_score, bg='#1a1a1a', fg='#ff0000',  # ✅ КРАСНЫЙ ДО АУДИТА
          font=('Consolas', 14, 'bold')).grid(row=2, column=1, sticky='w', padx=5)

    Label(stats_frame, text="⏱ ВРЕМЯ ПРОВЕРКИ:", bg='#1a1a1a', fg='#00ff00',
          font=('Arial', 10, 'bold')).grid(row=2, column=2, sticky='w', padx=20)
    Label(stats_frame, textvariable=scan_duration, bg='#1a1a1a', fg='#ffffff',
          font=('Consolas', 12, 'bold')).grid(row=2, column=3, sticky='w', padx=5)

# ═══════════════════════════════════════════════════════════════
# 🛡️ ПРОВЕРКА: БЫЛ ЛИ ПРОВЕДЁН АУДИТ
# ═══════════════════════════════════════════════════════════════
def check_audit_completed():
    """✅ Проверяет, был ли проведён аудит перед сохранением"""
    global audit_completed
    if not audit_completed:
        messagebox.showerror(
            "❌ АУДИТ НЕ ПРОВЕДЁН",
            "⚠️ ОШИБКА: Сохранение невозможно!\n\n"
            "📋 Аудит безопасности ещё не был проведён.\n\n"
            "💡 ЧТО НУЖНО СДЕЛАТЬ:\n"
            "1. Нажмите кнопку «🚀 ЗАПУСТИТЬ АУДИТ»\n"
            "2. Дождитесь завершения проверки\n"
            "3. После этого вы получите оценку безопасности\n"
            "4. Затем можно сохранить отчёт\n\n"
            "📊 Без аудита оценка будет: 0/100"
        )
        log("\n⚠️ Попытка сохранения без аудита! Сначала проведите проверку.", '#ffff00')
        log("   💡 Нажмите «🚀 ЗАПУСТИТЬ АУДИТ» для получения оценки безопасности", '#ffff00')
        return False
    return True

# ═══════════════════════════════════════════════════════════════
# 📄 ГЕНЕРАЦИЯ PDF ОТЧЁТА
# ═══════════════════════════════════════════════════════════════
def generate_pdf_report():
    """✅ Создаёт PDF с поддержкой кириллицы"""
    if not check_audit_completed():
        return False

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        font_registered = False
        font_paths = [
            '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            '/usr/share/fonts/TTF/DejaVuSans.ttf',
            '/usr/share/fonts/dejavu/DejaVuSans.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
            '/usr/share/fonts/liberation/LiberationSans-Regular.ttf',
            'C:\\Windows\\Fonts\\arial.ttf',
            '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
        ]

        for font_path in font_paths:
            if os.path.exists(font_path):
                try:
                    pdfmetrics.registerFont(TTFont('CyrillicFont', font_path))
                    font_registered = True
                    log(f"✅ Шрифт загружен: {font_path}", '#00ff00')
                    break
                except:
                    continue

        if not font_registered:
            log("⚠ Шрифт с кириллицей не найден. PDF будет с ограничениями.", '#ffff00')
            log("   Установите: sudo apt install fonts-dejavu", '#ffff00')

        doc = SimpleDocTemplate(CONFIG['export_pdf'], pagesize=A4,
                                rightMargin=0.5*inch, leftMargin=0.5*inch,
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()

        font_name = 'CyrillicFont' if font_registered else 'Helvetica'

        title_style = ParagraphStyle('CustomTitle', parent=styles['Normal'],
                                     fontName=font_name, fontSize=18,
                                     textColor=colors.darkblue, spaceAfter=12,
                                     alignment=TA_CENTER, leading=22)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Normal'],
                                       fontName=font_name, fontSize=14,
                                       textColor=colors.darkblue, spaceAfter=6,
                                       spaceBefore=12, leading=18)
        normal_style = ParagraphStyle('CustomNormal', parent=styles['Normal'],
                                      fontName=font_name, fontSize=11,
                                      textColor=colors.black, spaceAfter=6, leading=14)
        warning_style = ParagraphStyle('Warning', parent=styles['Normal'],
                                       fontName=font_name, fontSize=11,
                                       textColor=colors.orange, spaceAfter=6, leading=14)
        critical_style = ParagraphStyle('Critical', parent=styles['Normal'],
                                        fontName=font_name, fontSize=11,
                                        textColor=colors.red, spaceAfter=6, leading=14)
        success_style = ParagraphStyle('Success', parent=styles['Normal'],
                                       fontName=font_name, fontSize=11,
                                       textColor=colors.green, spaceAfter=6, leading=14)

        story = []
        s = stats.summary()

        story.append(Paragraph("ОТЧЁТ О БЕЗОПАСНОСТИ КОМПЬЮТЕРА", title_style))
        story.append(Paragraph(f"Дата проверки: {datetime.now().strftime('%d.%m.%Y в %H:%M')}", normal_style))
        story.append(Paragraph(f"Компьютер: {socket.gethostname()}", normal_style))
        story.append(Paragraph(f"OS: {platform.system()} {platform.release()}", normal_style))
        story.append(Spacer(1, 0.3*inch))

        grade = 'A' if s['score'] >= 90 else 'B' if s['score'] >= 75 else 'C' if s['score'] >= 60 else 'D' if s['score'] >= 40 else 'F'
        story.append(Paragraph(f"ОБЩАЯ ОЦЕНКА: {grade} ({s['score']} из 100)", heading_style))

        if s['score'] >= 80:
            explanation = "Хорошо! Ваш компьютер хорошо защищён."
        elif s['score'] >= 60:
            explanation = "Нормально. Есть несколько моментов для улучшения."
        else:
            explanation = "Внимание! Обнаружены серьёзные проблемы."
        story.append(Paragraph(explanation, normal_style))
        story.append(Spacer(1, 0.2*inch))

        stat_data = [
            ['Всё в порядке', str(s['passed'])],
            ['Требует внимания', str(s['warn'])],
            ['Критические проблемы', str(s['crit'])],
            ['Всего проверок', str(s['total'])],
            ['Время проверки', f"{s['dur']:.1f} сек"]
        ]
        stat_table = Table(stat_data, colWidths=[3*inch, 1*inch])
        stat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(stat_table)
        story.append(Spacer(1, 0.3*inch))

        critical_findings = [f for f in stats.findings if f['status'] == 'critical']
        if critical_findings:
            story.append(Paragraph("СНАЧАЛА ИСПРАВИТЬ ЭТО", heading_style))
            for i, finding in enumerate(critical_findings[:10], 1):
                story.append(Paragraph(f"<b>{i}. {finding['simple_msg']}</b>", critical_style))
                if finding['simple_fix']:
                    story.append(Paragraph(f"   Как исправить: {finding['simple_fix']}", normal_style))
                story.append(Spacer(1, 0.1*inch))

        warning_findings = [f for f in stats.findings if f['status'] == 'warning']
        if warning_findings:
            story.append(Paragraph("ЖЕЛАТЕЛЬНО ИСПРАВИТЬ", heading_style))
            for i, finding in enumerate(warning_findings[:15], 1):
                story.append(Paragraph(f"<b>{i}. {finding['simple_msg']}</b>", warning_style))
                if finding['simple_fix']:
                    story.append(Paragraph(f"   Как исправить: {finding['simple_fix']}", normal_style))
                story.append(Spacer(1, 0.1*inch))

        good_findings = [f for f in stats.findings if f['status'] == 'good']
        if good_findings:
            story.append(Paragraph("ВСЁ ХОРОШО", heading_style))
            good_table_data = [['Что затронуто', 'Результат']]
            for finding in good_findings[:20]:
                good_table_data.append([finding['simple_msg'], 'OK'])
            good_table = Table(good_table_data, colWidths=[3.5*inch, 1*inch])
            good_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), font_name),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(good_table)

        doc.build(story)
        log(f"✅ PDF-отчёт сохранён: {CONFIG['export_pdf']}", '#00ff00')
        return True
    except ImportError:
        log("⚠ Библиотека reportlab не установлена.", '#ffff00')
        log("   Установите: pip install reportlab", '#ffff00')
        return False
    except Exception as e:
        log(f"✗ Ошибка создания PDF: {e}", '#ff0000')
        return False

# ═══════════════════════════════════════════════════════════════
# 📄 TXT ОТЧЁТ
# ═══════════════════════════════════════════════════════════════
def generate_txt_report():
    """✅ Создаёт TXT-отчёт с кириллицей"""
    if not check_audit_completed():
        return False

    try:
        s = stats.summary()
        grade = 'A' if s['score'] >= 90 else 'B' if s['score'] >= 75 else 'C' if s['score'] >= 60 else 'D' if s['score'] >= 40 else 'F'
        with open(CONFIG['export_txt'], 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("🛡️ ОТЧЁТ О БЕЗОПАСНОСТИ КОМПЬЮТЕРА\n")
            f.write("=" * 80 + "\n")
            f.write(f"Дата проверки: {datetime.now().strftime('%d.%m.%Y в %H:%M')}\n")
            f.write(f"Компьютер: {socket.gethostname()}\n")
            f.write(f"ОС: {platform.system()} {platform.release()}\n")
            f.write("-" * 80 + "\n")
            f.write(f"ОБЩАЯ ОЦЕНКА: {grade} ({s['score']} из 100)\n")
            f.write("-" * 80 + "\n")
            if s['score'] >= 80:
                f.write("✅ ХОРОШО! Ваш компьютер хорошо защищён.\n")
            elif s['score'] >= 60:
                f.write("⚠ НОРМАЛЬНО. Есть несколько моментов для улучшения.\n")
            else:
                f.write("🔴 ВНИМАНИЕ! Обнаружены серьёзные проблемы.\n")
            f.write("СТАТИСТИКА:\n")
            f.write(f"  ✅ Всё в порядке: {s['passed']}\n")
            f.write(f"  ⚠ Требует внимания: {s['warn']}\n")
            f.write(f"  🔴 Критические проблемы: {s['crit']}\n")
            f.write(f"  Всего проверок: {s['total']}\n")

            critical_findings = [f for f in stats.findings if f['status'] == 'critical']
            if critical_findings:
                f.write("=" * 80 + "\n")
                f.write("🔴 СНАЧАЛА ИСПРАВЬТЕ ЭТО\n")
                f.write("=" * 80 + "\n")
                for i, finding in enumerate(critical_findings, 1):
                    f.write(f"{i}. {finding['simple_msg']}\n")
                    if finding['simple_fix']:
                        f.write(f"   Как исправить: {finding['simple_fix']}\n")
                f.write("\n")

            warning_findings = [f for f in stats.findings if f['status'] == 'warning']
            if warning_findings:
                f.write("=" * 80 + "\n")
                f.write("⚠ ЖЕЛАТЕЛЬНО ИСПРАВИТЬ\n")
                f.write("=" * 80 + "\n")
                for i, finding in enumerate(warning_findings, 1):
                    f.write(f"{i}. {finding['simple_msg']}\n")
                    if finding['simple_fix']:
                        f.write(f"   Как исправить: {finding['simple_fix']}\n")
                f.write("\n")

            good_findings = [f for f in stats.findings if f['status'] == 'good']
            if good_findings:
                f.write("=" * 80 + "\n")
                f.write("✅ ВСЁ ХОРОШО\n")
                f.write("=" * 80 + "\n")
                for finding in good_findings:
                    f.write(f"  ✓ {finding['simple_msg']}\n")
                f.write("\n")

        log(f"✅ TXT-отчёт сохранён: {CONFIG['export_txt']}", '#00ff00')
        return True
    except Exception as e:
        log(f"✗ Ошибка создания TXT: {e}", '#ff0000')
        return False

def save_reports():
    """Сохранение обоих отчётов"""
    if not check_audit_completed():
        return

    log("\n" + "="*70, '#00ffff')
    log("📄 СОХРАНЕНИЕ ОТЧЁТОВ", '#00ffff')
    log("="*70, '#00ffff')
    generate_txt_report()
    generate_pdf_report()
    log("="*70, '#00ff00')

# ═══════════════════════════════════════════════════════════════
# 🔍 ПРОВЕРКИ
# ═══════════════════════════════════════════════════════════════
def check_system():
    """Проверка окружения"""
    log("\n" + "="*70, '#00ffff')
    log("🖥️  ПРОВЕРКА ОКРУЖЕНИЯ", '#00ffff')
    log("="*70, '#00ffff')
    os_name = f"{platform.system()} {platform.release()}"
    if platform.system() == 'Linux':
        log(f"  ✅ ОС: {os_name}", '#00ff00')
        stats.add('system', 'good', f'ОС: {os_name}',
                  simple_msg=f'Операционная система: {os_name}')
    else:
        log(f"  🔴 ОС: {os_name} — только для Linux!", '#ff0000')
        stats.add('system', 'critical', f'Неподдерживаемая ОС',
                  simple_msg='Эта программа работает только на Linux')
        return False
    if os.geteuid() == 0:
        log(f"  ✅ Права root: подтверждены", '#00ff00')
        stats.add('system', 'good', 'Запуск с root',
                  simple_msg='Программа запущена с правами администратора')
    else:
        log(f"  ⚠ Запущено БЕЗ прав root", '#ffff00')
        stats.add('system', 'warning', 'Нет root-прав',
                  simple_msg='Программа запущена без прав администратора',
                  simple_fix='Запустите с командой: sudo python3 auditor.py')
    return True

def file_audit():
    """Аудит прав доступа к файлам"""
    log("\n" + "="*70, '#00ffff')
    log("📁 ПРАВА ДОСТУПА К ФАЙЛАМ", '#00ffff')
    log("="*70, '#00ffff')
    log(f"  {'Файл':<40} | {'Ожидаемо':<10} | {'Фактически':<12} | {'Статус'}", '#ffffff')
    log("-"*85, '#404040')
    for filepath, (target_mode, description) in CONFIG['critical_files'].items():
        if os.path.exists(filepath):
            try:
                mode = oct(os.stat(filepath).st_mode)[-3:]
                if mode == target_mode:
                    status_txt = f'OK ({mode})'
                    log(f"  ✅ {filepath:<40} | {target_mode:<10} | {mode:<12} | {status_txt}", '#00ff00')
                    stats.add('files', 'good', f'{filepath}: {mode}',
                              simple_msg=f'Права на {os.path.basename(filepath)} в порядке')
                else:
                    is_crit = any(x in filepath for x in ['shadow', 'sudoers'])
                    status = 'critical' if is_crit else 'warning'
                    status_txt = f'УЯЗВИМО ({mode})'
                    color = '#ff0000' if status == 'critical' else '#ffff00'
                    icon = '🔴' if status == 'critical' else '⚠'
                    log(f"  {icon} {filepath:<40} | {target_mode:<10} | {mode:<12} | {status_txt}", color)
                    stats.add('files', status, f'{filepath}: {mode}',
                              simple_msg=f'Права на {os.path.basename(filepath)}: {mode} (нужно {target_mode})',
                              simple_fix=f'sudo chmod {target_mode} {filepath}')
            except PermissionError:
                log(f"  ⚠ {filepath:<40} | {target_mode:<10} | {'НЕТ ДОСТУПА':<12} | ПРОВЕРЬТЕ", '#ffff00')
                stats.add('files', 'warning', f'Нет доступа к {filepath}',
                          simple_msg=f'Нет доступа к файлу {filepath}',
                          simple_fix='Запустите программу с sudo')
        else:
            log(f"  ⚪ {filepath:<40} | {target_mode:<10} | {'—':<12} | НЕ НАЙДЕН", '#ffffff')
            stats.add('files', 'info', f'Файл не найден: {filepath}',
                      simple_msg=f'Файл {filepath} не найден')

def network_audit():
    """Сетевой аудит"""
    log("\n" + "="*70, '#00ffff')
    log("🌐 СЕТЕВОЙ АУДИТ", '#00ffff')
    log("="*70, '#00ffff')
    log(f"  {'Порт':<8} | {'Сервис':<12} | {'Статус':<10} | {'Риск':<10} | {'Рекомендация'}", '#ffffff')
    log("-"*85, '#404040')
    simple_names = {
        'FTP': 'Передача файлов', 'SSH': 'Удалённое подключение',
        'Telnet': 'Старое подключение', 'HTTP': 'Сайт без защиты',
        'HTTPS': 'Сайт с защитой', 'MySQL': 'База данных',
        'Redis': 'База данных Redis'
    }
    for port, (name, risk_level, description) in CONFIG['suspicious_ports'].items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            result = s.connect_ex(('127.0.0.1', port))
            s.close()
            if result == 0:
                status = 'ОТКРЫТ'
                if risk_level == 'critical':
                    color, rec, st = '#ff0000', 'Закрыть!', 'critical'
                    icon = '🔴'
                elif risk_level == 'warning':
                    color, rec, st = '#ffff00', 'Проверить', 'warning'
                    icon = '⚠'
                else:
                    color, rec, st = '#00ff00', 'OK', 'good'
                    icon = '✅'
            else:
                status, color, rec, st, icon = 'ЗАКРЫТ', '#ffffff', '—', 'good', '✅'
            log(f"  {icon} {port:<8} | {name:<12} | {status:<10} | {risk_level.upper():<10} | {rec}", color)
            stats.add('network', st, f'Порт {port}/{name}: {status.lower()}',
                      simple_msg=f'Порт {port} ({simple_names.get(name, name)}): {status.lower()}',
                      details=description,
                      simple_fix=f'Закройте порт {port} в настройках фаервола' if rec == 'Закрыть!' else None)
        except:
            log(f"  ⚠ {port:<8} | {name:<12} | {'ОШИБКА':<10} | {'—':<10} | {'—'}", '#ffff00')
            stats.add('network', 'warning', f'Ошибка проверки порта {port}',
                      simple_msg=f'Не удалось проверить порт {port}')

    log("\n🔥 Брандмауэр:", '#ffffff')
    fw_found = False
    for cmd, name in [(['iptables', '-L', '-n'], 'iptables'), (['ufw', 'status'], 'UFW')]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and ('ACCEPT' in result.stdout or 'Status: active' in result.stdout):
                log(f"  ✅ {name}: активен", '#00ff00')
                stats.add('network', 'good', f'{name} активен', simple_msg='Брандмауэр включён')
                fw_found = True
                break
        except:
            pass
    if not fw_found:
        log(f"  🔴 Брандмауэр не обнаружен", '#ff0000')
        stats.add('network', 'critical', 'Нет фаервола',
                  simple_msg='Брандмауэр не включён',
                  simple_fix='sudo apt install ufw && sudo ufw enable')

def user_audit():
    """Аудит пользователей"""
    log("\n" + "="*70, '#00ffff')
    log("👥 ПОЛЬЗОВАТЕЛИ", '#00ffff')
    log("="*70, '#00ffff')
    zero_uid = []
    try:
        with open('/etc/passwd') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                    zero_uid.append(parts[0])
        if zero_uid:
            log(f"  🔴 Пользователи с UID 0: {', '.join(zero_uid)}", '#ff0000')
            stats.add('users', 'critical', f'UID 0: {", ".join(zero_uid)}',
                      simple_msg=f'Есть пользователи с правами админа: {", ".join(zero_uid)}',
                      simple_fix='Удалите лишних пользователей')
        else:
            log(f"  ✅ Только root имеет UID 0", '#00ff00')
            stats.add('users', 'good', 'UID 0 только у root',
                      simple_msg='Только главный администратор имеет полные права')
    except Exception as e:
        log(f"  ⚠ Ошибка проверки пользователей: {e}", '#ffff00')
        stats.add('users', 'warning', 'Ошибка проверки пользователей',
                  simple_msg='Не удалось проверить пользователей')

    try:
        result = subprocess.run(['awk', '-F:', '($2 == "" || $2 == "!") {print $1}', '/etc/shadow'],
                                capture_output=True, text=True, timeout=5)
        no_pass = [u for u in result.stdout.strip().split('\n') if u and u not in ['nobody', 'nologin']]
        if no_pass:
            log(f"  🔴 Без пароля: {', '.join(no_pass)}", '#ff0000')
            stats.add('users', 'critical', f'Без пароля: {", ".join(no_pass)}',
                      simple_msg=f'У пользователей нет пароля: {", ".join(no_pass)}',
                      simple_fix='sudo passwd <имя>')
        else:
            log(f"  ✅ Все пользователи имеют пароли", '#00ff00')
            stats.add('users', 'good', 'Пароли у всех пользователей',
                      simple_msg='У всех пользователей есть пароли')
    except:
        stats.add('users', 'warning', 'Не удалось проверить пароли',
                  simple_msg='Не удалось проверить наличие паролей')

def ssh_audit():
    """Аудит SSH"""
    log("\n" + "="*70, '#00ffff')
    log("🔑 НАСТРОЙКИ SSH", '#00ffff')
    log("="*70, '#00ffff')
    ssh_cfg = '/etc/ssh/sshd_config'
    if not os.path.exists(ssh_cfg):
        log(f"  ⚠ Настройки SSH не найдены", '#ffff00')
        stats.add('services', 'warning', 'Нет sshd_config',
                  simple_msg='Настройки SSH не найдены')
        return
    try:
        with open(ssh_cfg) as f:
            content = f.read().lower()
        checks = [
            ('permitrootlogin', 'no', 'critical', 'Вход root'),
            ('passwordauthentication', 'no', 'warning', 'Вход по паролю'),
            ('permitemptypasswords', 'no', 'critical', 'Пустые пароли'),
        ]
        for param, expected, risk, desc in checks:
            pattern = rf'^\s*{param}\s+{expected}'
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                log(f"  ✅ {param}: {expected}", '#00ff00')
                stats.add('services', 'good', f'SSH {param}={expected}',
                          simple_msg=f'{param}: настроено правильно')
            else:
                color = '#ff0000' if risk == 'critical' else '#ffff00'
                icon = '🔴' if risk == 'critical' else '⚠'
                log(f"  {icon} {param}: не задано (рекомендуется: {expected})", color)
                stats.add('services', risk, f'SSH {param}',
                          simple_msg=f'{param}: требует настройки',
                          simple_fix=f'Добавьте в /etc/ssh/sshd_config: {param} {expected}')
    except Exception as e:
        log(f"  ⚠ Ошибка: {e}", '#ffff00')

def package_audit():
    """Аудит пакетов"""
    log("\n" + "="*70, '#00ffff')
    log("📦 ПРОГРАММЫ", '#00ffff')
    log("="*70, '#00ffff')
    log(f"  {'Программа':<25} | {'Статус'}", '#ffffff')
    log("-"*45, '#404040')
    installed = set()
    for cmd in [['dpkg', '--get-selections'], ['rpm', '-qa']]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if line.strip():
                    installed.add(line.split()[0].lower())
        except:
            pass
    for pkg in CONFIG['suspicious_packages']:
        found = any(pkg in inst for inst in installed)
        if found:
            log(f"  ⚠ {pkg:<25} | УСТАНОВЛЕН", '#ffff00')
            stats.add('services', 'warning', f'Пакет {pkg} установлен',
                      simple_msg=f'Установлена программа: {pkg}',
                      simple_fix=f'sudo apt remove {pkg}')
        else:
            log(f"  ✅ {pkg:<25} | НЕ НАЙДЕН", '#00ff00')
            stats.add('services', 'good', f'Пакет {pkg} не установлен',
                      simple_msg=f'Программа {pkg} не установлена')

def print_summary():
    """Вывод итогов"""
    log("\n" + "="*70, '#00ffff')
    log("📊 ИТОГИ АУДИТА", '#00ffff')
    log("="*70, '#00ffff')
    s = stats.summary()
    if s['crit'] > 0:
        grade, gcolor = 'D', '#ff0000'
    elif s['warn'] > 5:
        grade, gcolor = 'C', '#ffff00'
    elif s['warn'] > 0:
        grade, gcolor = 'B', '#00ff00'
    else:
        grade, gcolor = 'A', '#00ff00'
    log(f"\n📈 ОЦЕНКА: {grade} ({s['score']}/100)", gcolor)
    log(f"  ✅ Пройдено: {s['passed']}  ⚠ Предупреждения: {s['warn']}  🔴 Критические: {s['crit']}", '#ffffff')
    log(f"  ⏱ Время проверки: {s['dur']:.1f} сек", '#ffffff')
    update_stats_display()

def run_audit():
    """Запуск полного аудита"""
    global audit_completed, audit_timestamp
    audit_completed = True

    clear_log()
    stats.__init__()
    log("="*70, '#00ffff')
    log("🛡️  АВТОМАТИЧЕСКИЙ АУДИТОР БЕЗОПАСНОСТИ LINUX", '#00ffff')
    log(f"  Версия: 3.2.4 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", '#ffffff')
    log("="*70, '#00ffff')
    if not check_system():
        log("\n🔴 Аудит прерван: неподдерживаемая ОС", '#ff0000')
        return
    file_audit()
    network_audit()
    user_audit()
    ssh_audit()
    package_audit()
    print_summary()
    save_reports()
    log("\n" + "="*70, '#00ff00')
    log("  ✅ АУДИТ ЗАВЕРШЁН!", '#00ff00')
    log(f"  📄 Отчёты: {CONFIG['export_txt']}, {CONFIG['export_pdf']}", '#00ff00')
    log("="*70, '#00ff00')

    # ✅ УСТАНАВЛИВАЕМ ФЛАГ: аудит проведён
    audit_completed = True
    audit_timestamp = datetime.now()
    log(f"\n✅ Аудит завершён в {audit_timestamp.strftime('%H:%M:%S')}", '#00ff00')

# ═══════════════════════════════════════════════════════════════
# 🎛️ КНОПКИ
# ═══════════════════════════════════════════════════════════════
btn_check = ttk.Button(btn_frame, text="🚀 ЗАПУСТИТЬ АУДИТ", command=run_audit)
btn_check.pack(side=LEFT, padx=5)

btn_clear = ttk.Button(btn_frame, text="🗑 ОЧИСТИТЬ", command=clear_log)
btn_clear.pack(side=LEFT, padx=5)

btn_report = ttk.Button(btn_frame, text="📄 СОХРАНИТЬ ОТЧЁТ", command=save_reports)
btn_report.pack(side=LEFT, padx=5)

btn_exit = ttk.Button(btn_frame, text="❌ ВЫХОД", command=root.quit)
btn_exit.pack(side=LEFT, padx=5)

create_stats_labels()
update_stats_display()

# ═══════════════════════════════════════════════════════════════
# 🚀 ЗАПУСК
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        log("⚠ Рекомендуется запуск с sudo для полной проверки", '#ffff00')
    root.mainloop()
