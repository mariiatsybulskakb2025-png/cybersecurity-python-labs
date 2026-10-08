# ============================
# ФАЙЛ: labs/lab02/README.md
# Лабораторна робота №2
## Варіант 11: Аудитор ARP-таблиць та виявлення ARP-Spoofing

### Опис
Утиліта аналізує ARP-таблиці, перевіряє коректність IP/MAC-адрес, виявляє дублікати MAC для різних IP (ознака ARP-Spoofing) та формує JSON-звіт.
Програма також веде логування подій безпеки.

### Структура файлів
- labs/lab02/task1.py — моделі користувачів та сесій
- labs/lab02/task2.py — утиліта ARP-auditor
- labs/lab02/main.py — демонстраційний сценарій
- labs/lab02/data/ — тестові дані (`arp_table.csv`, `arp_security_alerts.json`, `log.json`)
- labs/lab02/README.md — інструкція

### Встановлення
1. Створити та активувати віртуальне середовище:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux / macOS
   .venv\Scripts\activate      # Windows PowerShell
# Демонстрація роботи класів (завдання 1)
python -m labs.lab02.main demo

# Аналіз ARP-таблиці (завдання 2) — стандартний режим
python labs/lab02/task2.py --arp-file labs/lab02/data/arp_table.csv --output-json labs/lab02/data/arp_security_alerts.json --detect-spoofing --log-file labs/lab02/data/log.json

# Запуск без перевірки spoofing
python labs/lab02/task2.py --arp-file labs/lab02/data/arp_table.csv --output-json labs/lab02/data/arp_security_alerts.json

# Запуск із неіснуючим файлом (приклад помилки)
python labs/lab02/task2.py --arp-file labs/lab02/data/missing.csv --output-json labs/lab02/data/arp_security_alerts.json
git add labs/lab02
git commit -m "Add lab02: ARP auditor (variant 11) with README and sample data"
git push
