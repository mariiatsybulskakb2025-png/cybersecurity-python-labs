# Лабораторна робота №4. NVD API

Програма перегляду запису про вразливість у NVD (CVSS v3.1), варіант 11.
Правило: оцінка >= 6.0 і userInteraction = REQUIRED.

## Встановлення
```
pip install requests pytest ruff
```

## Запуск
Локально, без мережі:
```
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```
З одним запитом до NVD:
```
python -m labs.lab04.main --cve CVE-2021-44228
```
Результат: JSON-звіт (поля cve_id, variant, description, vuln_status,
cvss_version, score, score_source, vector, rule, observed, decision).
Коди завершення: 0 — успіх, 1 — помилка даних чи мережі, 2 — неправильні аргументи.

## Перевірка
```
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```