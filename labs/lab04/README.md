# Лабораторна робота №4. Інтеграція з NVD API та автоматизоване тестування

Консольна утиліта перегляду запису про вразливість у Національній базі даних
вразливостей (NVD). Шукає запис за ідентифікатором CVE, застосовує правило
свого варіанта до оцінки CVSS v3.1 і виводить JSON-звіт.

## Варіант

Номер варіанта береться з `shared/student.py` (`VARIANT_NUMBER`). Варіант 11:

| Параметр | Значення |
|---|---|
| Напрям відбору | потрібна взаємодія користувача |
| Поріг `T` | 6.0 |
| Поле `field` | `userInteraction` |
| Значення `expected` | `REQUIRED` |

Правило: `score >= 6.0` **і** `cvssData["userInteraction"] == "REQUIRED"` у тій
самій вибраній оцінці CVSS v3.1 (`metrics.cvssMetricV31`; елемент
`type="Primary"`, а за його відсутності — перший елемент списку).

## Встановлення

З кореня репозиторію, в активованому віртуальному середовищі (Python 3.12+):

```
pip install requests pytest ruff
```

Версії пакетів зафіксовано в спільному `requirements.txt`.

## Запуск

Локальний режим (без мережі, синтетична відповідь):

```
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Режим з одним запитом до NVD:

```
python -m labs.lab04.main --cve CVE-2021-44228
```

Ключ NVD API необов'язковий. Якщо потрібно, задайте його змінною середовища
`NVD_API_KEY` (він передається в заголовку `apiKey` і ніколи не виводиться).

Коди завершення: `0` — звіт сформовано (зокрема стани `not_found`,
`rejected`, `insufficient_data`); `1` — помилка отримання, читання чи перевірки
даних; `2` — неправильні аргументи або номер варіанта.

## Формат звіту

JSON-об'єкт із ключами `cve_id`, `variant`, `description`, `vuln_status`,
`cvss_version`, `score`, `score_source`, `vector`, `rule`
(`threshold`, `field`, `expected`), `observed`, `decision`.
Відсутні значення подаються як `null`. Стани `decision`: `not_found`,
`rejected`, `insufficient_data`, `review`, `other`.

Для синтетичного файлу очікується `decision = "other"`: оцінка 9.8 вища за
поріг, але `userInteraction` дорівнює `NONE`, а не `REQUIRED`.

## Перевірка

```
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `tests/conftest.py` видаляє `NVD_API_KEY` і
забороняє справжні запити Requests перед кожним тестом.

## Структура

```
labs/lab04/
├── main.py          # аргументи CLI, виклик функцій, повідомлення
├── api_client.py    # заголовки та один GET-запит
├── analysis.py      # перевірка даних і правило варіанта
├── data/nvd_sample.json
├── tests/           # тести аналізу, клієнта та CLI
└── README.md
```

> `CVE-2099-10001` — штучний запис лише для локальної перевірки, у NVD його
> шукати не потрібно.