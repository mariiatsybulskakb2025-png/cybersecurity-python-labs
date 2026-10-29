# Лабораторна робота №3 — FastAPI та SQLite (варіант 11)

**Предметна область:** облік вимірювань завантаження каналів зв’язку.
Категорії: `internet`, `vpn`, `backup_link`. `value` — частка використання
пропускної здатності каналу, % (від 0 до 100), одиниця `percent`, поріг `70.0`.
`status`: `new`, `in_progress`, `done`. Таблиці `categories` і `records` пов’язані
«один до багатьох»; категорію з записами видалити не можна (`ON DELETE RESTRICT`).

## Встановлення (з кореня репозиторію)
```bash
pip install fastapi uvicorn pydantic ruff
pip install -r requirements.txt
```

## База та початкове заповнення
```bash
python -m labs.lab03.database
python -m labs.lab03.seed
```
Повторний запуск `seed` для непорожньої бази нічого не змінює.

## Запуск API
```bash
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```
Swagger UI: http://127.0.0.1:8000/docs

## Приклади запитів
```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i -X POST "http://127.0.0.1:8000/records" -H "Content-Type: application/json" \
  -d '{"code":"V11-TEST","title":"Вимірювання каналу тест","category_id":1,"value":75.5,"status":"new"}'
```

## Перевірка стилю
```bash
ruff check .
ruff format --check .
```