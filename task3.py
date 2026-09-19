import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from functools import wraps

# Спроба імпортувати персональний номер варіанта зі спільного модуля проекту
try:
    from shared.student import VARIANT_NUMBER
except ImportError:
    # Значення за замовчуванням, якщо модуль відсутній
    VARIANT_NUMBER = 11

# Конфігураційні константи для Варіанта 11
HASH_ALGORITHM = "blake2b"
MIN_PASSWORD_LENGTH = 12

# Форматування солі: перетворюємо число у рядок із доповненням нулями ліворуч до 5 символів ("00011")
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

# Формування абсолютних/відносних шляхів для збереження даних
DATA_DIR = os.path.join("labs", "lab01", "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    """Кастомний клас винятку для обробки помилок невідповідності вимога до пароля."""


def generate_hash(password: str, salt: str = PERSONAL_SALT) -> str:
    """Генерує хеш пароля із додаванням солі за допомогою криптографічного алгоритму blake2b.

    :param password: Вхідний пароль у вигляді рядка.
    :param salt: Рядок солі для захисту від атак за допомогою готових таблиць (rainbow tables).
    :return: Хеш-значення у шістнадцятковому форматі (hex string).
    """
    # Перевірка на наявність порожніх значень
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    # Перевірка виконання вимоги щодо мінімальної довжини пароля
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину ({MIN_PASSWORD_LENGTH} символів)."
        )

    # Конкатенація (поєднання) пароля із сіллю та перетворення у байтовий рядок (UTF-8)
    salted_input = (password + salt).encode("utf-8")

    # Генерація хешу за допомогою алгоритму BLAKE2b та повернення хеш-рядка
    return hashlib.blake2b(salted_input).hexdigest()


def log_event(func):
    """Декоратор для автоматичного фіксування та логування спроб входу у JSON-файл."""

    @wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        # Початковий статус спроби автентифікації
        result_status = "failure"
        try:
            # Виконуємо декоровану функцію (login)
            res = func(username, password, *args, **kwargs)
            if res:
                result_status = "success"
            return res
        except Exception:
            # Якщо виникла помилка під час виконання функції — фіксуємо невдачу і передаємо помилку далі
            result_status = "failure"
            raise
        finally:
            # Гарантовано виконується після завершення (або помилки) функції
            # Створюємо папку для даних, якщо вона ще не існує
            os.makedirs(DATA_DIR, exist_ok=True)

            # Формуємо словник із даними про події входу
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                # Отримуємо поточний час у часовому поясі UTC у форматі ISO/ISO-подібному
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            # Якщо файл логів вже існує — зчитуємо його поточний вміст
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    # Якщо файл пошкоджений або порожній, створюємо новий список
                    logs = []

            # Додаємо новий запис логу до загального списку
            logs.append(log_entry)

            # Записуємо оновлений масив логів назад у JSON-файл із форматуванням
            try:
                with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(logs, f, ensure_ascii=False, indent=4)
            except (OSError, PermissionError) as e:
                print(f"[ПОМИЛКА ЛОГУВАННЯ] Не вдалося записати лог: {e}")

    return wrapper


# Вхідний кортеж тестових користувачів для первинної реєстрації в системі
USERS_TO_REGISTER: tuple[tuple[str, str], ...] = (
    ("risk_manager", "RiskPass2026!Sec"),
    ("business_analyst", "BizAnalysis#11Pass"),
    ("legal_counsel", "LegalDept2026$Val"),
    ("contractor_dev", "DevContractor11^"),
    ("sec_admin", "SuperSecureAdmin11*"),
    ("audit_expert", "AuditorCheck2026!"),
    ("threat_hunter", "ThreatHunter11#"),
    ("compliance_off", "CompliancePass2026"),
    ("sys_engineer", "SysEngineer11!Sec"),
    ("guest_user", "GuestAccountPass11"),
)


def create_user(username: str, password: str) -> tuple[str, str]:
    """Формує обліковий запис користувача, хешуючи його пароль."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """Обробляє кортеж користувачів та зберігає їх логіни й хеші у CSV-файл."""
    # Перевіряємо та створюємо директорію для зберігання
    os.makedirs(DATA_DIR, exist_ok=True)

    # Відкриваємо CSV-файл для запису (з режимом newline="" для коректних переносів рядків)
    with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        # Записуємо заголовок таблиці
        writer.writerow(["username", "password_hash"])

        # Проходимо по кожній парі (логін, пароль) та записуємо хешовані дані
        for username, password in users_list:
            user, pwd_hash = create_user(username, password)
            writer.writerow([user, pwd_hash])


def read_users_db() -> list[dict[str, str]]:
    """Зчитує дані користувачів із CSV-файлу у вигляді списку словників."""
    with open(USERS_CSV_PATH, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        # Преобразуємо об'єкт зчитування безпосередньо у список словників
        users_db = list(reader)

    return users_db


@log_event  # Декоруємо функцію для автоматичного логування результатів входу
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    """Здійснює аутентифікацію користувача: перевіряє співпадіння хешу введеного пароля з базою."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    # Генеруємо хеш введеного користувачем пароля
    input_hash = generate_hash(password, PERSONAL_SALT)

    # Шукаємо користувача у базі даних
    for record in users_db:
        if record["username"] == username:
            # Повертаємо True, якщо хеші збігаються, або False, якщо ні
            return record["password_hash"] == input_hash

    # Якщо користувача з таким логіном не знайдено
    return False


def run_task3() -> None:
    """Головна функція сценарію для демонстрації роботи всіх компонентів Завдання 3."""
    print("=" * 70)
    print(f"ЗАВДАННЯ 3 | ВАРІАНТ {VARIANT_NUMBER}")
    print(
        f"Алгоритм: {HASH_ALGORITHM} | Мін. довжина: {MIN_PASSWORD_LENGTH} | Сіль:"
        f" {PERSONAL_SALT}"
    )
    print("=" * 70)

    try:
        # 1. Генерація та збереження тестової бази користувачів
        print("\n[1] Створення бази даних користувачів (users.csv)...")
        create_users(USERS_TO_REGISTER)
        print("Базу даних успішно створено та записано.")

        # 2. Зчитування даних із CSV та демонстрація у табличному вигляді
        print("\n[2] Зчитування та відображення бази даних:")
        users_db = read_users_db()

        print("-" * 75)
        print(f"| {'Логін (Username)':<20} | {'Хеш пароля (blake2b)':<48} |")
        print("-" * 75)
        for user_rec in users_db:
            print(
                f"| {user_rec['username']:<20} |"
                f" {user_rec['password_hash'][:45]}... |"
            )
        print("-" * 75)

        # 3. Тестування системи автентифікації та роботи декоратора логування
        print("\n[3] Перевірка автентифікації (login):")

        # Тест 1: Валідні облікові дані
        res1 = login("risk_manager", "RiskPass2026!Sec", users_db)
        print(
            "Спроба входу [risk_manager / вірний пароль]:"
            f" {'СХВАЛЕНО' if res1 else 'ВІДХИЛЕНО'}"
        )

        # Тест 2: Невірний пароль для існуючого користувача
        res2 = login("risk_manager", "WrongPassword123!", users_db)
        print(
            "Спроба входу [risk_manager / невірний пароль]:"
            f" {'СХВАЛЕНО' if res2 else 'ВІДХИЛЕНО'}"
        )

        # Тест 3: Неіснуючий користувач
        res3 = login("unknown_user", "SomePassword123!", users_db)
        print(
            f"Спроба входу [unknown_user]: {'СХВАЛЕНО' if res3 else 'ВІДХИЛЕНО'}"
        )

        # 4. Демонстрація перевірки обмежень довжини пароля
        print(
            "\n[4] Перевірка генерації винятку ValidationError (короткий"
            " пароль):"
        )
        try:
            generate_hash("short", PERSONAL_SALT)
        except ValidationError as val_err:
            print(f"Спіймано виняток ValidationError: {val_err}")

        # 5. Демонстрація перевірки на порожні значення
        print("\n[5] Перевірка генерації винятку ValueError (порожній пароль):")
        try:
            login("", "", users_db)
        except ValueError as val_err:
            print(f"Спіймано виняток ValueError: {val_err}")

        print(f"\n[6] Журнал подій збережено у файлі: {LOG_JSON_PATH}")

    # Блок обробки можливих системних помилок роботи з файлами та валідації
    except FileNotFoundError as e:
        print(f"[КРИТИЧНА ПОМИЛКА] Файл не знайдено: {e}")
    except PermissionError as e:
        print(f"[КРИТИЧНА ПОМИЛКА] Відсутні права доступу до файлу: {e}")
    except OSError as e:
        print(f"[КРИТИЧНА ПОМИЛКА] Помилка вводу/виводу файлу: {e}")
    except (ValidationError, ValueError) as e:
        print(f"[ПОМИЛКА ВАЛІДАЦІЇ/ЗНАЧЕННЯ]: {e}")


# Точка входу: код виконується тільки при безпосередньому запуску цього файла
if __name__ == "__main__":
    run_task3()