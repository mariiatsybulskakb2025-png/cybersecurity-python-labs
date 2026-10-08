import csv
import hashlib  #Бібліотека для криптографії та безпеки. Саме вона містить алгоритми (наприклад, твій blake2b), які перетворюють звичайний пароль на складний хеш-рядок.
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

# Додаємо шлях до кореня проєкту, щоб мати можливість імпортувати спільний модуль shared
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

# Імпортуємо номер варіанта студента
try:
    from shared.student import VARIANT_NUMBER
except ImportError:
    # Якщо модуль не знайдено, за замовчуванням використовуємо Варіант 11
    VARIANT_NUMBER = 11

# --- КОНФІГУРАЦІЙНІ КОНСТАНТИ ВАРІАНТА 11 ---
HASH_ALGORITHM = "blake2b"         # Використовуваний алгоритм хешування
MIN_PASSWORD_LENGTH = 12           # Мінімально дозволена довжина пароля
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)  # Індивідуальна сіль на основі номера варіанта (напр. "00011")

# --- ШЛЯХИ ДО ДАНИХ ТА ФАЙЛІВ ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, "data")             # Папка для збереження файлів
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")     # База даних користувачів у CSV
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")       # Файл журналу подій у JSON


class ValidationError(Exception):
    """Кастомний клас винятку для виявлення помилок валідації (наприклад, закороткий пароль)."""


def generate_hash(password: str, salt: str = PERSONAL_SALT) -> str:
    """
    Генерує хеш BLAKE2b для пароля з використанням персональної солі.
    
    :param password: Вхідний пароль у відкритому вигляді
    :param salt: Сіль для підсилення хешу
    :return: 16-нковий рядок хешу
    """
    # 1. Перевірка на порожній пароль або пароль з одних пробілів
    if not password or not password.strip():
        raise ValueError("[ІНВАЛІДНИЙ ВХІД] Пароль не може бути порожнім.")
    
    # 2. Перевірка мінімальної довжини пароля
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину ({MIN_PASSWORD_LENGTH} символів)."
        )

    # 3. Конкатенація пароля із сіллю та перетворення у байтовий рядок UTF-8
    salted_input = (password + salt).encode("utf-8")
    
    # 4. Обчислення та повернення хешу BLAKE2b
    return hashlib.blake2b(salted_input).hexdigest()


def log_event(func):
    """
    Декоратор для автоматичного запису спроб входу (аутентифікації) у файл JSON.
    """
    @wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        result_status = "failure"
        try:
            # Викликаємо основну функцію login
            res = func(username, password, *args, **kwargs)
            if res:
                result_status = "success"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:
            # Створюємо папку data, якщо вона ще не існує
            os.makedirs(DATA_DIR, exist_ok=True)

            # Формуємо структуру запису логу (БЕЗ збереження хешів та бази даних)
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            }

            logs = []
            # Якщо файл логів уже існує — зчитуємо попередні записи
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            # Додаємо новий запис та залишаємо лише останні 15 подій
            logs.append(log_entry)
            logs = logs[-15:]

            # Записуємо оновлений журнал у JSON-файл
            try:
                with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                    json.dump(logs, f, ensure_ascii=False, indent=4)
            except (OSError, PermissionError) as e:
                print(f"[ПОМИЛКА ЛОГУВАННЯ] Не вдалося записати лог: {e}")

    return wrapper


# Список тестових користувачів та їх паролів для реєстрації
USERS_TO_REGISTER: tuple[tuple[str, str], ...] = (
    ("risk_manager", "RiskPass2026!Sec"),
    ("business_analyst", "BizAnalysis#11Pass"),  
    ("legal_counsel", "LegalDept2026$Val"),
    ("contractor_dev", "DevContractor11^"),
    ("sys_admin", "SuperSecureAdmin11*"),
    ("audit_expert", "AuditorCheck2026!"),
    ("threat_hunter", "ThreatHunter11#"),
    ("compliance_officer", "CompliancePass2026"),
    ("sys_engineer", "SysEngineer11!Sec"),
    ("", "GuestAccountPass11"),
    ("", "GuestAccountPass11"),

)


def create_user(username: str, password: str) -> tuple[str, str]:
    """
    Валідує дані та повертає пару (ім'я користувача, хеш пароля або статус помилки).
    """
    # Перевіряємо чи логін не порожній
    if not username or not username.strip():
        username = "<EMPTY_USERNAME>"
        raise ValueError("[ІНВАЛІДНИЙ ВХІД] Порожній логін")

    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value

def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    """
    Реєструє користувачів і зберігає їх у файл users.csv.
    Якщо дані невалідні, зберігає інформацію про помилку та продовжує обробку.
    """
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "password_hash"])
        
        seen_users = set()

        for username, password in users_list:
            try:
                # Намагаємося захешувати пароль
                user, pwd_hash = create_user(username, password)
            except (ValueError, ValidationError):
                # Якщо спіймали помилку — визначаємо, що саме було не так
                user = username if (username and username.strip()) else "<EMPTY_USERNAME>"
                pwd_hash = "<INVALID_PASSWORD>"

            # Записуємо рядок у CSV (або коректні дані, або статус помилки)
            if user not in seen_users:
                writer.writerow([user, pwd_hash])
                seen_users.add(user)


def read_users_db() -> list[dict[str, str]]:
    """
    Зчитує збережену базу даних користувачів із CSV-файлу у список словників.
    """
    with open(USERS_CSV_PATH, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)


@log_event  # Огортаємо функцію декоратором для запису дій у log.json
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    """
    Виконує перевірку автентифікації користувача за логіном і паролем.
    """
    # Валідація вхідних даних
    if not username or not username.strip():
        raise ValueError("[ІНВАЛІДНИЙ ВХІД] Логін не передано або він складається з пробілів!")

    if not password or not password.strip():
        raise ValueError("[ІНВАЛІДНИЙ ВХІД] Пароль не передано або він складається з пробілів!")

    # Хешуємо введений пароль для порівняння з базою
    input_hash = generate_hash(password, PERSONAL_SALT)

    # Шукаємо користувача у зчитаній базі даних
    for record in users_db:
        if record["username"] == username:
            # Повертаємо True, якщо хеш із бази збігається з обчисленим
            return record["password_hash"] == input_hash

    return False


def run_task3() -> None:
    """Головний сценарій виконання Завдання 3."""
    print("=" * 70)
    print(f"ЗАВДАННЯ 3 | ВАРІАНТ {VARIANT_NUMBER}")
    print(
        f"Алгоритм: {HASH_ALGORITHM} | Мін. довжина: {MIN_PASSWORD_LENGTH} | Сіль:"
        f" {PERSONAL_SALT}"
    )
    print("=" * 70)

    try:
        # Етап 1: Створення CSV-файлу з хешами паролів
        print("\n[1] Створення бази даних користувачів (users.csv)...")
        create_users(USERS_TO_REGISTER)
        print("Базу даних успішно оновлено.")

        # Етап 2: Зчитування CSV-файлу та виведення його вмісту у вигляді таблиці
        print("\n[2] Зчитування бази даних:")
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

        # Етап 3: Тестування входу під різними обліковими записами
        print("\n[3] Перевірка автентифікації:")
        
        res1 = login("risk_manager", "RiskPass2026!Sec", users_db)
        print(f"Спроба входу [risk_manager / вірний пароль]: {'СХВАЛЕНО' if res1 else 'ВІДХИЛЕНО'}")

        # Перевірка з невірним паролем для демонстрації відхилення
        res2 = login("business_analyst", "BizAnalysis#11Pass!", users_db)
        print(f"Спроба входу [business_analyst / невірний пароль]: {'СХВАЛЕНО' if res2 else 'ВІДХИЛЕНО'}")

        res3 = login("legal_counsel", "LegalDept2026$Val", users_db)
        print(f"Спроба входу [legal_counsel / вірний пароль]: {'СХВАЛЕНО' if res3 else 'ВІДХИЛЕНО'}")

        res4 = login("contractor_dev", "DevContractor11^", users_db)
        print(f"Спроба входу [contractor_dev / вірний пароль]: {'СХВАЛЕНО' if res4 else 'ВІДХИЛЕНО'}")

        res5 = login("sec_admin", "SuperSecureAdmin11*", users_db)
        print(f"Спроба входу [sec_admin / вірний пароль]: {'СХВАЛЕНО' if res5 else 'ВІДХИЛЕНО'}")

        res6 = login("audit_expert", "AuditorCheck2026!", users_db)
        print(f"Спроба входу [audit_expert / вірний пароль]: {'СХВАЛЕНО' if res6 else 'ВІДХИЛЕНО'}")

        res7 = login("threat_hunter", "ThreatHunter11#", users_db)
        print(f"Спроба входу [threat_hunter / вірний пароль]: {'СХВАЛЕНО' if res7 else 'ВІДХИЛЕНО'}")

        res8 = login("compliance_officer", "CompliancePass2026", users_db)
        print(f"Спроба входу [compliance_officer / вірний пароль]: {'СХВАЛЕНО' if res8 else 'ВІДХИЛЕНО'}")

        res9 = login("sys_engineer", "SysEngineer11!Sec", users_db)
        print(f"Спроба входу [sys_engineer / вірний пароль]: {'СХВАЛЕНО' if res9 else 'ВІДХИЛЕНО'}")

        res10 = login("guest_user", "GuestAccountPass11", users_db)
        print(f"Спроба входу [guest_user / вірний пароль]: {'СХВАЛЕНО' if res10 else 'ВІДХИЛЕНО'}")

        # Етап 4: Інформаційне повідомлення про збереження логів
        print(f"\n[4] Журнал подій збережено у файлі: {LOG_JSON_PATH}")

    # Блок обробки можливих винятків і помилок файлової системи
    except FileNotFoundError as e:
        print(f"[КРИТИЧНА ПОМИЛКА] Файл не знайдено: {e}")
    except PermissionError as e:
        print(f"[КРИТИЧНА ПОМИЛКА] Відсутні права доступу до файлу: {e}")
    except OSError as e:
        print(f"[КРИТИЧНА ПОМИЛКА] Помилка вводу/виводу файлу: {e}")
    except (ValidationError, ValueError) as e:
        print(f"\n[ВИЯВЛЕНО ПОРУШЕННЯ]: {e}")


# Запуск програми
if __name__ == "__main__":
    run_task3()