
import os
import random
import sys

# Додаємо кореневу папку проєкту до шляхів пошуку системи,
# щоб Python міг імпортувати спільний модуль shared.student із суміжної папки.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Імпортуємо персональні дані з модуля student.py
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідний список паролів для Варіанта 11
PASSWORDS = [
    "APT@Detect10n",
    "simple",
    "Red@Team2023",
    "participant",
    "Blue@T3am",
    "common123",
    "Purple@T34m",
    "regular123",
    "Gr33n@Team",
    "normal123",
]

# Критерії надійності для Варіанта 11 (мінімальна довжина та необхідні типи символів)
CRITERIA = {
    "min_length": 7,            # Пароль має бути не коротшим за 7 символів
    "require_digits": True,     # Має містити хоча б одну цифру
    "require_upper": True,      # Має містити хоча б одну велику літеру
    "require_special": True,    # Має містити хоча б один спецсимвол
}

# Множина слабких паролів, використання яких заборонено (для швидкого пошуку)
FORBIDDEN_PASSWORDS = {
    "simple",
    "participant",
    "common123",
    "regular123",
    "normal123",
    "test",
}


def check_criteria(password: str) -> dict[str, bool]:
    """Перевіряє наявність окремих груп символів у паролі."""
    # Повертає словник, де ключі - типи символів, а значення - True, якщо символ знайдено
    return {
        "digits": any(c.isdigit() for c in password),      # Перевірка на наявність цифр
        "upper": any(c.isupper() for c in password),       # Перевірка на великі літери
        "lower": any(c.islower() for c in password),       # Перевірка на малі літери
        "special": any(not c.isalnum() for c in password), # Перевірка на спецсимволи (не букви і не цифри)
    }


def evaluate_password(password: str, password_list: list[str]) -> str:
    """Оцінює надійність пароля за алгоритмом із Завдання 1."""
    min_len = CRITERIA["min_length"]
    checks = check_criteria(password)

    # 1. Заборонений: Якщо пароль є у списку заборонених АБО його довжина менша за мінімальну
    if password in FORBIDDEN_PASSWORDS or len(password) < min_len:
        return "Заборонений"

    # Перевіряємо, чи виконуються всі обов'язкові критерії безпеки (цифри, великі літери, спецсимволи)
    all_required = checks["digits"] and checks["upper"] and checks["special"]

    # 2. Перевірка на категорії "Сильний" та "Дуже сильний"
    if all_required:
        # Пароль є унікальним, якщо він зустрічається у списку лише 1 раз
        is_unique = password_list.count(password) == 1
        
        # Дуже сильний: Всі критерії виконані + довжина >= (min_length + 4) + він унікальний
        if len(password) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        
        # Сильний: Відповідає всім критеріям безпеки, але не дотягує до умов "Дуже сильного"
        return "Сильний"

    # 3. Перевірка на категорії "Середній" та "Слабкий"
    # Перевіряємо, чи виконується хоча б один критерій безпеки
    any_met = (
        checks["digits"] or checks["upper"] or checks["special"] or checks["lower"]
    )

    # Середній: Відповідає мінімальній довжині та містить деякі (але не всі) групи символів
    if len(password) >= min_len and any_met:
        return "Середній"

    # Слабкий: Не є забороненим, але виконує мінімум критеріїв і не відповідає середньому рівню
    return "Слабкий"


def run_task1() -> None:
    """Виконує Завдання 1."""
    print("=" * 50)
    # Виводимо персональні дані студента, імпортовані з модуля
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 50)

    # Дублювання 3 випадкових паролів згідно з умовою (імітація повторного використання)
    working_passwords = PASSWORDS.copy()
    
    # Використовуємо модуль random, щоб отримати 3 унікальні індекси зі списку паролів
    random_indices = random.sample(range(len(PASSWORDS)), 3)
    
    # За отриманими індексами беремо паролі та додаємо їх у кінець списку (робимо дублікати)
    for idx in random_indices:
        working_passwords.append(PASSWORDS[idx])

    # Табличний вивід результатів на екран з форматуванням стовпців
    print(f"\n{'Пароль':<20} | {'Оцінка надійності':<15}")
    print("-" * 38)
    
    # Проходимо по кожному паролю з оновленого списку і виводимо його оцінку
    for pwd in working_passwords:
        strength = evaluate_password(pwd, working_passwords)
        print(f"{pwd:<20} | {strength:<15}")


if __name__ == "__main__":
    run_task1()