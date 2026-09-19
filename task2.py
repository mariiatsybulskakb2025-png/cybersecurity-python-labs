
import os
import sys

# Додаємо кореневу папку проєкту до шляхів пошуку системи,
# щоб Python міг імпортувати спільний модуль shared.student із суміжної папки.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Імпортуємо персональні дані студента зі спільного модуля
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Словник ролей та відповідних списків дозволених дій (модель рольового доступу RBAC)
ROLE_PERMISSIONS = {
    "risk_manager": ["read_reports", "write_risk_assessments", "approve_policies"],
    "legal_counsel": ["read_reports", "review_contracts", "approve_policies"],
    "compliance_officer": ["read_reports", "audit_logs"],
    "guest": ["read_public_policies"],
}


def check_access(role: str, action: str) -> bool:
    """Перевіряє, чи має роль дозвіл на виконання дії.
    
    :param role: Назва ролі користувача.
    :param action: Запитувана дія.
    :return: True, якщо дія дозволена; False — якщо ні.
    """
    # Якщо ролі немає у словнику дозволів — доступ одразу відхиляється
    if role not in ROLE_PERMISSIONS:
        return False
    
    # Перевіряємо, чи є запитувана дія у списку привілеїв даної ролі
    return action in ROLE_PERMISSIONS[role]


def run_task2() -> None:
    """Виконує Завдання 2 та демонструє роботу перевірки доступу."""
    print("=" * 50)
    # Виводимо персональні дані студента
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 50)
    print("\nСистема контролю доступу (Рівень безперервності 4)\n")

    # Тестові сценарії перевірки у форматі кортежів (роль, запитувана_дія)
    test_scenarios = [
        ("risk_manager", "approve_policies"),            # Повинно бути дозволено
        ("legal_counsel", "review_contracts"),            # Повинно бути дозволено
        ("compliance_officer", "write_risk_assessments"),  # Повинно бути відхилено (немає прав)
        ("guest", "read_reports"),                         # Повинно бути відхилено (немає прав)
        ("unknown_hacker", "read_reports"),                # Повинно бути відхилено (неіснуюча роль)
    ]

    # Форматоване виведення заголовка таблиці
    print(f"{'Роль':<20} | {'Дія':<25} | {'Результат'}")
    print("-" * 60)

    # Проходимо по кожному сценарію та виводимо текстовий статус
    for role, action in test_scenarios:
        has_access = check_access(role, action)
        status = "ДОЗВОЛЕНО" if has_access else "ВІДМОВЛЕНО"
        print(f"{role:<20} | {action:<25} | {status}")

