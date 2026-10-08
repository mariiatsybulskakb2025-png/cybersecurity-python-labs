import os
import sys

# Додаємо шлях до кореня проєкту для імпорту shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Прямий імпорт без try...except
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# --- ДАНІ З МЕТОДИЧКИ (ЗАВДАННЯ 2, ВАРІАНТ 11) ---
users = {
    "risk_manager": {
        "role": "risk_analyst",
        "clearance": 4,
        "department": "Risk Management",
        "active": True,
    },
    "business_analyst": {
        "role": "business_analyst",
        "clearance": 2,
        "department": "Business",
        "active": True,
    },
    "legal_counsel": {
        "role": "legal",
        "clearance": 3,
        "department": "Legal",
        "active": True,
    },
    "contractor_dev": {
        "role": "contractor",
        "clearance": 2,
        "department": "Contract",
        "active": True,
    },
    "obsolete_system": {
        "role": "legacy_system",
        "clearance": 1,
        "department": "Legacy",
        "active": False,
    },
}

resources = [
    ("risk_registers", 4),
    ("business_requirements", 2),
    ("legal_documents", 3),
    ("contract_code", 2),
    ("governance_framework", 4),
    ("meeting_minutes", 1),
    ("regulatory_reports", 3),
    ("executive_dashboards", 4),
    ("project_specs", 2),
    ("public_statements", 1),
]

security_levels = ("Public", "Internal Use", "Restricted", "Highly Restricted")
blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}


def check_access(username: str, required_clearance: int) -> tuple[bool, str]:
    """
    Перевіряє доступ та повертає кортеж (дозволено_чи_ні, причина).
    """
    # 1. Якщо користувача немає у базі
    if username not in users:
        return False, "User not found"

    # 2. Якщо користувач у списку заблокованих
    if username in blocked_users:
        return False, "User is blocked"

    user_info = users[username]

    # 3. Якщо акаунт неактивний
    if not user_info.get("active", False):
        return False, "User is inactive"

    # 4. Якщо рівень допуску замалий
    if user_info.get("clearance", 0) < required_clearance:
        return False, "Insufficient clearance"

    return True, "ALLOW"


def run_task2() -> None:
    # Заголовок із використанням імпортованих даних
    print(
        f"=== Завдання 2 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    # Виведення списку ресурсів системи
    print("\n--- Список ресурсів системи ---")
    for res_name, req_clearance in resources:
        level_name = security_levels[req_clearance - 1]
        print(f"Ресурс: {res_name:<25} | Рівень: {level_name}")

    # Виведення результатів перевірки доступу
    print("\n--- Результати перевірки доступу ---")
    test_users = list(users.keys()) + ["guest_user"]

    for username in test_users:  # Це зовнішній цикл. Він бере першого користувача зі списку (наприклад, "risk_manager") і передає його далі.
        for res_name, req_clearance in resources:
            is_allowed, reason = check_access(username, req_clearance)

            if is_allowed:
                print(f"user=[{username}] resource=[{res_name}] -> ALLOW")
            else:
                print(f"user=[{username}] resource=[{res_name}] -> DENY ({reason})")


if __name__ == "__main__":
    run_task2()
